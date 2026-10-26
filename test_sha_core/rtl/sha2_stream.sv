// ============================================================================
// Module      : sha2_stream
// Description : Byte-stream frontend for the Unified SHA-256 / SHA-512 core.
//
// Responsibilities:
//   * Accept one message byte per handshake when data_ready_o is high.
//   * Track total message length in bytes.
//   * Generate SHA-2 padding automatically when finish_i is accepted.
//   * Compress full data blocks as they become available.
//   * Feed the final one or two padded block(s) to sha2_core.
//   * Pulse digest_valid_o when the final digest is ready.
//
// Stream protocol:
//   1. Pulse start_i while start_ready_o is high; mode_i is latched.
//   2. Send bytes with data_valid_i && data_ready_o.
//   3. After the final byte has been accepted, assert finish_i. Hold it until
//      finish_ready_o is high. finish_i is accepted only when data_valid_i=0.
//      This also supports an empty message (start, then finish, no data bytes).
//   4. Wait for digest_valid_o. digest_o[255:0] contains SHA-256 and
//      digest_o[511:0] contains SHA-512.
//
// Block mapping matches sha2_core:
//   SHA-256 block bytes occupy buffer_q[1023:512].
//   SHA-512 block bytes occupy buffer_q[1023:0].
//   Byte zero is placed at the most-significant byte of the selected block.
//
// This is a simple single-buffer frontend. It backpressures the input stream
// while sha2_core compresses a block. It is intended as a clear first version;
// a FIFO/double-buffer can be added later for higher throughput.
// ============================================================================

`default_nettype none

module sha2_stream (
    input  wire                       clk_i,
    input  wire                       rst_ni,

    // Start a new hash message.
    input  wire                       start_i,
    output wire                       start_ready_o,
    input  wire sha2_pkg::sha2_mode_t mode_i,

    // Byte stream input.
    input  wire [7:0]                 data_i,
    input  wire                       data_valid_i,
    output wire                       data_ready_o,

    // End-of-message handshake. Assert only after all message bytes have been
    // presented. finish_ready_o is high when the frontend can accept finish_i.
    input  wire                       finish_i,
    output wire                       finish_ready_o,

    // Result/status.
    output wire                       busy_o,
    output logic [511:0]              digest_o,
    output logic                      digest_valid_o
);

    import sha2_pkg::*;

    typedef enum logic [2:0] {
        ST_IDLE,
        ST_LOAD,
        ST_PAD_BUILD,
        ST_SEND_BLOCK,
        ST_WAIT_BLOCK
    } stream_state_t;

    typedef enum logic [1:0] {
        RESUME_LOAD,
        RESUME_DONE,
        RESUME_LENGTH_BLOCK
    } resume_state_t;

    stream_state_t  state_q;
    resume_state_t  resume_q;

    sha2_mode_t     mode_q;
    logic           first_block_q;

    // 1024-bit physical buffer; SHA-256 uses only the upper 512 bits.
    logic [1023:0]  buffer_q;

    // Number of bytes currently stored in buffer_q. It can reach 128 for a
    // full SHA-512 block, so 8 bits are sufficient.
    logic [7:0]     block_byte_count_q;

    // Total message bytes, modulo 2^128. SHA-256 uses the low 64 bits of the
    // bit length; SHA-512 uses all 128 bits.
    logic [127:0]   total_bytes_q;
    wire  [127:0]   total_bits_w = total_bytes_q << 3;

    wire core_ready_w;
    wire core_busy_w;
    wire [511:0] core_digest_w;
    wire core_digest_valid_w;
    wire core_init_w;
    wire core_next_w;

    // The variable byte offset is widened before multiplying by eight so the
    // calculation cannot overflow an 8-bit expression for SHA-512 byte 127.
    wire [15:0] block_byte_offset_w = {8'b0, block_byte_count_q} << 3;
    wire [15:0] block_byte_msb_w    = 16'd1023 - block_byte_offset_w;

    wire full_block_last_byte_w =
        ((mode_q == SHA2_256) && (block_byte_count_q == 8'd63)) ||
        ((mode_q == SHA2_512) && (block_byte_count_q == 8'd127));

    assign start_ready_o  = (state_q == ST_IDLE);
    assign data_ready_o   = (state_q == ST_LOAD);
    assign finish_ready_o = (state_q == ST_LOAD) && !data_valid_i;
    assign busy_o         = (state_q != ST_IDLE);

    // Commands are asserted only when the compression core is ready. The
    // buffer remains unchanged until the compression has completed.
    assign core_init_w = (state_q == ST_SEND_BLOCK) && core_ready_w && first_block_q;
    assign core_next_w = (state_q == ST_SEND_BLOCK) && core_ready_w && !first_block_q;

    sha2_core u_sha2_core (
        .clk_i          (clk_i),
        .rst_ni         (rst_ni),
        .mode_i         (mode_q),
        .init_i         (core_init_w),
        .next_i         (core_next_w),
        .block_i        (buffer_q),
        .ready_o        (core_ready_w),
        .busy_o         (core_busy_w),
        .digest_o       (core_digest_w),
        .digest_valid_o (core_digest_valid_w)
    );

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q             <= ST_IDLE;
            resume_q            <= RESUME_LOAD;
            mode_q              <= SHA2_256;
            first_block_q       <= 1'b1;
            buffer_q            <= '0;
            block_byte_count_q  <= 8'd0;
            total_bytes_q       <= 128'd0;
            digest_o            <= 512'd0;
            digest_valid_o      <= 1'b0;
        end
        else begin
            // digest_valid_o is a one-cycle pulse for the complete message.
            digest_valid_o <= 1'b0;

            case (state_q)
                // ----------------------------------------------------------
                // Wait for the start of a new message.
                // ----------------------------------------------------------
                ST_IDLE: begin
                    if (start_i && start_ready_o) begin
                        mode_q             <= mode_i;
                        first_block_q      <= 1'b1;
                        buffer_q           <= '0;
                        block_byte_count_q <= 8'd0;
                        total_bytes_q      <= 128'd0;
                        digest_valid_o     <= 1'b0;
                        state_q             <= ST_LOAD;
                    end
                end

                // ----------------------------------------------------------
                // Collect bytes. Every full data block is compressed before
                // accepting more input. finish_i is accepted only when there
                // is no simultaneous valid byte, so empty messages work too.
                // ----------------------------------------------------------
                ST_LOAD: begin
                    if (finish_i && finish_ready_o) begin
                        state_q <= ST_PAD_BUILD;
                    end
                    else if (data_valid_i && data_ready_o) begin
                        buffer_q[block_byte_msb_w -: 8] <= data_i;
                        total_bytes_q <= total_bytes_q + 128'd1;

                        if (full_block_last_byte_w) begin
                            block_byte_count_q <= (mode_q == SHA2_256) ? 8'd64 : 8'd128;
                            resume_q           <= RESUME_LOAD;
                            state_q            <= ST_SEND_BLOCK;
                        end
                        else begin
                            block_byte_count_q <= block_byte_count_q + 8'd1;
                        end
                    end
                end

                // ----------------------------------------------------------
                // Add the mandatory 0x80 byte. Unused buffer bytes are already
                // zero because the buffer is cleared after each compression.
                // If the length field no longer fits, send this block without
                // a length and create a second, length-only block afterwards.
                // ----------------------------------------------------------
                ST_PAD_BUILD: begin
                    buffer_q[block_byte_msb_w -: 8] <= 8'h80;

                    if (mode_q == SHA2_256) begin
                        if (block_byte_count_q < 8'd56) begin
                            buffer_q[575:512] <= total_bits_w[63:0];
                            resume_q <= RESUME_DONE;
                        end
                        else begin
                            resume_q <= RESUME_LENGTH_BLOCK;
                        end
                    end
                    else begin
                        if (block_byte_count_q < 8'd112) begin
                            buffer_q[127:0] <= total_bits_w[127:0];
                            resume_q <= RESUME_DONE;
                        end
                        else begin
                            resume_q <= RESUME_LENGTH_BLOCK;
                        end
                    end

                    state_q <= ST_SEND_BLOCK;
                end

                // ----------------------------------------------------------
                // Send the current block to the compression core.
                // init_i is used for the first block, next_i for all later
                // blocks of the same message.
                // ----------------------------------------------------------
                ST_SEND_BLOCK: begin
                    if (core_ready_w) begin
                        first_block_q <= 1'b0;
                        state_q       <= ST_WAIT_BLOCK;
                    end
                end

                // ----------------------------------------------------------
                // Wait for the core to finish. Depending on resume_q:
                //   LOAD          -> clear buffer and accept more bytes
                //   DONE          -> publish final digest
                //   LENGTH_BLOCK  -> create and send the second padding block
                // ----------------------------------------------------------
                ST_WAIT_BLOCK: begin
                    if (core_digest_valid_w) begin
                        case (resume_q)
                            RESUME_LOAD: begin
                                buffer_q           <= '0;
                                block_byte_count_q <= 8'd0;
                                state_q            <= ST_LOAD;
                            end

                            RESUME_DONE: begin
                                digest_o       <= core_digest_w;
                                digest_valid_o <= 1'b1;
                                buffer_q        <= '0;
                                block_byte_count_q <= 8'd0;
                                state_q         <= ST_IDLE;
                            end

                            RESUME_LENGTH_BLOCK: begin
                                // Length-only block. SHA-256 occupies the top
                                // 512-bit half of the unified block bus; SHA-512
                                // occupies the entire 1024-bit bus.
                                if (mode_q == SHA2_256)
                                    buffer_q <= {448'b0, total_bits_w[63:0], 512'b0};
                                else
                                    buffer_q <= {896'b0, total_bits_w[127:0]};

                                block_byte_count_q <= 8'd0;
                                resume_q           <= RESUME_DONE;
                                state_q            <= ST_SEND_BLOCK;
                            end

                            default: begin
                                buffer_q           <= '0;
                                block_byte_count_q <= 8'd0;
                                state_q            <= ST_IDLE;
                            end
                        endcase
                    end
                end

                default: begin
                    state_q        <= ST_IDLE;
                    buffer_q       <= '0;
                    digest_valid_o <= 1'b0;
                end
            endcase
        end
    end

endmodule

`default_nettype wire
