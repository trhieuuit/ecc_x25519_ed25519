// ============================================================================
// Module      : hmac_sha256
// Description : Streaming HMAC-SHA-256 engine built on top of sha2_stream.
//
// HMAC definition:
//   HMAC(K, M) = SHA256((K0 xor opad) ||
//                       SHA256((K0 xor ipad) || M))
//
// Key normalization:
//   if key_len <= 64 bytes: K0 = key || zero padding to 64 bytes
//   if key_len >  64 bytes: K0 = SHA256(key) || 32 zero bytes
//
// Interface sequence:
//   1. Assert start_i until start_ready_o = 1.
//   2. Stream key bytes using key_valid_i/key_ready_o.
//   3. Assert key_finish_i until key_finish_ready_o = 1.
//   4. The engine internally normalizes K, sends K0^ipad to sha2_stream,
//      then raises data_ready_o when it is ready for message bytes.
//   5. Stream message bytes using data_valid_i/data_ready_o.
//   6. Assert finish_i until finish_ready_o = 1.
//   7. Wait for hmac_valid_o. hmac_o is valid for that cycle.
//
// Notes:
//   * One sha2_stream instance is reused for key hashing, inner hash and outer
//     hash, minimizing area at the cost of latency.
//   * For a simple first implementation, every key is hashed once internally.
//     For keys <= 64 bytes that digest is discarded and the original padded
//     key is used. A later optimization may bypass this unnecessary key hash.
//   * This module always operates sha2_stream in SHA2_256 mode.
// ============================================================================

`default_nettype none

module hmac_sha256 (
    input  wire         clk_i,
    input  wire         rst_ni,

    // Start a new HMAC operation.
    input  wire         start_i,
    output wire         start_ready_o,

    // Streaming HMAC key.
    input  wire [7:0]   key_i,
    input  wire         key_valid_i,
    output logic        key_ready_o,
    input  wire         key_finish_i,
    output logic        key_finish_ready_o,

    // Streaming message.
    input  wire [7:0]   data_i,
    input  wire         data_valid_i,
    output logic        data_ready_o,
    input  wire         finish_i,
    output logic        finish_ready_o,

    // Result/status.
    output wire         busy_o,
    output logic [255:0] hmac_o,
    output logic         hmac_valid_o
);

    import sha2_pkg::*;

    localparam logic [7:0] HMAC_IPAD = 8'h36;
    localparam logic [7:0] HMAC_OPAD = 8'h5c;

    typedef enum logic [3:0] {
        ST_IDLE,
        ST_KEY_HASH_START,
        ST_KEY_LOAD,
        ST_KEY_HASH_WAIT,
        ST_INNER_START,
        ST_INNER_PAD,
        ST_INNER_MSG,
        ST_INNER_WAIT,
        ST_OUTER_START,
        ST_OUTER_PAD,
        ST_OUTER_DIGEST,
        ST_OUTER_FINISH,
        ST_OUTER_WAIT
    } hmac_state_t;

    hmac_state_t state_q;

    // First 64 key bytes are retained so short keys can be zero padded.
    logic [511:0] key_buffer_q;
    logic [31:0]  key_count_q;

    // Normalized 64-byte HMAC key block K0.
    logic [511:0] key_block_q;

    // Inner SHA-256 digest.
    logic [255:0] inner_digest_q;

    logic [5:0] pad_index_q;
    logic [4:0] digest_index_q;

    // ------------------------------------------------------------------------
    // Shared SHA-2 streaming frontend.
    // ------------------------------------------------------------------------
    logic        sha_start_w;
    wire         sha_start_ready_w;
    logic [7:0]  sha_data_w;
    logic        sha_data_valid_w;
    wire         sha_data_ready_w;
    logic        sha_finish_w;
    wire         sha_finish_ready_w;
    wire         sha_busy_w;
    wire [511:0] sha_digest_w;
    wire         sha_digest_valid_w;

    // Byte selectors. Byte 0 is the most-significant byte.
    wire [8:0] key_write_msb_w = 9'd511 - ({3'b000, key_count_q[5:0]} << 3);
    wire [8:0] pad_byte_msb_w = 9'd511 - ({3'b000, pad_index_q} << 3);
    wire [8:0] digest_byte_msb_w = 9'd255 - ({4'b0000, digest_index_q} << 3);

    assign start_ready_o = (state_q == ST_IDLE);
    assign busy_o        = (state_q != ST_IDLE);

    sha2_stream u_sha2_stream (
        .clk_i          (clk_i),
        .rst_ni         (rst_ni),
        .start_i        (sha_start_w),
        .start_ready_o  (sha_start_ready_w),
        .mode_i         (SHA2_256),
        .data_i         (sha_data_w),
        .data_valid_i   (sha_data_valid_w),
        .data_ready_o   (sha_data_ready_w),
        .finish_i       (sha_finish_w),
        .finish_ready_o (sha_finish_ready_w),
        .busy_o         (sha_busy_w),
        .digest_o       (sha_digest_w),
        .digest_valid_o (sha_digest_valid_w)
    );

    // ------------------------------------------------------------------------
    // Combinational routing to/from the single shared sha2_stream instance.
    // ------------------------------------------------------------------------
    always_comb begin
        sha_start_w          = 1'b0;
        sha_data_w           = 8'h00;
        sha_data_valid_w     = 1'b0;
        sha_finish_w         = 1'b0;

        key_ready_o          = 1'b0;
        key_finish_ready_o   = 1'b0;
        data_ready_o         = 1'b0;
        finish_ready_o       = 1'b0;

        case (state_q)
            // Start a SHA-256 message that hashes the key. This is used for
            // long-key normalization and discarded for keys <= 64 bytes.
            ST_KEY_HASH_START: begin
                sha_start_w = 1'b1;
            end

            // Forward external key bytes directly into sha2_stream while also
            // saving the first 64 bytes locally.
            ST_KEY_LOAD: begin
                sha_data_w         = key_i;
                sha_data_valid_w   = key_valid_i;
                key_ready_o        = sha_data_ready_w;

                sha_finish_w       = key_finish_i;
                key_finish_ready_o = sha_finish_ready_w;
            end

            ST_INNER_START: begin
                sha_start_w = 1'b1;
            end

            // Inject exactly 64 bytes of K0 xor ipad.
            ST_INNER_PAD: begin
                sha_data_w       = key_block_q[pad_byte_msb_w -: 8] ^ HMAC_IPAD;
                sha_data_valid_w = 1'b1;
            end

            // Forward the user's message bytes into the inner hash.
            ST_INNER_MSG: begin
                sha_data_w       = data_i;
                sha_data_valid_w = data_valid_i;
                data_ready_o     = sha_data_ready_w;

                sha_finish_w     = finish_i;
                finish_ready_o   = sha_finish_ready_w;
            end

            ST_OUTER_START: begin
                sha_start_w = 1'b1;
            end

            // Inject exactly 64 bytes of K0 xor opad.
            ST_OUTER_PAD: begin
                sha_data_w       = key_block_q[pad_byte_msb_w -: 8] ^ HMAC_OPAD;
                sha_data_valid_w = 1'b1;
            end

            // Append the 32-byte inner digest to the outer SHA-256 message.
            ST_OUTER_DIGEST: begin
                sha_data_w       = inner_digest_q[digest_byte_msb_w -: 8];
                sha_data_valid_w = 1'b1;
            end

            // End the outer SHA-256 message.
            ST_OUTER_FINISH: begin
                sha_finish_w = 1'b1;
            end

            default: begin
                sha_start_w          = 1'b0;
                sha_data_w           = 8'h00;
                sha_data_valid_w     = 1'b0;
                sha_finish_w         = 1'b0;
                key_ready_o          = 1'b0;
                key_finish_ready_o   = 1'b0;
                data_ready_o         = 1'b0;
                finish_ready_o       = 1'b0;
            end
        endcase
    end

    // ------------------------------------------------------------------------
    // HMAC controller.
    // ------------------------------------------------------------------------
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q          <= ST_IDLE;
            key_buffer_q     <= 512'd0;
            key_count_q      <= 32'd0;
            key_block_q      <= 512'd0;
            inner_digest_q   <= 256'd0;
            pad_index_q      <= 6'd0;
            digest_index_q   <= 5'd0;
            hmac_o           <= 256'd0;
            hmac_valid_o     <= 1'b0;
        end
        else begin
            // Final result valid for one clock cycle.
            hmac_valid_o <= 1'b0;

            case (state_q)
                ST_IDLE: begin
                    if (start_i && start_ready_o) begin
                        key_buffer_q   <= 512'd0;
                        key_count_q    <= 32'd0;
                        key_block_q    <= 512'd0;
                        inner_digest_q <= 256'd0;
                        pad_index_q    <= 6'd0;
                        digest_index_q <= 5'd0;
                        state_q        <= ST_KEY_HASH_START;
                    end
                end

                ST_KEY_HASH_START: begin
                    if (sha_start_ready_w) begin
                        state_q <= ST_KEY_LOAD;
                    end
                end

                ST_KEY_LOAD: begin
                    // A key byte is accepted only on the normal valid/ready
                    // handshake of sha2_stream.
                    if (key_valid_i && key_ready_o) begin
                        if (key_count_q < 32'd64)
                            key_buffer_q[key_write_msb_w -: 8] <= key_i;
                        key_count_q <= key_count_q + 32'd1;
                    end

                    // key_finish_i is accepted only when sha2_stream itself is
                    // ready to terminate the key message.
                    if (key_finish_i && key_finish_ready_o) begin
                        state_q <= ST_KEY_HASH_WAIT;
                    end
                end

                ST_KEY_HASH_WAIT: begin
                    if (sha_digest_valid_w) begin
                        if (key_count_q > 32'd64)
                            key_block_q <= {sha_digest_w[255:0], 256'd0};
                        else
                            key_block_q <= key_buffer_q;

                        pad_index_q <= 6'd0;
                        state_q     <= ST_INNER_START;
                    end
                end

                ST_INNER_START: begin
                    if (sha_start_ready_w) begin
                        pad_index_q <= 6'd0;
                        state_q     <= ST_INNER_PAD;
                    end
                end

                ST_INNER_PAD: begin
                    if (sha_data_valid_w && sha_data_ready_w) begin
                        if (pad_index_q == 6'd63) begin
                            pad_index_q <= 6'd0;
                            state_q     <= ST_INNER_MSG;
                        end
                        else begin
                            pad_index_q <= pad_index_q + 6'd1;
                        end
                    end
                end

                ST_INNER_MSG: begin
                    if (finish_i && finish_ready_o) begin
                        state_q <= ST_INNER_WAIT;
                    end
                end

                ST_INNER_WAIT: begin
                    if (sha_digest_valid_w) begin
                        inner_digest_q <= sha_digest_w[255:0];
                        state_q        <= ST_OUTER_START;
                    end
                end

                ST_OUTER_START: begin
                    if (sha_start_ready_w) begin
                        pad_index_q <= 6'd0;
                        state_q     <= ST_OUTER_PAD;
                    end
                end

                ST_OUTER_PAD: begin
                    if (sha_data_valid_w && sha_data_ready_w) begin
                        if (pad_index_q == 6'd63) begin
                            digest_index_q <= 5'd0;
                            state_q        <= ST_OUTER_DIGEST;
                        end
                        else begin
                            pad_index_q <= pad_index_q + 6'd1;
                        end
                    end
                end

                ST_OUTER_DIGEST: begin
                    if (sha_data_valid_w && sha_data_ready_w) begin
                        if (digest_index_q == 5'd31) begin
                            digest_index_q <= 5'd0;
                            state_q        <= ST_OUTER_FINISH;
                        end
                        else begin
                            digest_index_q <= digest_index_q + 5'd1;
                        end
                    end
                end

                ST_OUTER_FINISH: begin
                    if (sha_finish_ready_w) begin
                        state_q <= ST_OUTER_WAIT;
                    end
                end

                ST_OUTER_WAIT: begin
                    if (sha_digest_valid_w) begin
                        hmac_o       <= sha_digest_w[255:0];
                        hmac_valid_o <= 1'b1;
                        state_q      <= ST_IDLE;
                    end
                end

                default: begin
                    state_q      <= ST_IDLE;
                    hmac_valid_o <= 1'b0;
                end
            endcase
        end
    end

endmodule

`default_nettype wire
