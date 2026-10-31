// ============================================================================
// Module      : hkdf_sha256
// Description : Unified HKDF-SHA-256 engine built on top of hmac_sha256.
//
// RFC 5869:
//   Extract:
//     PRK = HMAC-SHA256(salt, IKM)
//
//   Expand:
//     T(0) = empty
//     T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
//     OKM  = T(1) || T(2) || ... truncated to L bytes
//
// Supported operations:
//   2'b00 : EXTRACT_ONLY
//   2'b01 : EXPAND_ONLY
//   2'b10 : EXTRACT_AND_EXPAND
//
// Interface ordering:
//
// EXTRACT_ONLY:
//   start -> salt stream -> salt_finish -> IKM stream -> ikm_finish
//   -> PRK output stream (32 bytes) -> done
//
// EXPAND_ONLY:
//   start -> external PRK input stream (exactly 32 bytes) -> prk_finish
//   -> info stream -> info_finish -> OKM output stream -> done
//
// EXTRACT_AND_EXPAND:
//   start -> salt -> salt_finish -> IKM -> ikm_finish
//   -> PRK output stream (32 bytes)
//   -> info -> info_finish -> OKM output stream -> done
//
// Notes:
//   * All external cryptographic byte interfaces are 8-bit streaming interfaces.
//     This avoids making 256-bit PRK/OKM buses top-level physical I/O.
//   * One hmac_sha256 instance is reused for Extract and every Expand block.
//     This minimizes area at the cost of latency.
//   * info must be replayed for each T(i), so it is buffered internally.
//   * Default INFO_MAX_BYTES is 256 and may be changed by parameter.
//   * SHA-256 HashLen = 32 bytes, therefore RFC 5869 requires L <= 255*32
//     = 8160 bytes.
// ============================================================================

`default_nettype none

module hkdf_sha256 #(
    parameter integer INFO_MAX_BYTES = 256
) (
    input  wire         clk_i,
    input  wire         rst_ni,

    // ------------------------------------------------------------------------
    // Command.
    // ------------------------------------------------------------------------
    input  wire         start_i,
    output wire         start_ready_o,
    input  wire [1:0]   op_i,
    input  wire [13:0]  okm_len_i,       // bytes, valid range 0..8160

    // ------------------------------------------------------------------------
    // Extract input: salt becomes the HMAC key.
    // Used by EXTRACT_ONLY and EXTRACT_AND_EXPAND.
    // Zero-length salt is allowed.
    // ------------------------------------------------------------------------
    input  wire [7:0]   salt_i,
    input  wire         salt_valid_i,
    output logic        salt_ready_o,
    input  wire         salt_finish_i,
    output logic        salt_finish_ready_o,

    // Extract input: IKM becomes the HMAC message.
    input  wire [7:0]   ikm_i,
    input  wire         ikm_valid_i,
    output logic        ikm_ready_o,
    input  wire         ikm_finish_i,
    output logic        ikm_finish_ready_o,

    // ------------------------------------------------------------------------
    // Expand-only input: external PRK, exactly 32 bytes.
    // Used only by EXPAND_ONLY.
    // ------------------------------------------------------------------------
    input  wire [7:0]   prk_i,
    input  wire         prk_valid_i,
    output logic        prk_ready_o,
    input  wire         prk_finish_i,
    output logic        prk_finish_ready_o,

    // ------------------------------------------------------------------------
    // PRK result stream from Extract.
    // Used by EXTRACT_ONLY and EXTRACT_AND_EXPAND.
    // ------------------------------------------------------------------------
    output logic [7:0]  prk_o,
    output logic        prk_valid_o,
    input  wire         prk_ready_i,
    output logic        prk_last_o,

    // ------------------------------------------------------------------------
    // Expand input: info, buffered internally and replayed for every T(i).
    // Used by EXPAND_ONLY and EXTRACT_AND_EXPAND.
    // Zero-length info is allowed.
    // ------------------------------------------------------------------------
    input  wire [7:0]   info_i,
    input  wire         info_valid_i,
    output logic        info_ready_o,
    input  wire         info_finish_i,
    output logic        info_finish_ready_o,

    // ------------------------------------------------------------------------
    // Expand result stream.
    // ------------------------------------------------------------------------
    output logic [7:0]  okm_o,
    output logic        okm_valid_o,
    input  wire         okm_ready_i,
    output logic        okm_last_o,

    // ------------------------------------------------------------------------
    // Status.
    // done_o and error_o are one-cycle pulses.
    // ------------------------------------------------------------------------
    output wire         busy_o,
    output logic        done_o,
    output logic        error_o
);

    // Public operation encodings.
    localparam logic [1:0] OP_EXTRACT_ONLY       = 2'b00;
    localparam logic [1:0] OP_EXPAND_ONLY        = 2'b01;
    localparam logic [1:0] OP_EXTRACT_AND_EXPAND = 2'b10;

    localparam integer HASH_LEN_BYTES = 32;
    localparam integer MAX_OKM_BYTES  = 255 * HASH_LEN_BYTES; // 8160

    localparam integer INFO_CNT_W =
        (INFO_MAX_BYTES <= 1) ? 1 : $clog2(INFO_MAX_BYTES + 1);

    typedef enum logic [4:0] {
        ST_IDLE,

        ST_LOAD_EXTERNAL_PRK,

        ST_EXTRACT_START,
        ST_EXTRACT_SALT,
        ST_EXTRACT_IKM,
        ST_EXTRACT_WAIT,
        ST_PRK_OUT,

        ST_INFO_LOAD,

        ST_EXPAND_START,
        ST_EXPAND_KEY,
        ST_EXPAND_KEY_FINISH,
        ST_EXPAND_PREV,
        ST_EXPAND_INFO,
        ST_EXPAND_COUNTER,
        ST_EXPAND_FINISH,
        ST_EXPAND_WAIT,
        ST_OKM_OUT,

        ST_DONE
    } hkdf_state_t;

    hkdf_state_t state_q;

    logic [1:0]  op_q;
    logic [13:0] okm_len_q;
    logic [13:0] remaining_q;

    // 32-byte PRK retained internally.
    logic [255:0] prk_q;

    // Current/previous Expand block T(i).
    logic [255:0] t_q;

    // Buffered info. It must be replayed for every T(i).
    logic [7:0] info_mem [0:INFO_MAX_BYTES-1];
    logic [INFO_CNT_W-1:0] info_count_q;
    logic [INFO_CNT_W-1:0] info_index_q;

    // Byte indices.
    logic [5:0] prk_load_count_q;  // 0..32 for EXPAND_ONLY input.
    logic [4:0] prk_out_index_q;   // 0..31.
    logic [4:0] key_index_q;       // 0..31 when feeding PRK as HMAC key.
    logic [4:0] prev_index_q;      // 0..31 when feeding T(i-1).
    logic [5:0] okm_index_q;       // 0..31.
    logic [5:0] bytes_this_block_q;// 1..32.

    // Expand block number i = 1..255.
    logic [7:0] block_index_q;

    logic error_pending_q;

    // ------------------------------------------------------------------------
    // Shared HMAC-SHA-256 instance.
    // ------------------------------------------------------------------------
    logic        hmac_start_w;
    wire         hmac_start_ready_w;

    logic [7:0]  hmac_key_w;
    logic        hmac_key_valid_w;
    wire         hmac_key_ready_w;
    logic        hmac_key_finish_w;
    wire         hmac_key_finish_ready_w;

    logic [7:0]  hmac_data_w;
    logic        hmac_data_valid_w;
    wire         hmac_data_ready_w;
    logic        hmac_finish_w;
    wire         hmac_finish_ready_w;

    wire         hmac_busy_w;
    wire [255:0] hmac_result_w;
    wire         hmac_valid_w;

    hmac_sha256 u_hmac_sha256 (
        .clk_i              (clk_i),
        .rst_ni             (rst_ni),

        .start_i            (hmac_start_w),
        .start_ready_o      (hmac_start_ready_w),

        .key_i              (hmac_key_w),
        .key_valid_i        (hmac_key_valid_w),
        .key_ready_o        (hmac_key_ready_w),
        .key_finish_i       (hmac_key_finish_w),
        .key_finish_ready_o (hmac_key_finish_ready_w),

        .data_i             (hmac_data_w),
        .data_valid_i       (hmac_data_valid_w),
        .data_ready_o       (hmac_data_ready_w),
        .finish_i           (hmac_finish_w),
        .finish_ready_o     (hmac_finish_ready_w),

        .busy_o             (hmac_busy_w),
        .hmac_o             (hmac_result_w),
        .hmac_valid_o       (hmac_valid_w)
    );

    // ------------------------------------------------------------------------
    // Common outputs.
    // ------------------------------------------------------------------------
    assign start_ready_o = (state_q == ST_IDLE);
    assign busy_o        = (state_q != ST_IDLE);

    // ------------------------------------------------------------------------
    // Combinational interface routing.
    // ------------------------------------------------------------------------
    always_comb begin
        // HMAC defaults.
        hmac_start_w      = 1'b0;

        hmac_key_w        = 8'h00;
        hmac_key_valid_w  = 1'b0;
        hmac_key_finish_w = 1'b0;

        hmac_data_w       = 8'h00;
        hmac_data_valid_w = 1'b0;
        hmac_finish_w     = 1'b0;

        // External input defaults.
        salt_ready_o        = 1'b0;
        salt_finish_ready_o = 1'b0;
        ikm_ready_o         = 1'b0;
        ikm_finish_ready_o  = 1'b0;

        prk_ready_o         = 1'b0;
        prk_finish_ready_o  = 1'b0;

        info_ready_o        = 1'b0;
        info_finish_ready_o = 1'b0;

        // Extract PRK output defaults.
        prk_o       = 8'h00;
        prk_valid_o = 1'b0;
        prk_last_o  = 1'b0;

        // Expand OKM output defaults.
        okm_o       = 8'h00;
        okm_valid_o = 1'b0;
        okm_last_o  = 1'b0;

        case (state_q)
            // --------------------------------------------------------------
            // EXPAND_ONLY: load a 32-byte external PRK.
            // --------------------------------------------------------------
            ST_LOAD_EXTERNAL_PRK: begin
                prk_ready_o        = (prk_load_count_q < 6'd32);
                prk_finish_ready_o = !prk_valid_i;
            end

            // --------------------------------------------------------------
            // Extract: HMAC(salt, IKM)
            // --------------------------------------------------------------
            ST_EXTRACT_START: begin
                hmac_start_w = 1'b1;
            end

            ST_EXTRACT_SALT: begin
                hmac_key_w        = salt_i;
                hmac_key_valid_w  = salt_valid_i;
                salt_ready_o      = hmac_key_ready_w;

                hmac_key_finish_w = salt_finish_i;
                salt_finish_ready_o = hmac_key_finish_ready_w;
            end

            ST_EXTRACT_IKM: begin
                hmac_data_w        = ikm_i;
                hmac_data_valid_w  = ikm_valid_i;
                ikm_ready_o        = hmac_data_ready_w;

                hmac_finish_w      = ikm_finish_i;
                ikm_finish_ready_o = hmac_finish_ready_w;
            end

            // Stream the 32-byte PRK to the caller after Extract.
            ST_PRK_OUT: begin
                prk_o       = prk_q[255 - ({4'b0000, prk_out_index_q} << 3) -: 8];
                prk_valid_o = 1'b1;
                prk_last_o  = (prk_out_index_q == 5'd31);
            end

            // --------------------------------------------------------------
            // Buffer info for replay in each Expand HMAC.
            // --------------------------------------------------------------
            ST_INFO_LOAD: begin
                info_ready_o = (info_count_q < INFO_MAX_BYTES);
                // Finish is accepted only when no info byte is being offered
                // in the same cycle. This keeps the interface unambiguous.
                info_finish_ready_o = !info_valid_i;
            end

            // --------------------------------------------------------------
            // Expand block:
            // T(i) = HMAC(PRK, T(i-1) || info || i)
            // --------------------------------------------------------------
            ST_EXPAND_START: begin
                hmac_start_w = 1'b1;
            end

            // PRK is always the HMAC key for Expand.
            ST_EXPAND_KEY: begin
                hmac_key_w = prk_q[255 - ({4'b0000, key_index_q} << 3) -: 8];
                hmac_key_valid_w = 1'b1;
            end

            ST_EXPAND_KEY_FINISH: begin
                hmac_key_finish_w = 1'b1;
            end

            // For i > 1, prepend T(i-1).
            ST_EXPAND_PREV: begin
                hmac_data_w = t_q[255 - ({4'b0000, prev_index_q} << 3) -: 8];
                hmac_data_valid_w = 1'b1;
            end

            // Replay buffered info.
            ST_EXPAND_INFO: begin
                hmac_data_w       = info_mem[info_index_q];
                hmac_data_valid_w = 1'b1;
            end

            // Append the single-octet block counter i.
            ST_EXPAND_COUNTER: begin
                hmac_data_w       = block_index_q;
                hmac_data_valid_w = 1'b1;
            end

            ST_EXPAND_FINISH: begin
                hmac_finish_w = 1'b1;
            end

            // Stream current T(i), truncated on the final block if needed.
            ST_OKM_OUT: begin
                okm_o = t_q[255 - ({3'b000, okm_index_q[4:0]} << 3) -: 8];
                okm_valid_o = 1'b1;
                okm_last_o  = (remaining_q == bytes_this_block_q) && (okm_index_q == (bytes_this_block_q - 1'b1));
            end

            default: begin
                // Defaults already assigned.
            end
        endcase
    end

    // ------------------------------------------------------------------------
    // Sequential controller.
    // ------------------------------------------------------------------------
    integer mem_i;
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q             <= ST_IDLE;
            op_q                <= OP_EXTRACT_ONLY;
            okm_len_q           <= 14'd0;
            remaining_q         <= 14'd0;

            prk_q               <= 256'd0;
            t_q                 <= 256'd0;

            info_count_q        <= '0;
            info_index_q        <= '0;

            prk_load_count_q    <= 6'd0;
            prk_out_index_q     <= 5'd0;
            key_index_q         <= 5'd0;
            prev_index_q        <= 5'd0;
            okm_index_q         <= 6'd0;
            bytes_this_block_q  <= 6'd0;
            block_index_q       <= 8'd1;

            error_pending_q     <= 1'b0;
            done_o              <= 1'b0;
            error_o             <= 1'b0;

            for (mem_i = 0; mem_i < INFO_MAX_BYTES; mem_i = mem_i + 1)
                info_mem[mem_i] <= 8'h00;
        end
        else begin
            // Status outputs are pulses.
            done_o  <= 1'b0;
            error_o <= 1'b0;

            case (state_q)
                // ==========================================================
                // New operation.
                // ==========================================================
                ST_IDLE: begin
                    if (start_i && start_ready_o) begin
                        op_q               <= op_i;
                        okm_len_q          <= okm_len_i;
                        remaining_q        <= okm_len_i;

                        prk_q              <= 256'd0;
                        t_q                <= 256'd0;

                        info_count_q       <= '0;
                        info_index_q       <= '0;

                        prk_load_count_q   <= 6'd0;
                        prk_out_index_q    <= 5'd0;
                        key_index_q        <= 5'd0;
                        prev_index_q       <= 5'd0;
                        okm_index_q        <= 6'd0;
                        bytes_this_block_q <= 6'd0;
                        block_index_q      <= 8'd1;

                        error_pending_q    <= 1'b0;

                        // Validate command.
                        if ((op_i != OP_EXTRACT_ONLY) && (op_i != OP_EXPAND_ONLY) && (op_i != OP_EXTRACT_AND_EXPAND)) begin
                            error_pending_q <= 1'b1;
                            state_q         <= ST_DONE;
                        end
                        else if (((op_i == OP_EXPAND_ONLY) || (op_i == OP_EXTRACT_AND_EXPAND)) && (okm_len_i > MAX_OKM_BYTES)) begin
                            error_pending_q <= 1'b1;
                            state_q         <= ST_DONE;
                        end
                        else if (op_i == OP_EXPAND_ONLY) begin
                            state_q <= ST_LOAD_EXTERNAL_PRK;
                        end
                        else begin
                            state_q <= ST_EXTRACT_START;
                        end
                    end
                end

                // ==========================================================
                // EXPAND_ONLY external PRK input.
                // ==========================================================
                ST_LOAD_EXTERNAL_PRK: begin
                    if (prk_valid_i && prk_ready_o) begin
                        prk_q[255 - ({3'b000, prk_load_count_q[4:0]} << 3) -: 8]
                            <= prk_i;
                        prk_load_count_q <= prk_load_count_q + 6'd1;
                    end

                    if (prk_finish_i && prk_finish_ready_o) begin
                        if (prk_load_count_q != 6'd32) begin
                            error_pending_q <= 1'b1;
                            state_q         <= ST_DONE;
                        end
                        else if (okm_len_q == 14'd0) begin
                            state_q <= ST_DONE;
                        end
                        else begin
                            info_count_q <= '0;
                            state_q      <= ST_INFO_LOAD;
                        end
                    end
                end

                // ==========================================================
                // Extract: PRK = HMAC(salt, IKM)
                // ==========================================================
                ST_EXTRACT_START: begin
                    if (hmac_start_ready_w) begin
                        state_q <= ST_EXTRACT_SALT;
                    end
                end

                ST_EXTRACT_SALT: begin
                    if (salt_finish_i && salt_finish_ready_o) begin
                        state_q <= ST_EXTRACT_IKM;
                    end
                end

                ST_EXTRACT_IKM: begin
                    if (ikm_finish_i && ikm_finish_ready_o) begin
                        state_q <= ST_EXTRACT_WAIT;
                    end
                end

                ST_EXTRACT_WAIT: begin
                    if (hmac_valid_w) begin
                        prk_q           <= hmac_result_w;
                        prk_out_index_q <= 5'd0;
                        state_q         <= ST_PRK_OUT;
                    end
                end

                // ==========================================================
                // Expose Extract PRK as a 32-byte stream.
                // ==========================================================
                ST_PRK_OUT: begin
                    if (prk_valid_o && prk_ready_i) begin
                        if (prk_out_index_q == 5'd31) begin
                            prk_out_index_q <= 5'd0;

                            if (op_q == OP_EXTRACT_ONLY) begin
                                state_q <= ST_DONE;
                            end
                            else if (okm_len_q == 14'd0) begin
                                state_q <= ST_DONE;
                            end
                            else begin
                                info_count_q <= '0;
                                state_q      <= ST_INFO_LOAD;
                            end
                        end
                        else begin
                            prk_out_index_q <= prk_out_index_q + 5'd1;
                        end
                    end
                end

                // ==========================================================
                // Buffer info.
                // ==========================================================
                ST_INFO_LOAD: begin
                    if (info_valid_i && info_ready_o) begin
                        info_mem[info_count_q] <= info_i;
                        info_count_q <= info_count_q + 1'b1;
                    end
                    else if (info_valid_i && !info_ready_o) begin
                        // info is larger than the configured internal buffer.
                        error_pending_q <= 1'b1;
                        state_q         <= ST_DONE;
                    end

                    if (info_finish_i && info_finish_ready_o) begin
                        if (okm_len_q == 14'd0) begin
                            state_q <= ST_DONE;
                        end
                        else begin
                            remaining_q   <= okm_len_q;
                            block_index_q <= 8'd1;
                            state_q       <= ST_EXPAND_START;
                        end
                    end
                end

                // ==========================================================
                // Start HMAC for T(i).
                // ==========================================================
                ST_EXPAND_START: begin
                    if (hmac_start_ready_w) begin
                        key_index_q <= 5'd0;
                        state_q     <= ST_EXPAND_KEY;
                    end
                end

                // Send the 32-byte PRK as HMAC key.
                ST_EXPAND_KEY: begin
                    if (hmac_key_valid_w && hmac_key_ready_w) begin
                        if (key_index_q == 5'd31) begin
                            key_index_q <= 5'd0;
                            state_q     <= ST_EXPAND_KEY_FINISH;
                        end
                        else begin
                            key_index_q <= key_index_q + 5'd1;
                        end
                    end
                end

                // Finish PRK key stream, then construct HMAC message.
                ST_EXPAND_KEY_FINISH: begin
                    if (hmac_key_finish_ready_w) begin
                        if (block_index_q > 8'd1) begin
                            prev_index_q <= 5'd0;
                            state_q      <= ST_EXPAND_PREV;
                        end
                        else if (info_count_q != 0) begin
                            info_index_q <= '0;
                            state_q      <= ST_EXPAND_INFO;
                        end
                        else begin
                            state_q <= ST_EXPAND_COUNTER;
                        end
                    end
                end

                // T(i-1), present only for i > 1.
                ST_EXPAND_PREV: begin
                    if (hmac_data_valid_w && hmac_data_ready_w) begin
                        if (prev_index_q == 5'd31) begin
                            prev_index_q <= 5'd0;
                            if (info_count_q != 0) begin
                                info_index_q <= '0;
                                state_q      <= ST_EXPAND_INFO;
                            end
                            else begin
                                state_q <= ST_EXPAND_COUNTER;
                            end
                        end
                        else begin
                            prev_index_q <= prev_index_q + 5'd1;
                        end
                    end
                end

                // info
                ST_EXPAND_INFO: begin
                    if (hmac_data_valid_w && hmac_data_ready_w) begin
                        if (info_index_q == (info_count_q - 1'b1)) begin
                            info_index_q <= '0;
                            state_q      <= ST_EXPAND_COUNTER;
                        end
                        else begin
                            info_index_q <= info_index_q + 1'b1;
                        end
                    end
                end

                // One-byte counter i.
                ST_EXPAND_COUNTER: begin
                    if (hmac_data_valid_w && hmac_data_ready_w) begin
                        state_q <= ST_EXPAND_FINISH;
                    end
                end

                ST_EXPAND_FINISH: begin
                    if (hmac_finish_ready_w) begin
                        state_q <= ST_EXPAND_WAIT;
                    end
                end

                // Current T(i) is complete.
                ST_EXPAND_WAIT: begin
                    if (hmac_valid_w) begin
                        t_q         <= hmac_result_w;
                        okm_index_q <= 6'd0;

                        if (remaining_q > HASH_LEN_BYTES)
                            bytes_this_block_q <= HASH_LEN_BYTES;
                        else
                            bytes_this_block_q <= remaining_q[5:0];

                        state_q <= ST_OKM_OUT;
                    end
                end

                // Stream T(i), truncating the final block to exactly L bytes.
                ST_OKM_OUT: begin
                    if (okm_valid_o && okm_ready_i) begin
                        if (okm_index_q == (bytes_this_block_q - 1'b1)) begin
                            okm_index_q <= 6'd0;

                            if (remaining_q == bytes_this_block_q) begin
                                remaining_q <= 14'd0;
                                state_q     <= ST_DONE;
                            end
                            else begin
                                remaining_q   <= remaining_q - bytes_this_block_q;
                                block_index_q <= block_index_q + 8'd1;
                                state_q       <= ST_EXPAND_START;
                            end
                        end
                        else begin
                            okm_index_q <= okm_index_q + 6'd1;
                        end
                    end
                end

                // ==========================================================
                // Completion/error pulse.
                // ==========================================================
                ST_DONE: begin
                    done_o          <= 1'b1;
                    error_o         <= error_pending_q;
                    error_pending_q <= 1'b0;
                    state_q         <= ST_IDLE;
                end

                default: begin
                    error_pending_q <= 1'b1;
                    state_q         <= ST_DONE;
                end
            endcase
        end
    end

endmodule

`default_nettype wire
