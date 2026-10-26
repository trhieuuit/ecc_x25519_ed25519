//============================================================================================================================
// Module      : sha256_core
//
// Description :
//   SHA-256 compression core.
//   Processes exactly one 512-bit block per operation and performs 64 SHA-256 rounds.
//
// Operation:
//   init_i = 1 : start a new hash from the standard SHA-256 IV.
//   next_i = 1 : process the next block using the current chaining state.
//
// Notes:
//   - Padding and message-length handling are NOT performed here.
//   - Those functions belong to sha256.sv.
//   - One round is executed per clock cycle.
//============================================================================================================================

import sha256_pkg::*;

module sha256_core_ref (

    //========================================================================================================================
    // Clock and reset
    //========================================================================================================================
    input  logic         clk_i,
    input  logic         rst_ni,

    //========================================================================================================================
    // Control
    //========================================================================================================================
    input  logic         init_i,
    input  logic         next_i,

    //========================================================================================================================
    // 512-bit message block
    //========================================================================================================================
    input  logic [511:0] block_i,

    //========================================================================================================================
    // Status / result
    //========================================================================================================================
    output logic         ready_o,
    output logic [255:0] digest_o,
    output logic         digest_valid_o,
    output logic         busy_o
);

    //========================================================================================================================
    // FSM
    //========================================================================================================================
    typedef enum logic [1:0] {
        ST_IDLE,
        ST_ROUND,
        ST_DONE
    } state_t;

    state_t state_q;

    //========================================================================================================================
    // Chaining state H0..H7
    //========================================================================================================================
    logic [31:0] h0_q, h1_q, h2_q, h3_q;
    logic [31:0] h4_q, h5_q, h6_q, h7_q;

    //========================================================================================================================
    // Working variables a..h
    //========================================================================================================================
    logic [31:0] a_q, b_q, c_q, d_q;
    logic [31:0] e_q, f_q, g_q, h_q;

    logic [31:0] a_next_w, b_next_w, c_next_w, d_next_w;
    logic [31:0] e_next_w, f_next_w, g_next_w, h_next_w;

    //========================================================================================================================
    // 16-word rolling message schedule
    //========================================================================================================================
    logic [31:0] w_q [0:15];

    logic [31:0] w_t_w;
    logic [31:0] w_new_w;

    logic [5:0]  round_q;

    //========================================================================================================================
    // Round datapath
    //========================================================================================================================
    logic [31:0] t1_w;
    logic [31:0] t2_w;

    integer i;

    // W[t] generation.
    //
    // For rounds 0..15, use words directly from the input block.
    // For rounds 16..63, derive the next word from the rolling 16-word window.
    always_comb begin
        w_new_w = sha256_ssig1(w_q[14])
                + w_q[9]
                + sha256_ssig0(w_q[1])
                + w_q[0];

        if (round_q < 6'd16)
            w_t_w = w_q[round_q];
        else
            w_t_w = w_new_w;
    end

    // SHA-256 round equations.
    always_comb begin
        t1_w = h_q
             + sha256_bsig1(e_q)
             + sha256_ch(e_q, f_q, g_q)
             + SHA256_K[round_q]
             + w_t_w;

        t2_w = sha256_bsig0(a_q)
             + sha256_maj(a_q, b_q, c_q);

        a_next_w = t1_w + t2_w;
        b_next_w = a_q;
        c_next_w = b_q;
        d_next_w = c_q;
        e_next_w = d_q + t1_w;
        f_next_w = e_q;
        g_next_w = f_q;
        h_next_w = g_q;
    end

    //========================================================================================================================
    // Output assignments
    //========================================================================================================================
    assign ready_o = (state_q == ST_IDLE);
    assign busy_o  = (state_q == ST_ROUND);

    assign digest_o = {
        h0_q, h1_q, h2_q, h3_q,
        h4_q, h5_q, h6_q, h7_q
    };

    assign digest_valid_o = (state_q == ST_DONE);

    //========================================================================================================================
    // Sequential logic
    //========================================================================================================================
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin

            state_q <= ST_IDLE;
            round_q <= '0;

            h0_q <= SHA256_H0;
            h1_q <= SHA256_H1;
            h2_q <= SHA256_H2;
            h3_q <= SHA256_H3;
            h4_q <= SHA256_H4;
            h5_q <= SHA256_H5;
            h6_q <= SHA256_H6;
            h7_q <= SHA256_H7;

            a_q <= '0;
            b_q <= '0;
            c_q <= '0;
            d_q <= '0;
            e_q <= '0;
            f_q <= '0;
            g_q <= '0;
            h_q <= '0;

            for (i = 0; i < 16; i = i + 1)
                w_q[i] <= '0;

        end
        else begin

            case (state_q)

                //============================================================================================================
                // IDLE
                //============================================================================================================
                ST_IDLE: begin

                    if (init_i || next_i) begin

                        // Load 16 big-endian words from the 512-bit message block.
                        for (i = 0; i < 16; i = i + 1)
                            w_q[i] <= block_i[511 - (i * 32) -: 32];

                        round_q <= 6'd0;

                        // Start a new message from the SHA-256 IV.
                        if (init_i) begin

                            h0_q <= SHA256_H0;
                            h1_q <= SHA256_H1;
                            h2_q <= SHA256_H2;
                            h3_q <= SHA256_H3;
                            h4_q <= SHA256_H4;
                            h5_q <= SHA256_H5;
                            h6_q <= SHA256_H6;
                            h7_q <= SHA256_H7;

                            a_q <= SHA256_H0;
                            b_q <= SHA256_H1;
                            c_q <= SHA256_H2;
                            d_q <= SHA256_H3;
                            e_q <= SHA256_H4;
                            f_q <= SHA256_H5;
                            g_q <= SHA256_H6;
                            h_q <= SHA256_H7;

                        end
                        // Continue an existing multi-block message.
                        else begin

                            a_q <= h0_q;
                            b_q <= h1_q;
                            c_q <= h2_q;
                            d_q <= h3_q;
                            e_q <= h4_q;
                            f_q <= h5_q;
                            g_q <= h6_q;
                            h_q <= h7_q;

                        end

                        state_q <= ST_ROUND;

                    end

                end


                //============================================================================================================
                // SHA-256 64-round compression
                //============================================================================================================
                ST_ROUND: begin

                    a_q <= a_next_w;
                    b_q <= b_next_w;
                    c_q <= c_next_w;
                    d_q <= d_next_w;
                    e_q <= e_next_w;
                    f_q <= f_next_w;
                    g_q <= g_next_w;
                    h_q <= h_next_w;

                    // Update rolling message schedule from round 16 onward.
                    if (round_q >= 6'd16) begin
                        for (i = 0; i < 15; i = i + 1)
                            w_q[i] <= w_q[i + 1];

                        w_q[15] <= w_new_w;
                    end

                    // Final round: add working variables to chaining state.
                    if (round_q == 6'd63) begin

                        h0_q <= h0_q + a_next_w;
                        h1_q <= h1_q + b_next_w;
                        h2_q <= h2_q + c_next_w;
                        h3_q <= h3_q + d_next_w;
                        h4_q <= h4_q + e_next_w;
                        h5_q <= h5_q + f_next_w;
                        h6_q <= h6_q + g_next_w;
                        h7_q <= h7_q + h_next_w;

                        state_q <= ST_DONE;

                    end
                    else begin
                        round_q <= round_q + 1'b1;
                    end

                end


                //============================================================================================================
                // Result is valid for one clock cycle
                //============================================================================================================
                ST_DONE: begin
                    state_q <= ST_IDLE;
                end


                default: begin
                    state_q <= ST_IDLE;
                end

            endcase

        end
    end

endmodule
