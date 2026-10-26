//============================================================================================================================
// Module      : sha2_core
// Description :
//   Unified SHA-256 / SHA-512 compression core.
//
// Design basis:
//   This module is forked architecturally from the Secworks SHA-512 core.
//   The original SHA-512 core organization is retained where useful:
//     - 8 working registers a..h
//     - 8 chaining registers H0..H7
//     - one round counter
//     - IDLE -> ROUNDS -> DONE control flow
//     - init = first block of a new message
//     - next = following block of the same message
//
// Unified changes:
//   - Removes Secworks work_factor/work_factor_num functionality.
//   - Adds SHA2_256 / SHA2_512 algorithm mode.
//   - Latches the algorithm in mode_q at init_i.
//   - Reuses a single 64-bit physical datapath for both algorithms.
//   - Instantiates sha2_constants, sha2_w_mem and sha2_round.
//   - Selects 64 rounds for SHA-256 and 80 rounds for SHA-512.
//   - Applies modulo 2^32 chaining updates in SHA-256 mode.
//   - Applies modulo 2^64 chaining updates in SHA-512 mode.
//   - Formats SHA-256 digest into digest_o[255:0] with digest_o[511:256] = 0.
//   - Formats SHA-512 digest across digest_o[511:0].
//
// Original Secworks SHA-512 work:
//   Author: Joachim Strombergson
//   Copyright (c) 2014 Secworks Sweden AB
//   All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//============================================================================================================================

`default_nettype none

module sha2_core (
    //========================================================================================================================
    // Clock / reset
    //========================================================================================================================
    input  wire                         clk_i,
    input  wire                         rst_ni,

    //========================================================================================================================
    // Hash algorithm selection
    //
    // mode_i is sampled ONLY when init_i is accepted in IDLE.
    // A following next_i block continues with the already latched mode_q.
    //========================================================================================================================
    input  wire sha2_pkg::sha2_mode_t   mode_i,

    //========================================================================================================================
    // Block control
    //
    // init_i : first block of a NEW message. Loads a new algorithm mode and IV.
    // next_i : next block of the SAME message. Reuses current chaining H state.
    //
    // Commands are accepted only while ready_o = 1.
    // If init_i and next_i are asserted together, init_i has priority.
    //========================================================================================================================
    input  wire                         init_i,
    input  wire                         next_i,

    //========================================================================================================================
    // Unified block input
    //
    // SHA-512 : block_i[1023:0]   is the full 1024-bit block.
    // SHA-256 : block_i[1023:512] is the 512-bit block; [511:0] is unused.
    //========================================================================================================================
    input  wire [1023:0]                block_i,

    //========================================================================================================================
    // Status / result
    //========================================================================================================================
    output wire                         ready_o,
    output wire                         busy_o,
    output logic [511:0]                digest_o,
    output wire                         digest_valid_o
);

    import sha2_pkg::*;

    //========================================================================================================================
    // Controller state
    //========================================================================================================================
    typedef enum logic [1:0] {
        ST_IDLE,
        ST_ROUNDS,
        ST_DONE
    } sha2_state_t;

    sha2_state_t state_q;

    //========================================================================================================================
    // Latched algorithm mode
    //
    // SHA-2 mode MUST remain constant across all rounds and all next_i blocks
    // belonging to one message. Therefore only init_i changes mode_q.
    //========================================================================================================================
    sha2_mode_t mode_q;
    sha2_mode_t mode_exec;

    //========================================================================================================================
    // Working variables a..h
    //
    // Physical width is always 64 bits.
    // SHA-256 invariant:
    //   a_q[63:32] ... h_q[63:32] are always zero.
    //========================================================================================================================
    logic [63:0] a_q;
    logic [63:0] b_q;
    logic [63:0] c_q;
    logic [63:0] d_q;
    logic [63:0] e_q;
    logic [63:0] f_q;
    logic [63:0] g_q;
    logic [63:0] h_q;

    //========================================================================================================================
    // Chaining state H0..H7
    //
    // Physical width is always 64 bits.
    // SHA-256 uses only [31:0] of each register.
    //========================================================================================================================
    logic [63:0] H0_q;
    logic [63:0] H1_q;
    logic [63:0] H2_q;
    logic [63:0] H3_q;
    logic [63:0] H4_q;
    logic [63:0] H5_q;
    logic [63:0] H6_q;
    logic [63:0] H7_q;

    //========================================================================================================================
    // Round counter
    //========================================================================================================================
    logic [6:0] round_q;
    logic [6:0] last_round;

    //========================================================================================================================
    // Digest-valid state
    //
    // This intentionally preserves the Secworks-style level behavior:
    //   - asserted when a block finishes and the chaining state is updated
    //   - remains asserted while IDLE
    //   - cleared when the next init_i/next_i command is accepted
    //
    // For a multi-block message, digest_o after an intermediate block is the
    // chaining value. The external message-level controller decides which block
    // is final.
    //========================================================================================================================
    logic digest_valid_q;

    //========================================================================================================================
    // Command acceptance
    //========================================================================================================================
    wire accept_init;
    wire accept_next;

    assign accept_init = (state_q == ST_IDLE) && init_i;
    assign accept_next = (state_q == ST_IDLE) && (!init_i) && next_i;

    //========================================================================================================================
    // Internal W-schedule control
    //========================================================================================================================
    wire w_init;
    wire w_next;

    assign w_init = accept_init || accept_next;
    assign w_next = (state_q == ST_ROUNDS);

    //========================================================================================================================
    // Constants / schedule / round datapath wires
    //========================================================================================================================
    wire [63:0] k_w;
    wire [63:0] w_w;

    wire [63:0] iv0_w;
    wire [63:0] iv1_w;
    wire [63:0] iv2_w;
    wire [63:0] iv3_w;
    wire [63:0] iv4_w;
    wire [63:0] iv5_w;
    wire [63:0] iv6_w;
    wire [63:0] iv7_w;

    wire [63:0] a_round_w;
    wire [63:0] b_round_w;
    wire [63:0] c_round_w;
    wire [63:0] d_round_w;
    wire [63:0] e_round_w;
    wire [63:0] f_round_w;
    wire [63:0] g_round_w;
    wire [63:0] h_round_w;

    //========================================================================================================================
    // Chaining-update combinational results
    //========================================================================================================================
    logic [63:0] H0_update_w;
    logic [63:0] H1_update_w;
    logic [63:0] H2_update_w;
    logic [63:0] H3_update_w;
    logic [63:0] H4_update_w;
    logic [63:0] H5_update_w;
    logic [63:0] H6_update_w;
    logic [63:0] H7_update_w;


    //========================================================================================================================
    // Status outputs
    //========================================================================================================================
    assign ready_o        = (state_q == ST_IDLE);
    assign busy_o         = (state_q != ST_IDLE);
    assign digest_valid_o = digest_valid_q;


    //========================================================================================================================
    // Mode used by blocks that load on the current clock edge
    //
    // Subtle but important:
    //   mode_q is updated on the SAME edge that accepts init_i. If sha2_w_mem and
    //   sha2_constants were driven only by the old mode_q before that edge, a new
    //   message could accidentally load its first block/IV using the previous
    //   message's algorithm.
    //
    // Therefore:
    //   - while accepting init_i, use external mode_i immediately
    //   - otherwise use the already latched mode_q
    //========================================================================================================================
    always_comb begin
        mode_exec = mode_q;

        if (accept_init)
            mode_exec = mode_i;
    end


    //========================================================================================================================
    // Last-round selection
    //========================================================================================================================
    always_comb begin
        case (mode_q)
            SHA2_256: last_round = SHA256_LAST_ROUND;  // 63 => 64 rounds total
            SHA2_512: last_round = SHA512_LAST_ROUND;  // 79 => 80 rounds total
            default : last_round = SHA256_LAST_ROUND;
        endcase
    end


    //========================================================================================================================
    // Unified constants
    //
    // mode_exec is used rather than mode_q so that the correct IV is visible in
    // the cycle in which a NEW init_i command is accepted.
    //========================================================================================================================
    sha2_constants u_sha2_constants (
        .mode_i  (mode_exec),
        .round_i (round_q),

        .k_o     (k_w),

        .iv0_o   (iv0_w),
        .iv1_o   (iv1_w),
        .iv2_o   (iv2_w),
        .iv3_o   (iv3_w),
        .iv4_o   (iv4_w),
        .iv5_o   (iv5_w),
        .iv6_o   (iv6_w),
        .iv7_o   (iv7_w)
    );


    //========================================================================================================================
    // Unified W message schedule
    //
    // mode_exec guarantees that the first block of a newly selected algorithm is
    // loaded with the correct 32-bit/64-bit word interpretation.
    // During ROUNDS, mode_exec == mode_q.
    //========================================================================================================================
    sha2_w_mem u_sha2_w_mem (
        .clk_i   (clk_i),
        .rst_ni  (rst_ni),
        .mode_i  (mode_exec),
        .block_i (block_i),
        .init_i  (w_init),
        .next_i  (w_next),
        .w_o     (w_w)
    );


    //========================================================================================================================
    // Unified compression round datapath
    //
    // sha2_round contains no registers. It produces the next a..h values for one
    // SHA round from the current state, K[t], and W[t].
    //========================================================================================================================
    sha2_round u_sha2_round (
        .mode_i (mode_q),

        .a_i    (a_q),
        .b_i    (b_q),
        .c_i    (c_q),
        .d_i    (d_q),
        .e_i    (e_q),
        .f_i    (f_q),
        .g_i    (g_q),
        .h_i    (h_q),

        .k_i    (k_w),
        .w_i    (w_w),

        .a_o    (a_round_w),
        .b_o    (b_round_w),
        .c_o    (c_round_w),
        .d_o    (d_round_w),
        .e_o    (e_round_w),
        .f_o    (f_round_w),
        .g_o    (g_round_w),
        .h_o    (h_round_w)
    );


    //========================================================================================================================
    // Chaining update
    //
    // After the final compression round of one block:
    //
    //   H0 <- H0 + a
    //   H1 <- H1 + b
    //   ...
    //   H7 <- H7 + h
    //
    // sha2_norm_word enforces the algorithm word width:
    //   SHA-256 => modulo 2^32
    //   SHA-512 => modulo 2^64
    //========================================================================================================================
    always_comb begin
        H0_update_w = sha2_norm_word(H0_q + a_q, mode_q);
        H1_update_w = sha2_norm_word(H1_q + b_q, mode_q);
        H2_update_w = sha2_norm_word(H2_q + c_q, mode_q);
        H3_update_w = sha2_norm_word(H3_q + d_q, mode_q);
        H4_update_w = sha2_norm_word(H4_q + e_q, mode_q);
        H5_update_w = sha2_norm_word(H5_q + f_q, mode_q);
        H6_update_w = sha2_norm_word(H6_q + g_q, mode_q);
        H7_update_w = sha2_norm_word(H7_q + h_q, mode_q);
    end


    //========================================================================================================================
    // Digest formatting
    //
    // SHA-512:
    //   digest_o = H0 || H1 || ... || H7              (512 bits)
    //
    // SHA-256:
    //   digest_o[511:256] = 0
    //   digest_o[255:0]   = H0[31:0] || ... || H7[31:0]
    //
    // This gives the unified block a fixed 512-bit output port while preserving
    // the standard SHA-256 digest ordering in the low 256 bits.
    //========================================================================================================================
    always_comb begin
        digest_o = 512'b0;

        case (mode_q)
            SHA2_256: begin
                digest_o = {
                    256'b0,
                    H0_q[31:0], H1_q[31:0], H2_q[31:0], H3_q[31:0],
                    H4_q[31:0], H5_q[31:0], H6_q[31:0], H7_q[31:0]
                };
            end

            SHA2_512: begin
                digest_o = {
                    H0_q, H1_q, H2_q, H3_q,
                    H4_q, H5_q, H6_q, H7_q
                };
            end

            default: begin
                digest_o = 512'b0;
            end
        endcase
    end


    //========================================================================================================================
    // Main sequential controller / register update
    //========================================================================================================================
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q        <= ST_IDLE;
            mode_q         <= SHA2_256;
            round_q        <= 7'd0;
            digest_valid_q <= 1'b0;

            a_q <= 64'b0;
            b_q <= 64'b0;
            c_q <= 64'b0;
            d_q <= 64'b0;
            e_q <= 64'b0;
            f_q <= 64'b0;
            g_q <= 64'b0;
            h_q <= 64'b0;

            H0_q <= 64'b0;
            H1_q <= 64'b0;
            H2_q <= 64'b0;
            H3_q <= 64'b0;
            H4_q <= 64'b0;
            H5_q <= 64'b0;
            H6_q <= 64'b0;
            H7_q <= 64'b0;
        end
        else begin
            case (state_q)

                //============================================================================================================
                // IDLE
                //
                // init_i:
                //   Start a NEW message:
                //     1. latch mode_i into mode_q
                //     2. load H0..H7 from the selected IV
                //     3. load working a..h from the same IV
                //     4. load W0..W15 in sha2_w_mem through w_init
                //     5. start round 0
                //
                // next_i:
                //   Continue SAME message:
                //     1. keep mode_q unchanged
                //     2. keep H0..H7 chaining state unchanged
                //     3. load working a..h from H0..H7
                //     4. load the next block into W memory
                //     5. start round 0
                //============================================================================================================
                ST_IDLE: begin
                    if (init_i) begin
                        mode_q  <= mode_i;
                        round_q <= 7'd0;

                        H0_q <= iv0_w;
                        H1_q <= iv1_w;
                        H2_q <= iv2_w;
                        H3_q <= iv3_w;
                        H4_q <= iv4_w;
                        H5_q <= iv5_w;
                        H6_q <= iv6_w;
                        H7_q <= iv7_w;

                        a_q <= iv0_w;
                        b_q <= iv1_w;
                        c_q <= iv2_w;
                        d_q <= iv3_w;
                        e_q <= iv4_w;
                        f_q <= iv5_w;
                        g_q <= iv6_w;
                        h_q <= iv7_w;

                        digest_valid_q <= 1'b0;
                        state_q        <= ST_ROUNDS;
                    end
                    else if (next_i) begin
                        round_q <= 7'd0;

                        a_q <= H0_q;
                        b_q <= H1_q;
                        c_q <= H2_q;
                        d_q <= H3_q;
                        e_q <= H4_q;
                        f_q <= H5_q;
                        g_q <= H6_q;
                        h_q <= H7_q;

                        digest_valid_q <= 1'b0;
                        state_q        <= ST_ROUNDS;
                    end
                end


                //============================================================================================================
                // ROUNDS
                //
                // One complete SHA round is committed per clock cycle.
                // sha2_round computes a_round_w..h_round_w combinationally from:
                //   current a_q..h_q + K[round_q] + W[round_q].
                //============================================================================================================
                ST_ROUNDS: begin
                    a_q <= a_round_w;
                    b_q <= b_round_w;
                    c_q <= c_round_w;
                    d_q <= d_round_w;
                    e_q <= e_round_w;
                    f_q <= f_round_w;
                    g_q <= g_round_w;
                    h_q <= h_round_w;

                    if (round_q == last_round) begin
                        // The final round result is captured now.
                        // The chaining addition is intentionally deferred to ST_DONE
                        // so that it uses the fully updated final a_q..h_q values.
                        state_q <= ST_DONE;
                    end
                    else begin
                        round_q <= round_q + 7'd1;
                    end
                end


                //============================================================================================================
                // DONE
                //
                // At entry to this state, a_q..h_q already contain the result of
                // the final compression round. Perform the feed-forward/chaining
                // addition now and return to IDLE.
                //============================================================================================================
                ST_DONE: begin
                    H0_q <= H0_update_w;
                    H1_q <= H1_update_w;
                    H2_q <= H2_update_w;
                    H3_q <= H3_update_w;
                    H4_q <= H4_update_w;
                    H5_q <= H5_update_w;
                    H6_q <= H6_update_w;
                    H7_q <= H7_update_w;

                    digest_valid_q <= 1'b1;
                    state_q        <= ST_IDLE;
                end


                default: begin
                    state_q        <= ST_IDLE;
                    digest_valid_q <= 1'b0;
                end

            endcase
        end
    end

endmodule

`default_nettype wire
