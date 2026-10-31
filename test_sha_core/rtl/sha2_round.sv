//============================================================================================================================
// Module      : sha2_round
// Description :
//   Unified SHA-256 / SHA-512 round datapath.
//
// Design basis:
//   This module is derived from the t1_logic, t2_logic and state_logic ideas in
//   the Secworks SHA-512 core, but separates the combinational round datapath
//   from the controller/register logic.
//
// Unified design rule:
//   - Physical datapath width is always 64 bits.
//   - SHA-512 uses all 64 bits.
//   - SHA-256 uses only bits [31:0]; bits [63:32] are forced to zero at the
//     module output/register boundary.
//   - SHA-256 arithmetic is therefore reduced modulo 2^32.
//   - SHA-512 arithmetic is reduced modulo 2^64.
//
// Round equations used by both SHA-256 and SHA-512:
//
//   T1 = h + BSIG1(e) + Ch(e,f,g) + K[t] + W[t]
//   T2 = BSIG0(a) + Maj(a,b,c)
//
//   a' = T1 + T2
//   b' = a
//   c' = b
//   d' = c
//   e' = d + T1
//   f' = e
//   g' = f
//   h' = g
//
// Only BSIG0/BSIG1 and effective word width depend on mode.
//============================================================================================================================

`default_nettype none

module sha2_round (
    //========================================================================================================================
    // Algorithm mode
    //========================================================================================================================
    input  wire sha2_pkg::sha2_mode_t mode_i,

    //========================================================================================================================
    // Current working state a..h
    //========================================================================================================================
    input  wire logic [63:0] a_i,
    input  wire logic [63:0] b_i,
    input  wire logic [63:0] c_i,
    input  wire logic [63:0] d_i,
    input  wire logic [63:0] e_i,
    input  wire logic [63:0] f_i,
    input  wire logic [63:0] g_i,
    input  wire logic [63:0] h_i,

    //========================================================================================================================
    // Round constant K[t] and message-schedule word W[t]
    //========================================================================================================================
    input  wire logic [63:0] k_i,
    input  wire logic [63:0] w_i,

    //========================================================================================================================
    // Next working state a'..h'
    //========================================================================================================================
    output logic [63:0] a_o,
    output logic [63:0] b_o,
    output logic [63:0] c_o,
    output logic [63:0] d_o,
    output logic [63:0] e_o,
    output logic [63:0] f_o,
    output logic [63:0] g_o,
    output logic [63:0] h_o
);

    import sha2_pkg::*;

    //========================================================================================================================
    // Effective datapath operands
    //========================================================================================================================
    logic [63:0] a_eff;
    logic [63:0] b_eff;
    logic [63:0] c_eff;
    logic [63:0] d_eff;
    logic [63:0] e_eff;
    logic [63:0] f_eff;
    logic [63:0] g_eff;
    logic [63:0] h_eff;

    logic [63:0] k_eff;
    logic [63:0] w_eff;

    //========================================================================================================================
    // Shared Boolean functions
    //========================================================================================================================
    logic [63:0] ch_w;
    logic [63:0] maj_w;

    //========================================================================================================================
    // Mode-dependent big-sigma results
    //========================================================================================================================
    logic [63:0] bsig0_w;
    logic [63:0] bsig1_w;

    //========================================================================================================================
    // T1 / T2 and intermediate sums
    //========================================================================================================================
    logic [63:0] t1_raw;
    logic [63:0] t2_raw;

    logic [63:0] t1_eff;
    logic [63:0] t2_eff;

    logic [63:0] a_sum_raw;
    logic [63:0] e_sum_raw;


    //========================================================================================================================
    // Unified round combinational logic
    //========================================================================================================================
    always_comb begin

        //--------------------------------------------------------------------------------------------------------------
        // 1. Normalize all inputs according to the selected word width.
        //--------------------------------------------------------------------------------------------------------------
        a_eff = sha2_norm_word(a_i, mode_i);
        b_eff = sha2_norm_word(b_i, mode_i);
        c_eff = sha2_norm_word(c_i, mode_i);
        d_eff = sha2_norm_word(d_i, mode_i);
        e_eff = sha2_norm_word(e_i, mode_i);
        f_eff = sha2_norm_word(f_i, mode_i);
        g_eff = sha2_norm_word(g_i, mode_i);
        h_eff = sha2_norm_word(h_i, mode_i);

        k_eff = sha2_norm_word(k_i, mode_i);
        w_eff = sha2_norm_word(w_i, mode_i);

        //--------------------------------------------------------------------------------------------------------------
        // 2. Ch and Maj are structurally identical in SHA-256 and SHA-512.
        //--------------------------------------------------------------------------------------------------------------
        ch_w  = sha2_ch(e_eff, f_eff, g_eff);
        maj_w = sha2_maj(a_eff, b_eff, c_eff);

        //--------------------------------------------------------------------------------------------------------------
        // 3. Select the algorithm-specific big-sigma functions.
        //--------------------------------------------------------------------------------------------------------------
        bsig0_w = 64'b0;
        bsig1_w = 64'b0;

        case (mode_i)
            SHA2_256: begin
                bsig0_w = zext32(sha256_bsig0(a_eff[31:0]));
                bsig1_w = zext32(sha256_bsig1(e_eff[31:0]));
            end

            SHA2_512: begin
                bsig0_w = sha512_bsig0(a_eff);
                bsig1_w = sha512_bsig1(e_eff);
            end

            default: begin
                bsig0_w = 64'b0;
                bsig1_w = 64'b0;
            end
        endcase

        //--------------------------------------------------------------------------------------------------------------
        // 4. Shared T1 / T2 arithmetic.
        //
        //   T1 = h + BSIG1(e) + Ch(e,f,g) + K[t] + W[t]
        //   T2 = BSIG0(a) + Maj(a,b,c)
        //--------------------------------------------------------------------------------------------------------------
        t1_raw = h_eff + bsig1_w + ch_w + k_eff + w_eff;
        t2_raw = bsig0_w + maj_w;

        // Explicit word-width normalization:
        //   SHA-256 -> keep only [31:0]  => modulo 2^32
        //   SHA-512 -> keep all [63:0]   => modulo 2^64
        t1_eff = sha2_norm_word(t1_raw, mode_i);
        t2_eff = sha2_norm_word(t2_raw, mode_i);

        //--------------------------------------------------------------------------------------------------------------
        // 5. Compute the two additions needed by the next-state equations.
        //--------------------------------------------------------------------------------------------------------------
        a_sum_raw = t1_eff + t2_eff;
        e_sum_raw = d_eff  + t1_eff;

        //--------------------------------------------------------------------------------------------------------------
        // 6. Next working state.
        //
        //   a' = T1 + T2
        //   b' = a
        //   c' = b
        //   d' = c
        //   e' = d + T1
        //   f' = e
        //   g' = f
        //   h' = g
        //--------------------------------------------------------------------------------------------------------------
        a_o = sha2_norm_word(a_sum_raw, mode_i);

        b_o = a_eff;
        c_o = b_eff;
        d_o = c_eff;

        e_o = sha2_norm_word(e_sum_raw, mode_i);

        f_o = e_eff;
        g_o = f_eff;
        h_o = g_eff;
    end

endmodule

`default_nettype wire
