//============================================================================================================================
// Module      : sha2_constants
// Description :
//   Constant adapter for a unified SHA-256 / SHA-512 core.
//
// Reuse strategy:
//   - Reuse Secworks sha512_k_constants unchanged.
//   - Reuse Secworks sha512_h_constants unchanged in SHA-512 mode (mode = 2'b11).
//   - SHA-256 K[t] is the upper 32 bits of SHA-512 K[t] for t = 0..63.
//   - SHA-256 IV words are the upper 32 bits of the standard SHA-512 IV words.
//   - Unified outputs are always 64-bit. SHA-256 constants are placed in bits [31:0] and zero-extended.
//============================================================================================================================

`default_nettype none

import sha2_pkg::*;

module sha2_constants (
    input  wire sha2_pkg::sha2_mode_t  mode_i,
    input  wire [6:0]   round_i,

    output logic [63:0]  k_o,

    output logic [63:0]  iv0_o,
    output logic [63:0]  iv1_o,
    output logic [63:0]  iv2_o,
    output logic [63:0]  iv3_o,
    output logic [63:0]  iv4_o,
    output logic [63:0]  iv5_o,
    output logic [63:0]  iv6_o,
    output logic [63:0]  iv7_o
);

    //========================================================================================================================
    // Raw Secworks SHA-512 constants
    //========================================================================================================================
    logic [63:0] k512_raw;

    logic [63:0] h512_0;
    logic [63:0] h512_1;
    logic [63:0] h512_2;
    logic [63:0] h512_3;
    logic [63:0] h512_4;
    logic [63:0] h512_5;
    logic [63:0] h512_6;
    logic [63:0] h512_7;

    //========================================================================================================================
    // Reuse the original Secworks SHA-512 K table without modification.
    //========================================================================================================================
    sha512_k_constants u_sha512_k_constants (
        .addr (round_i),
        .K    (k512_raw)
    );

    //========================================================================================================================
    // Reuse the original Secworks H table without modification.
    //
    // IMPORTANT:
    //   Secworks' 2-bit "mode" is NOT the same as sha2_mode_t.
    //   In the Secworks block:
    //      2'b00 = SHA-512/224
    //      2'b01 = SHA-512/256
    //      2'b10 = SHA-384
    //      2'b11 = SHA-512
    //
    //   We always request the normal SHA-512 IV here, then adapt it for SHA-256 below.
    //========================================================================================================================
    sha512_h_constants u_sha512_h_constants (
        .H0   (h512_0),
        .H1   (h512_1),
        .H2   (h512_2),
        .H3   (h512_3),
        .H4   (h512_4),
        .H5   (h512_5),
        .H6   (h512_6),
        .H7   (h512_7)
    );

    //========================================================================================================================
    // Mode-dependent adaptation
    //========================================================================================================================
    always_comb begin

        // Safe defaults.
        k_o   = 64'b0;
        iv0_o = 64'b0;
        iv1_o = 64'b0;
        iv2_o = 64'b0;
        iv3_o = 64'b0;
        iv4_o = 64'b0;
        iv5_o = 64'b0;
        iv6_o = 64'b0;
        iv7_o = 64'b0;

        case (mode_i)

            //--------------------------------------------------------------------------------------------------------------
            // SHA-256 mode
            //
            // Active algorithm word is 32-bit, but physical datapath is 64-bit.
            // Put the selected 32-bit constant into [31:0] and force [63:32] to zero.
            //--------------------------------------------------------------------------------------------------------------
            SHA2_256: begin
                k_o   = {32'b0, k512_raw[63:32]};

                iv0_o = {32'b0, h512_0[63:32]};
                iv1_o = {32'b0, h512_1[63:32]};
                iv2_o = {32'b0, h512_2[63:32]};
                iv3_o = {32'b0, h512_3[63:32]};
                iv4_o = {32'b0, h512_4[63:32]};
                iv5_o = {32'b0, h512_5[63:32]};
                iv6_o = {32'b0, h512_6[63:32]};
                iv7_o = {32'b0, h512_7[63:32]};
            end

            //--------------------------------------------------------------------------------------------------------------
            // SHA-512 mode
            //--------------------------------------------------------------------------------------------------------------
            SHA2_512: begin
                k_o   = k512_raw;

                iv0_o = h512_0;
                iv1_o = h512_1;
                iv2_o = h512_2;
                iv3_o = h512_3;
                iv4_o = h512_4;
                iv5_o = h512_5;
                iv6_o = h512_6;
                iv7_o = h512_7;
            end

            default: begin
                // Keep all outputs at zero for X/Z/invalid mode values.
            end

        endcase

    end

endmodule

`default_nettype wire
