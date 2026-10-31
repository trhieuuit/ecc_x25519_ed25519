//============================================================================================================================
// Package     : sha2_pkg
// Description :
//   Common definitions and helper functions for a unified SHA-256 / SHA-512 compression core.
//
// Design rule:
//   - The unified datapath is physically 64-bit wide.
//   - SHA-512 uses all 64 bits of each word.
//   - SHA-256 uses only bits [31:0]; bits [63:32] are kept at zero at register boundaries.
//   - SHA-256 arithmetic must still be reduced modulo 2^32.
//============================================================================================================================

package sha2_pkg;

    //========================================================================================================================
    // Operating mode
    //========================================================================================================================
    typedef enum logic {
        SHA2_256 = 1'b0,
        SHA2_512 = 1'b1
    } sha2_mode_t;

    //========================================================================================================================
    // Algorithm dimensions
    //========================================================================================================================
    localparam int unsigned SHA256_WORD_W     = 32;
    localparam int unsigned SHA512_WORD_W     = 64;

    localparam int unsigned SHA256_BLOCK_W    = 512;
    localparam int unsigned SHA512_BLOCK_W    = 1024;

    localparam int unsigned SHA256_DIGEST_W   = 256;
    localparam int unsigned SHA512_DIGEST_W   = 512;

    localparam int unsigned SHA256_ROUNDS     = 64;
    localparam int unsigned SHA512_ROUNDS     = 80;

    // Round counter starts at zero, therefore final indices are 63 and 79.
    localparam logic [6:0] SHA256_LAST_ROUND  = 7'd63;
    localparam logic [6:0] SHA512_LAST_ROUND  = 7'd79;

    // Physical widths used by the unified implementation.
    localparam int unsigned SHA2_MAX_WORD_W   = SHA512_WORD_W;
    localparam int unsigned SHA2_MAX_BLOCK_W  = SHA512_BLOCK_W;
    localparam int unsigned SHA2_MAX_DIGEST_W = SHA512_DIGEST_W;

    //========================================================================================================================
    // Rotate-right primitives
    //========================================================================================================================
    function automatic logic [31:0] rotr32(
        input logic [31:0] x,
        input int unsigned n
    );
        rotr32 = (x >> n) | (x << (32 - n));
    endfunction

    function automatic logic [63:0] rotr64(
        input logic [63:0] x,
        input int unsigned n
    );
        rotr64 = (x >> n) | (x << (64 - n));
    endfunction

    //========================================================================================================================
    // Ch and Maj
    //
    // These Boolean functions are structurally identical in SHA-256 and SHA-512.
    // A single 64-bit implementation is therefore sufficient. In SHA-256 mode the caller supplies zero-extended 32-bit words.
    //========================================================================================================================
    function automatic logic [63:0] sha2_ch(
        input logic [63:0] x,
        input logic [63:0] y,
        input logic [63:0] z
    );
        sha2_ch = (x & y) ^ ((~x) & z);
    endfunction

    function automatic logic [63:0] sha2_maj(
        input logic [63:0] x,
        input logic [63:0] y,
        input logic [63:0] z
    );
        sha2_maj = (x & y) ^ (x & z) ^ (y & z);
    endfunction

    //========================================================================================================================
    // SHA-256 big-sigma functions used by the round function
    //========================================================================================================================
    function automatic logic [31:0] sha256_bsig0(input logic [31:0] x);
        sha256_bsig0 = rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
    endfunction

    function automatic logic [31:0] sha256_bsig1(input logic [31:0] x);
        sha256_bsig1 = rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
    endfunction

    //========================================================================================================================
    // SHA-256 small-sigma functions used by the message schedule
    //========================================================================================================================
    function automatic logic [31:0] sha256_ssig0(input logic [31:0] x);
        sha256_ssig0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
    endfunction

    function automatic logic [31:0] sha256_ssig1(input logic [31:0] x);
        sha256_ssig1 = rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
    endfunction

    //========================================================================================================================
    // SHA-512 big-sigma functions used by the round function
    //========================================================================================================================
    function automatic logic [63:0] sha512_bsig0(input logic [63:0] x);
        sha512_bsig0 = rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
    endfunction

    function automatic logic [63:0] sha512_bsig1(input logic [63:0] x);
        sha512_bsig1 = rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
    endfunction

    //========================================================================================================================
    // SHA-512 small-sigma functions used by the message schedule
    //========================================================================================================================
    function automatic logic [63:0] sha512_ssig0(input logic [63:0] x);
        sha512_ssig0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
    endfunction

    function automatic logic [63:0] sha512_ssig1(input logic [63:0] x);
        sha512_ssig1 = rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
    endfunction

    //========================================================================================================================
    // Utility helpers for the 64-bit physical datapath
    //========================================================================================================================

    // Zero-extend a SHA-256 word into the 64-bit physical datapath.
    function automatic logic [63:0] zext32(input logic [31:0] x);
        zext32 = {32'b0, x};
    endfunction

    // Normalize a datapath value at a register boundary.
    // In SHA-256 mode, the upper 32 bits are discarded so arithmetic remains modulo 2^32.
    function automatic logic [63:0] sha2_norm_word(
        input logic [63:0] x,
        input sha2_mode_t  mode
    );
        case (mode)
            SHA2_256: sha2_norm_word = {32'b0, x[31:0]};
            SHA2_512: sha2_norm_word = x;
            default : sha2_norm_word = 64'b0;
        endcase
    endfunction

endpackage
