//============================================================================================================================
// Package     : sha256_pkg
//
// Description :
//   Common constants and helper functions for SHA-256, HMAC-SHA256 and HKDF-SHA256.
//
// Notes:
//   - This package contains constants only; it does not infer a separate hardware module.
//   - SHA-256 words are handled in big-endian order.
//============================================================================================================================

package sha256_pkg;

    //========================================================================================================================
    // Common widths
    //========================================================================================================================
    parameter int SHA_WORD_W   = 32;
    parameter int SHA_BLOCK_W  = 512;
    parameter int SHA_DIGEST_W = 256;
    parameter int SHA_ROUNDS   = 64;

    //========================================================================================================================
    // SHA-256 initial hash values
    //========================================================================================================================
    localparam logic [31:0] SHA256_H0 = 32'h6a09e667;
    localparam logic [31:0] SHA256_H1 = 32'hbb67ae85;
    localparam logic [31:0] SHA256_H2 = 32'h3c6ef372;
    localparam logic [31:0] SHA256_H3 = 32'ha54ff53a;
    localparam logic [31:0] SHA256_H4 = 32'h510e527f;
    localparam logic [31:0] SHA256_H5 = 32'h9b05688c;
    localparam logic [31:0] SHA256_H6 = 32'h1f83d9ab;
    localparam logic [31:0] SHA256_H7 = 32'h5be0cd19;

    //========================================================================================================================
    // HMAC constants
    //========================================================================================================================
    localparam logic [31:0] HMAC_IPAD_WORD = 32'h36363636;
    localparam logic [31:0] HMAC_OPAD_WORD = 32'h5c5c5c5c;

    //========================================================================================================================
    // SHA-256 round constants
    //========================================================================================================================
    localparam logic [31:0] SHA256_K [0:63] = '{
        32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5,
        32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
        32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3,
        32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
        32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc,
        32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
        32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7,
        32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
        32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13,
        32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
        32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3,
        32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
        32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5,
        32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
        32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208,
        32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
    };

    //========================================================================================================================
    // SHA-256 helper functions
    //========================================================================================================================
    function automatic logic [31:0] rotr32(
        input logic [31:0] x,
        input int unsigned n
    );
        rotr32 = (x >> n) | (x << (32 - n));
    endfunction

    function automatic logic [31:0] sha256_ch(
        input logic [31:0] x,
        input logic [31:0] y,
        input logic [31:0] z
    );
        sha256_ch = (x & y) ^ (~x & z);
    endfunction

    function automatic logic [31:0] sha256_maj(
        input logic [31:0] x,
        input logic [31:0] y,
        input logic [31:0] z
    );
        sha256_maj = (x & y) ^ (x & z) ^ (y & z);
    endfunction

    function automatic logic [31:0] sha256_bsig0(input logic [31:0] x);
        sha256_bsig0 = rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
    endfunction

    function automatic logic [31:0] sha256_bsig1(input logic [31:0] x);
        sha256_bsig1 = rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
    endfunction

    function automatic logic [31:0] sha256_ssig0(input logic [31:0] x);
        sha256_ssig0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
    endfunction

    function automatic logic [31:0] sha256_ssig1(input logic [31:0] x);
        sha256_ssig1 = rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
    endfunction

endpackage
