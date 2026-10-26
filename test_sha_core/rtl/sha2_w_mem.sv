//============================================================================================================================
// Module      : sha2_w_mem
// Description :
//   Unified SHA-256 / SHA-512 message-schedule memory.
//
// Architecture:
//   - One physical sliding window: 16 x 64-bit words.
//   - SHA-512 mode:
//       * Load 16 x 64-bit words from the full 1024-bit block.
//       * Use SHA-512 small-sigma functions.
//       * Arithmetic naturally wraps modulo 2^64.
//   - SHA-256 mode:
//       * Load 16 x 32-bit words from block_i[1023:512].
//       * Store each word zero-extended in bits [31:0] of the 64-bit window.
//       * Use SHA-256 small-sigma functions.
//       * New schedule words are explicitly truncated to 32 bits, giving modulo 2^32.
//
// This file is derived from the Secworks sha512_w_mem implementation.
//
// Original work:
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

module sha2_w_mem (
    //========================================================================================================================
    // Clock / reset
    //========================================================================================================================
    input  wire                         clk_i,
    input  wire                         rst_ni,

    //========================================================================================================================
    // Algorithm mode
    //
    // IMPORTANT:
    //   mode_i must remain stable while a message block is being processed.
    //   In the final sha2_core, mode_i should come from a latched mode_q.
    //========================================================================================================================
    input  wire sha2_pkg::sha2_mode_t   mode_i,

    //========================================================================================================================
    // Message block
    //
    // SHA-512 : block_i[1023:0]   = 1024-bit block.
    // SHA-256 : block_i[1023:512] =  512-bit block, block_i[511:0] unused.
    //========================================================================================================================
    input  wire [1023:0]                block_i,

    //========================================================================================================================
    // Schedule control
    //
    // init_i:
    //   Load W[0]..W[15] from block_i and reset the W counter to round 0.
    //
    // next_i:
    //   Advance the W counter by one round.
    //   For rounds >= 16, shift the 16-word window and insert the newly
    //   generated schedule word into W[15].
    //
    // init_i and next_i are expected to be mutually exclusive.
    //========================================================================================================================
    input  wire                         init_i,
    input  wire                         next_i,

    //========================================================================================================================
    // Current schedule word
    //
    // Unified physical width is always 64 bits.
    // In SHA-256 mode: w_o[63:32] = 0, w_o[31:0] = W[t].
    //========================================================================================================================
    output wire [63:0]                  w_o
);

    import sha2_pkg::*;

    //========================================================================================================================
    // 16-word sliding window
    //========================================================================================================================
    logic [63:0] w_mem_q [0:15];
    logic [63:0] w_mem_d [0:15];

    //========================================================================================================================
    // Schedule counter
    //
    // 7 bits are sufficient for both:
    //   SHA-256 rounds 0..63
    //   SHA-512 rounds 0..79
    //
    // This module does NOT decide when hashing stops. sha2_core controls
    // how many next_i pulses are issued according to mode_q.
    //========================================================================================================================
    logic [6:0] w_ctr_q;
    logic [6:0] w_ctr_d;

    //========================================================================================================================
    // Current/new W values
    //========================================================================================================================
    logic [63:0] w_selected;
    logic [63:0] w_new;

    logic [31:0] d0_32;
    logic [31:0] d1_32;
    logic [31:0] w_new_32;

    logic [63:0] d0_64;
    logic [63:0] d1_64;

    //========================================================================================================================
    // Output connection
    //========================================================================================================================
    assign w_o = w_selected;


    //========================================================================================================================
    // Current W[t] selection
    //
    // For rounds 0..15:
    //   W[t] is one of the 16 words initially loaded from the message block.
    //
    // For rounds >= 16:
    //   W[t] is the combinationally generated w_new value.
    //========================================================================================================================
    always_comb begin
        if (w_ctr_q < 7'd16)
            w_selected = w_mem_q[w_ctr_q[3:0]];
        else
            w_selected = w_new;
    end


    //========================================================================================================================
    // Mode-dependent message-schedule expansion
    //
    // Both SHA-256 and SHA-512 use the same recurrence:
    //
    //   W[t] = W[t-16] + sigma0(W[t-15]) + W[t-7] + sigma1(W[t-2])
    //
    // With the 16-word sliding window:
    //
    //   w_mem_q[0]  = W[t-16]
    //   w_mem_q[1]  = W[t-15]
    //   w_mem_q[9]  = W[t-7]
    //   w_mem_q[14] = W[t-2]
    //
    // Only the small-sigma functions and arithmetic word width differ.
    //========================================================================================================================
    always_comb begin
        d0_32    = 32'b0;
        d1_32    = 32'b0;
        w_new_32 = 32'b0;

        d0_64    = 64'b0;
        d1_64    = 64'b0;

        w_new    = 64'b0;

        case (mode_i)

            //--------------------------------------------------------------------------------------------------------------
            // SHA-256 schedule
            //
            // sigma0(x) = ROTR^7(x)  XOR ROTR^18(x) XOR SHR^3(x)
            // sigma1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
            //
            // All arithmetic is modulo 2^32.
            // Assignment to w_new_32 explicitly discards any carry above bit 31.
            //--------------------------------------------------------------------------------------------------------------
            SHA2_256: begin
                d0_32 = sha256_ssig0(w_mem_q[1][31:0]);
                d1_32 = sha256_ssig1(w_mem_q[14][31:0]);
                w_new_32 = w_mem_q[0][31:0] + d0_32 + w_mem_q[9][31:0] + d1_32;
                w_new = {32'b0, w_new_32};
            end

            //--------------------------------------------------------------------------------------------------------------
            // SHA-512 schedule
            //
            // sigma0(x) = ROTR^1(x)  XOR ROTR^8(x)  XOR SHR^7(x)
            // sigma1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
            //
            // All arithmetic is modulo 2^64.
            // The 64-bit destination naturally discards carry above bit 63.
            //--------------------------------------------------------------------------------------------------------------
            SHA2_512: begin
                d0_64 = sha512_ssig0(w_mem_q[1]);
                d1_64 = sha512_ssig1(w_mem_q[14]);
                w_new = w_mem_q[0] + d0_64 + w_mem_q[9] + d1_64;
            end

            default: begin
                // Keep w_new at zero for an invalid/X mode.
            end

        endcase
    end


    //========================================================================================================================
    // Sliding-window next-state logic
    //========================================================================================================================
    always_comb begin : w_mem_next_logic
        integer i;

        // Default: hold all 16 registers.
        for (i = 0; i < 16; i = i + 1)
            w_mem_d[i] = w_mem_q[i];

        //--------------------------------------------------------------------------------------------------------------
        // Load a new message block.
        //--------------------------------------------------------------------------------------------------------------
        if (init_i) begin

            case (mode_i)

                //----------------------------------------------------------------------------------------------------------
                // SHA-256
                //
                // One SHA-256 block = 512 bits = 16 x 32-bit words.
                //
                // Unified block convention:
                //   SHA-256 block occupies block_i[1023:512].
                //
                // Each 32-bit word is stored in the LOW half of a 64-bit slot:
                //
                //   w_mem_d[n][63:32] = 0
                //   w_mem_d[n][31:0]  = W[n]
                //
                // Input is interpreted in big-endian word order:
                //   W0  = block_i[1023:992]
                //   W1  = block_i[991:960]
                //   ...
                //   W15 = block_i[543:512]
                //----------------------------------------------------------------------------------------------------------
                SHA2_256: begin
                    for (i = 0; i < 16; i = i + 1)
                        w_mem_d[i] = {32'b0, block_i[1023 - (i * 32) -: 32]};
                end

                //----------------------------------------------------------------------------------------------------------
                // SHA-512
                //
                // One SHA-512 block = 1024 bits = 16 x 64-bit words.
                //
                // This preserves the original Secworks word mapping:
                //   W0  = block_i[1023:960]
                //   W1  = block_i[959:896]
                //   ...
                //   W15 = block_i[63:0]
                //----------------------------------------------------------------------------------------------------------
                SHA2_512: begin
                    for (i = 0; i < 16; i = i + 1)
                        w_mem_d[i] = block_i[1023 - (i * 64) -: 64];
                end

                default: begin
                    for (i = 0; i < 16; i = i + 1)
                        w_mem_d[i] = 64'b0;
                end

            endcase
        end

        //--------------------------------------------------------------------------------------------------------------
        // Expand W[t] for t >= 16.
        //
        // Example before the shift:
        //   index 0  = W[t-16]
        //   index 1  = W[t-15]
        //   ...
        //   index 15 = W[t-1]
        //
        // After the shift:
        //   index 0  <- old index 1
        //   ...
        //   index 14 <- old index 15
        //   index 15 <- W[t]
        //
        // For SHA-256, w_new is already zero-extended to 64 bits.
        //--------------------------------------------------------------------------------------------------------------
        else if (next_i && (w_ctr_q > 7'd15)) begin
            for (i = 0; i < 15; i = i + 1)
                w_mem_d[i] = w_mem_q[i + 1];

            w_mem_d[15] = w_new;
        end
    end


    //========================================================================================================================
    // Schedule-counter next-state logic
    //========================================================================================================================
    always_comb begin
        w_ctr_d = w_ctr_q;

        if (init_i)
            w_ctr_d = 7'd0;
        else if (next_i)
            w_ctr_d = w_ctr_q + 7'd1;
    end


    //========================================================================================================================
    // Registers
    //========================================================================================================================
    always_ff @(posedge clk_i or negedge rst_ni) begin : reg_update
        integer i;

        if (!rst_ni) begin
            for (i = 0; i < 16; i = i + 1)
                w_mem_q[i] <= 64'b0;

            w_ctr_q <= 7'd0;
        end
        else begin
            for (i = 0; i < 16; i = i + 1)
                w_mem_q[i] <= w_mem_d[i];

            w_ctr_q <= w_ctr_d;
        end
    end

endmodule

`default_nettype wire
