`timescale 1ns/1ps
`default_nettype none

module tb_sha2_core_multitest;

    import sha2_pkg::*;

    //========================================================================================================================
    // Clock / reset
    //========================================================================================================================
    localparam time CLK_PERIOD = 10ns;

    logic clk;
    logic rst_n;

    always #(CLK_PERIOD/2) clk = ~clk;


    //========================================================================================================================
    // Standard single-block "abc" test vectors.
    // Padding is already included here. This testbench verifies only the
    // compression/block core; it does NOT test a padding engine.
    //========================================================================================================================

    // SHA-256("abc") padded to one 512-bit block:
    //   61 62 63 80 || zeros || 64-bit length = 24 = 0x18
    localparam logic [511:0] SHA256_ABC_BLOCK =
        512'h61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

    localparam logic [255:0] SHA256_ABC_EXPECTED =
        256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;

    // SHA-512("abc") padded to one 1024-bit block:
    //   61 62 63 80 || zeros || 128-bit length = 24 = 0x18
    localparam logic [1023:0] SHA512_ABC_BLOCK =
        1024'h6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

    localparam logic [511:0] SHA512_ABC_EXPECTED =
        512'hddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f;


    //========================================================================================================================
    // Standard multi-block known-answer vectors.
    // These blocks are already padded; no hardware padding is tested here.
    //========================================================================================================================

    // SHA-256 message:
    // "abcdbcdecdefdefgefghfghighijhijk"
    // "ijkljklmklmnlmnomnopnopq"
    // 56 bytes = 448 bits = 0x1c0 -> TWO padded 512-bit blocks.
    localparam logic [511:0] SHA256_MB_BLOCK0 =
        512'h6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000;

    localparam logic [511:0] SHA256_MB_BLOCK1 =
        512'h000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0;

    localparam logic [255:0] SHA256_MB_EXPECTED =
        256'h248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1;

    // SHA-512 message:
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    // "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    // 112 bytes = 896 bits = 0x380 -> TWO padded 1024-bit blocks.
    localparam logic [1023:0] SHA512_MB_BLOCK0 =
        1024'h61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f70717273747580000000000000000000000000000000;

    localparam logic [1023:0] SHA512_MB_BLOCK1 =
        1024'h0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000380;

    localparam logic [511:0] SHA512_MB_EXPECTED =
        512'h8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909;


    //========================================================================================================================
    // Unified SHA-2 DUT signals
    //========================================================================================================================
    sha2_mode_t   dut_mode;
    logic         dut_init;
    logic         dut_next;
    logic [1023:0] dut_block;

    wire          dut_ready;
    wire          dut_busy;
    wire [511:0]  dut_digest;
    wire          dut_digest_valid;


    //========================================================================================================================
    // SHA-256 golden reference signals
    //========================================================================================================================
    logic         ref256_init;
    logic         ref256_next;
    logic [511:0] ref256_block;

    wire          ref256_ready;
    wire          ref256_busy;
    wire [255:0]  ref256_digest;
    wire          ref256_digest_valid;


    //========================================================================================================================
    // SHA-512 golden reference signals
    //========================================================================================================================
    logic          ref512_init;
    logic          ref512_next;
    logic [1023:0] ref512_block;

    wire           ref512_ready;
    wire [511:0]   ref512_digest;
    wire           ref512_digest_valid;


    //========================================================================================================================
    // Captured results
    //========================================================================================================================
    logic [511:0] dut_digest_saved;
    logic [255:0] ref256_digest_saved;
    logic [511:0] ref512_digest_saved;

    integer error_count;


    //========================================================================================================================
    // DUT: Unified SHA-256 / SHA-512 core
    //========================================================================================================================
    sha2_core u_dut (
        .clk_i          (clk),
        .rst_ni         (rst_n),

        .mode_i         (dut_mode),
        .init_i         (dut_init),
        .next_i         (dut_next),
        .block_i        (dut_block),

        .ready_o        (dut_ready),
        .busy_o         (dut_busy),
        .digest_o       (dut_digest),
        .digest_valid_o (dut_digest_valid)
    );


    //========================================================================================================================
    // Golden SHA-256 reference
    //========================================================================================================================
    sha256_core_ref u_sha256_ref (
        .clk_i          (clk),
        .rst_ni         (rst_n),

        .init_i         (ref256_init),
        .next_i         (ref256_next),
        .block_i        (ref256_block),

        .ready_o        (ref256_ready),
        .digest_o       (ref256_digest),
        .digest_valid_o (ref256_digest_valid),
        .busy_o         (ref256_busy)
    );


    //========================================================================================================================
    // Golden SHA-512 Secworks reference
    //========================================================================================================================
    sha512_core_ref u_sha512_ref (
        .clk             (clk),
        .reset_n         (rst_n),

        .init            (ref512_init),
        .next            (ref512_next),
        .mode            (2'b11),       // Secworks mode 3 = SHA-512

        .work_factor     (1'b0),
        .work_factor_num (32'd0),

        .block           (ref512_block),

        .ready           (ref512_ready),
        .digest          (ref512_digest),
        .digest_valid    (ref512_digest_valid)
    );


    //========================================================================================================================
    // Reset task
    //========================================================================================================================
    task automatic apply_reset;
        begin
            rst_n       = 1'b0;

            dut_mode    = SHA2_256;
            dut_init    = 1'b0;
            dut_next    = 1'b0;
            dut_block   = '0;

            ref256_init  = 1'b0;
            ref256_next  = 1'b0;
            ref256_block = '0;

            ref512_init  = 1'b0;
            ref512_next  = 1'b0;
            ref512_block = '0;

            repeat (4) @(posedge clk);
            @(negedge clk);
            rst_n = 1'b1;

            // Give all three cores a cycle to settle in IDLE.
            repeat (2) @(posedge clk);
        end
    endtask


    //========================================================================================================================
    // SHA-256("abc") single-block differential test
    //========================================================================================================================
    task automatic test_sha256_abc;
        begin
            $display("\n============================================================");
            $display("TEST 1: SHA-256 single block: \"abc\"");
            $display("============================================================");

            wait (dut_ready === 1'b1);
            wait (ref256_ready === 1'b1);

            // Unified SHA-256 convention:
            //   block_i[1023:512] = 512-bit SHA-256 block
            //   block_i[511:0]    = unused/zero
            @(negedge clk);
            dut_mode     = SHA2_256;
            dut_block    = {SHA256_ABC_BLOCK, 512'b0};
            ref256_block = SHA256_ABC_BLOCK;

            dut_init     = 1'b1;
            ref256_init  = 1'b1;

            // One-cycle command pulse.
            @(negedge clk);
            dut_init     = 1'b0;
            ref256_init  = 1'b0;

            // Capture results independently. The golden and DUT are NOT
            // required to assert digest_valid on the same clock cycle.
            fork
                begin : wait_dut256
                    // The DUT clears its sticky digest_valid when init is accepted.
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_digest_saved = dut_digest;
                end

                begin : wait_ref256
                    wait (ref256_digest_valid === 1'b1);
                    #1;
                    ref256_digest_saved = ref256_digest;
                end
            join

            $display("Golden SHA-256 : %064h", ref256_digest_saved);
            $display("Unified DUT    : %064h", dut_digest_saved[255:0]);
            $display("Expected       : %064h", SHA256_ABC_EXPECTED);

            // First compare DUT against the frozen reference implementation.
            if (dut_digest_saved[255:0] !== ref256_digest_saved) begin
                $error("SHA-256 DUT != golden reference");
                error_count = error_count + 1;
            end

            // Also validate both against the standard known-answer vector.
            if (ref256_digest_saved !== SHA256_ABC_EXPECTED) begin
                $error("SHA-256 golden reference != standard expected digest");
                error_count = error_count + 1;
            end

            if (dut_digest_saved[255:0] !== SHA256_ABC_EXPECTED) begin
                $error("SHA-256 DUT != standard expected digest");
                error_count = error_count + 1;
            end

            // Unified SHA-256 formatting rule requires the upper half to be zero.
            if (dut_digest_saved[511:256] !== 256'b0) begin
                $error("SHA-256 DUT digest_o[511:256] is not zero: %064h",
                       dut_digest_saved[511:256]);
                error_count = error_count + 1;
            end

            if ((dut_digest_saved[255:0] === ref256_digest_saved) &&
                (dut_digest_saved[255:0] === SHA256_ABC_EXPECTED) &&
                (dut_digest_saved[511:256] === 256'b0)) begin
                $display("RESULT         : PASS");
            end
            else begin
                $display("RESULT         : FAIL");
            end

            // Keep a clean gap before switching the single DUT to SHA-512.
            repeat (3) @(posedge clk);
        end
    endtask


    //========================================================================================================================
    // SHA-512("abc") single-block differential test
    //========================================================================================================================
    task automatic test_sha512_abc;
        begin
            $display("\n============================================================");
            $display("TEST 2: SHA-512 single block: \"abc\"");
            $display("============================================================");

            wait (dut_ready === 1'b1);
            wait (ref512_ready === 1'b1);

            @(negedge clk);
            dut_mode     = SHA2_512;
            dut_block    = SHA512_ABC_BLOCK;
            ref512_block = SHA512_ABC_BLOCK;

            dut_init     = 1'b1;
            ref512_init  = 1'b1;

            // One-cycle command pulse.
            @(negedge clk);
            dut_init     = 1'b0;
            ref512_init  = 1'b0;

            fork
                begin : wait_dut512
                    // Previous SHA-256 test left DUT digest_valid high in IDLE.
                    // Starting this new init clears it; wait for that low level
                    // before accepting the next rising result indication.
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_digest_saved = dut_digest;
                end

                begin : wait_ref512
                    wait (ref512_digest_valid === 1'b1);
                    #1;
                    ref512_digest_saved = ref512_digest;
                end
            join

            $display("Golden SHA-512 : %0128h", ref512_digest_saved);
            $display("Unified DUT    : %0128h", dut_digest_saved);
            $display("Expected       : %0128h", SHA512_ABC_EXPECTED);

            if (dut_digest_saved !== ref512_digest_saved) begin
                $error("SHA-512 DUT != golden reference");
                error_count = error_count + 1;
            end

            if (ref512_digest_saved !== SHA512_ABC_EXPECTED) begin
                $error("SHA-512 golden reference != standard expected digest");
                error_count = error_count + 1;
            end

            if (dut_digest_saved !== SHA512_ABC_EXPECTED) begin
                $error("SHA-512 DUT != standard expected digest");
                error_count = error_count + 1;
            end

            if ((dut_digest_saved === ref512_digest_saved) &&
                (dut_digest_saved === SHA512_ABC_EXPECTED)) begin
                $display("RESULT         : PASS");
            end
            else begin
                $display("RESULT         : FAIL");
            end

            repeat (3) @(posedge clk);
        end
    endtask



    //========================================================================================================================
    // SHA-256 multi-block differential/chaining test
    //========================================================================================================================
    task automatic test_sha256_multiblock;
        logic [255:0] dut_chain0;
        logic [255:0] ref_chain0;
        logic [511:0] dut_final;
        logic [255:0] ref_final;
        begin
            $display("\n============================================================");
            $display("TEST 3: SHA-256 multi-block chaining");
            $display("============================================================");

            // BLOCK 0: init_i = 1, next_i = 0
            wait (dut_ready === 1'b1);
            wait (ref256_ready === 1'b1);

            @(negedge clk);
            dut_mode     = SHA2_256;
            dut_block    = {SHA256_MB_BLOCK0, 512'b0};
            ref256_block = SHA256_MB_BLOCK0;
            dut_init     = 1'b1;
            dut_next     = 1'b0;
            ref256_init  = 1'b1;
            ref256_next  = 1'b0;

            @(negedge clk);
            dut_init    = 1'b0;
            ref256_init = 1'b0;

            fork
                begin : wait_dut256_mb_b0
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_chain0 = dut_digest[255:0];
                end
                begin : wait_ref256_mb_b0
                    wait (ref256_digest_valid === 1'b1);
                    #1;
                    ref_chain0 = ref256_digest;
                end
            join

            $display("Block 0 DUT chaining    : %064h", dut_chain0);
            $display("Block 0 Golden chaining : %064h", ref_chain0);

            if (dut_chain0 !== ref_chain0) begin
                $error("SHA-256 block-0 chaining mismatch: DUT != golden");
                error_count = error_count + 1;
            end

            if ({u_dut.H0_q[31:0], u_dut.H1_q[31:0],
                 u_dut.H2_q[31:0], u_dut.H3_q[31:0],
                 u_dut.H4_q[31:0], u_dut.H5_q[31:0],
                 u_dut.H6_q[31:0], u_dut.H7_q[31:0]} !== dut_chain0) begin
                $error("SHA-256 DUT internal H0_q..H7_q != block-0 chaining digest");
                error_count = error_count + 1;
            end

            if ((u_dut.H0_q[63:32] !== 32'b0) ||
                (u_dut.H1_q[63:32] !== 32'b0) ||
                (u_dut.H2_q[63:32] !== 32'b0) ||
                (u_dut.H3_q[63:32] !== 32'b0) ||
                (u_dut.H4_q[63:32] !== 32'b0) ||
                (u_dut.H5_q[63:32] !== 32'b0) ||
                (u_dut.H6_q[63:32] !== 32'b0) ||
                (u_dut.H7_q[63:32] !== 32'b0)) begin
                $error("SHA-256 DUT chaining registers are not zero-extended");
                error_count = error_count + 1;
            end

            // BLOCK 1: init_i = 0, next_i = 1
            wait (dut_ready === 1'b1);
            wait (ref256_ready === 1'b1);

            @(negedge clk);
            dut_block    = {SHA256_MB_BLOCK1, 512'b0};
            ref256_block = SHA256_MB_BLOCK1;
            dut_init     = 1'b0;
            dut_next     = 1'b1;
            ref256_init  = 1'b0;
            ref256_next  = 1'b1;

            // next_i is accepted at this edge. After NBA updates settle,
            // a..h must equal the previous block's H0..H7 chaining state.
            @(posedge clk);
            #1;

            if ((u_dut.a_q !== u_dut.H0_q) ||
                (u_dut.b_q !== u_dut.H1_q) ||
                (u_dut.c_q !== u_dut.H2_q) ||
                (u_dut.d_q !== u_dut.H3_q) ||
                (u_dut.e_q !== u_dut.H4_q) ||
                (u_dut.f_q !== u_dut.H5_q) ||
                (u_dut.g_q !== u_dut.H6_q) ||
                (u_dut.h_q !== u_dut.H7_q)) begin
                $error("SHA-256 DUT next_i did not initialize a..h from H0..H7");
                error_count = error_count + 1;
            end

            if ((u_sha256_ref.a_q !== u_sha256_ref.h0_q) ||
                (u_sha256_ref.b_q !== u_sha256_ref.h1_q) ||
                (u_sha256_ref.c_q !== u_sha256_ref.h2_q) ||
                (u_sha256_ref.d_q !== u_sha256_ref.h3_q) ||
                (u_sha256_ref.e_q !== u_sha256_ref.h4_q) ||
                (u_sha256_ref.f_q !== u_sha256_ref.h5_q) ||
                (u_sha256_ref.g_q !== u_sha256_ref.h6_q) ||
                (u_sha256_ref.h_q !== u_sha256_ref.h7_q)) begin
                $error("SHA-256 golden next_i did not initialize a..h from h0..h7");
                error_count = error_count + 1;
            end

            $display("next_i check: a..h loaded from previous H0..H7 : PASS");

            @(negedge clk);
            dut_next    = 1'b0;
            ref256_next = 1'b0;

            fork
                begin : wait_dut256_mb_b1
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_final = dut_digest;
                end
                begin : wait_ref256_mb_b1
                    wait (ref256_digest_valid === 1'b1);
                    #1;
                    ref_final = ref256_digest;
                end
            join

            $display("Golden SHA-256 final : %064h", ref_final);
            $display("Unified DUT final    : %064h", dut_final[255:0]);
            $display("Expected             : %064h", SHA256_MB_EXPECTED);

            if (dut_final[255:0] !== ref_final) begin
                $error("SHA-256 multi-block DUT != golden reference");
                error_count = error_count + 1;
            end
            if (ref_final !== SHA256_MB_EXPECTED) begin
                $error("SHA-256 multi-block golden != standard expected digest");
                error_count = error_count + 1;
            end
            if (dut_final[255:0] !== SHA256_MB_EXPECTED) begin
                $error("SHA-256 multi-block DUT != standard expected digest");
                error_count = error_count + 1;
            end
            if (dut_final[511:256] !== 256'b0) begin
                $error("SHA-256 multi-block DUT upper digest bits are not zero");
                error_count = error_count + 1;
            end

            if ((dut_final[255:0] === ref_final) &&
                (dut_final[255:0] === SHA256_MB_EXPECTED) &&
                (dut_final[511:256] === 256'b0))
                $display("RESULT               : PASS");
            else
                $display("RESULT               : FAIL");

            repeat (3) @(posedge clk);
        end
    endtask


    //========================================================================================================================
    // SHA-512 multi-block differential/chaining test
    //========================================================================================================================
    task automatic test_sha512_multiblock;
        logic [511:0] dut_chain0;
        logic [511:0] ref_chain0;
        logic [511:0] dut_final;
        logic [511:0] ref_final;
        begin
            $display("\n============================================================");
            $display("TEST 4: SHA-512 multi-block chaining");
            $display("============================================================");

            // BLOCK 0: init_i = 1, next_i = 0
            wait (dut_ready === 1'b1);
            wait (ref512_ready === 1'b1);

            @(negedge clk);
            dut_mode     = SHA2_512;
            dut_block    = SHA512_MB_BLOCK0;
            ref512_block = SHA512_MB_BLOCK0;
            dut_init     = 1'b1;
            dut_next     = 1'b0;
            ref512_init  = 1'b1;
            ref512_next  = 1'b0;

            @(negedge clk);
            dut_init    = 1'b0;
            ref512_init = 1'b0;

            fork
                begin : wait_dut512_mb_b0
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_chain0 = dut_digest;
                end
                begin : wait_ref512_mb_b0
                    wait (ref512_digest_valid === 1'b0);
                    wait (ref512_digest_valid === 1'b1);
                    #1;
                    ref_chain0 = ref512_digest;
                end
            join

            $display("Block 0 DUT chaining    : %0128h", dut_chain0);
            $display("Block 0 Golden chaining : %0128h", ref_chain0);

            if (dut_chain0 !== ref_chain0) begin
                $error("SHA-512 block-0 chaining mismatch: DUT != golden");
                error_count = error_count + 1;
            end

            if ({u_dut.H0_q, u_dut.H1_q, u_dut.H2_q, u_dut.H3_q,
                 u_dut.H4_q, u_dut.H5_q, u_dut.H6_q, u_dut.H7_q} !== dut_chain0) begin
                $error("SHA-512 DUT internal H0_q..H7_q != block-0 chaining digest");
                error_count = error_count + 1;
            end

            // BLOCK 1: init_i = 0, next_i = 1
            wait (dut_ready === 1'b1);
            wait (ref512_ready === 1'b1);

            @(negedge clk);
            dut_block    = SHA512_MB_BLOCK1;
            ref512_block = SHA512_MB_BLOCK1;
            dut_init     = 1'b0;
            dut_next     = 1'b1;
            ref512_init  = 1'b0;
            ref512_next  = 1'b1;

            @(posedge clk);
            #1;

            if ((u_dut.a_q !== u_dut.H0_q) ||
                (u_dut.b_q !== u_dut.H1_q) ||
                (u_dut.c_q !== u_dut.H2_q) ||
                (u_dut.d_q !== u_dut.H3_q) ||
                (u_dut.e_q !== u_dut.H4_q) ||
                (u_dut.f_q !== u_dut.H5_q) ||
                (u_dut.g_q !== u_dut.H6_q) ||
                (u_dut.h_q !== u_dut.H7_q)) begin
                $error("SHA-512 DUT next_i did not initialize a..h from H0..H7");
                error_count = error_count + 1;
            end

            if ((u_sha512_ref.a_reg !== u_sha512_ref.H0_reg) ||
                (u_sha512_ref.b_reg !== u_sha512_ref.H1_reg) ||
                (u_sha512_ref.c_reg !== u_sha512_ref.H2_reg) ||
                (u_sha512_ref.d_reg !== u_sha512_ref.H3_reg) ||
                (u_sha512_ref.e_reg !== u_sha512_ref.H4_reg) ||
                (u_sha512_ref.f_reg !== u_sha512_ref.H5_reg) ||
                (u_sha512_ref.g_reg !== u_sha512_ref.H6_reg) ||
                (u_sha512_ref.h_reg !== u_sha512_ref.H7_reg)) begin
                $error("SHA-512 golden next_i did not initialize a..h from H0..H7");
                error_count = error_count + 1;
            end

            $display("next_i check: a..h loaded from previous H0..H7 : PASS");

            @(negedge clk);
            dut_next    = 1'b0;
            ref512_next = 1'b0;

            fork
                begin : wait_dut512_mb_b1
                    wait (dut_digest_valid === 1'b0);
                    wait (dut_digest_valid === 1'b1);
                    #1;
                    dut_final = dut_digest;
                end
                begin : wait_ref512_mb_b1
                    wait (ref512_digest_valid === 1'b0);
                    wait (ref512_digest_valid === 1'b1);
                    #1;
                    ref_final = ref512_digest;
                end
            join

            $display("Golden SHA-512 final : %0128h", ref_final);
            $display("Unified DUT final    : %0128h", dut_final);
            $display("Expected             : %0128h", SHA512_MB_EXPECTED);

            if (dut_final !== ref_final) begin
                $error("SHA-512 multi-block DUT != golden reference");
                error_count = error_count + 1;
            end
            if (ref_final !== SHA512_MB_EXPECTED) begin
                $error("SHA-512 multi-block golden != standard expected digest");
                error_count = error_count + 1;
            end
            if (dut_final !== SHA512_MB_EXPECTED) begin
                $error("SHA-512 multi-block DUT != standard expected digest");
                error_count = error_count + 1;
            end

            if ((dut_final === ref_final) &&
                (dut_final === SHA512_MB_EXPECTED))
                $display("RESULT               : PASS");
            else
                $display("RESULT               : FAIL");

            repeat (3) @(posedge clk);
        end
    endtask


    //========================================================================================================================
    // Main test sequence
    //========================================================================================================================
    initial begin
        clk                 = 1'b0;
        error_count         = 0;
        dut_digest_saved    = '0;
        ref256_digest_saved = '0;
        ref512_digest_saved = '0;

        apply_reset();

        test_sha256_abc();
        test_sha512_abc();
        test_sha256_multiblock();
        test_sha512_multiblock();

        $display("\n============================================================");
        if (error_count == 0) begin
            $display("ALL SINGLE-BLOCK AND MULTI-BLOCK SHA-2 TESTS PASSED");
        end
        else begin
            $display("TESTS FAILED: %0d error(s)", error_count);
        end
        $display("============================================================\n");

        if (error_count != 0)
            $fatal(1, "tb_sha2_core failed");

        $finish;
    end


    //========================================================================================================================
    // Global timeout: prevents an RTL bug from hanging simulation forever.
    //========================================================================================================================
    initial begin
        #12000ns;
        $fatal(1, "TIMEOUT: tb_sha2_core did not finish within 12000 ns");
    end

endmodule

`default_nettype wire
