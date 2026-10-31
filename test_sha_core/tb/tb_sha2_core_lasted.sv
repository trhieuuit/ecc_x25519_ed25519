`timescale 1ns/1ps
`default_nettype none

// ============================================================================
// Comprehensive self-checking regression testbench for unified SHA-2 core.
//
// DUT scope:
//   * Compression/block core only.
//   * SHA-256 uses block_i[1023:512]; block_i[511:0] must be ignored.
//   * SHA-512 uses block_i[1023:0].
//   * init_i starts a NEW message from the selected IV.
//   * next_i continues the current message from the current chaining state.
//   * mode_i is sampled only when init_i is accepted.
//   * init_i has priority if init_i and next_i are high together.
//   * commands are accepted only while ready_o == 1.
//
// Verification strategy:
//   1. Standard known-answer tests (independent expected digests).
//   2. Differential checking against independent SHA-256/SHA-512 golden cores.
//   3. Deterministic corner-pattern blocks.
//   4. Large pseudo-random single-block regression.
//   5. Large pseudo-random multi-block/chaining regression.
//   6. Interface/control tests: mode latch, init priority, command while busy,
//      sticky digest_valid, reset during compression, and mode switching.
//   7. Internal SHA-256 32-bit zero-extension invariant.
//
// IMPORTANT:
//   This testbench does NOT test message padding. Padding is tested in the
//   sha2 frontend/streaming testbench.
// ============================================================================

module tb_sha2_core;

    import sha2_pkg::*;

    // ------------------------------------------------------------------------
    // Configuration.
    // Increase these values for a longer regression.
    // ------------------------------------------------------------------------
    localparam time CLK_PERIOD = 10ns;

    localparam integer MAX_WAIT_CYCLES       = 500;
    localparam integer RANDOM_SINGLE_PER_MODE = 100;
    localparam integer RANDOM_MULTI_PER_MODE  = 50;
    localparam integer RANDOM_MULTI_MAX_BLOCKS = 8;

    // Deterministic pseudo-random seed.
    // Change this value to create a different randomized regression.
    localparam logic [31:0] DEFAULT_RANDOM_SEED = 32'h6A09_E667;

    // Expected core latency measured AFTER the command-accepting edge:
    // 64 rounds + DONE = 65 clocks for SHA-256.
    // 80 rounds + DONE = 81 clocks for SHA-512.
    localparam integer SHA256_EXPECTED_LATENCY = 65;
    localparam integer SHA512_EXPECTED_LATENCY = 81;

    logic clk;
    logic rst_n;

    always #(CLK_PERIOD/2) clk = ~clk;

    // ------------------------------------------------------------------------
    // Standard KAT blocks: padding already included.
    // ------------------------------------------------------------------------
    localparam logic [511:0] SHA256_EMPTY_BLOCK =
        512'h80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;

    localparam logic [255:0] SHA256_EMPTY_EXPECTED =
        256'he3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

    localparam logic [511:0] SHA256_ABC_BLOCK =
        512'h61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

    localparam logic [255:0] SHA256_ABC_EXPECTED =
        256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;

    localparam logic [1023:0] SHA512_EMPTY_BLOCK =
        1024'h8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;

    localparam logic [511:0] SHA512_EMPTY_EXPECTED =
        512'hcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e;

    localparam logic [1023:0] SHA512_ABC_BLOCK =
        1024'h6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

    localparam logic [511:0] SHA512_ABC_EXPECTED =
        512'hddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f;

    // SHA-256 56-byte standard message, already padded into two blocks.
    localparam logic [511:0] SHA256_MB_BLOCK0 =
        512'h6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000;

    localparam logic [511:0] SHA256_MB_BLOCK1 =
        512'h000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0;

    localparam logic [255:0] SHA256_MB_EXPECTED =
        256'h248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1;

    // SHA-512 112-byte standard message, already padded into two blocks.
    localparam logic [1023:0] SHA512_MB_BLOCK0 =
        1024'h61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f70717273747580000000000000000000000000000000;

    localparam logic [1023:0] SHA512_MB_BLOCK1 =
        1024'h0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000380;

    localparam logic [511:0] SHA512_MB_EXPECTED =
        512'h8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909;

    // ------------------------------------------------------------------------
    // DUT interface.
    // ------------------------------------------------------------------------
    sha2_mode_t    dut_mode;
    logic          dut_init;
    logic          dut_next;
    logic [1023:0] dut_block;

    wire           dut_ready;
    wire           dut_busy;
    wire [511:0]   dut_digest;
    wire           dut_digest_valid;

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

    // ------------------------------------------------------------------------
    // Independent SHA-256 golden reference.
    // ------------------------------------------------------------------------
    logic         ref256_init;
    logic         ref256_next;
    logic [511:0] ref256_block;

    wire          ref256_ready;
    wire          ref256_busy;
    wire [255:0]  ref256_digest;
    wire          ref256_digest_valid;

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

    // ------------------------------------------------------------------------
    // Independent Secworks SHA-512 golden reference.
    // ------------------------------------------------------------------------
    logic          ref512_init;
    logic          ref512_next;
    logic [1023:0] ref512_block;

    wire           ref512_ready;
    wire [511:0]   ref512_digest;
    wire           ref512_digest_valid;

    sha512_core_ref u_sha512_ref (
        .clk             (clk),
        .reset_n         (rst_n),
        .init            (ref512_init),
        .next            (ref512_next),
        .mode            (2'b11), // Secworks SHA-512 mode.
        .work_factor     (1'b0),
        .work_factor_num (32'd0),
        .block           (ref512_block),
        .ready           (ref512_ready),
        .digest          (ref512_digest),
        .digest_valid    (ref512_digest_valid)
    );

    // ------------------------------------------------------------------------
    // Scoreboard / coverage bookkeeping.
    // ------------------------------------------------------------------------
    integer error_count;
    integer test_count;
    integer pass_count;

    integer random_single_256_blocks;
    integer random_single_512_blocks;
    integer random_multi_256_blocks;
    integer random_multi_512_blocks;

    integer protocol_monitor_checks;

    logic cov_sha256_round63;
    logic cov_sha512_round79;
    logic cov_sha256_zeroext;
    logic cov_mode_switch_256_to_512;
    logic cov_mode_switch_512_to_256;
    logic cov_init_priority;
    logic cov_busy_ignore;
    logic cov_sticky_digest;
    logic cov_reset_during_256;
    logic cov_reset_during_512;
    logic cov_next_mode_ignored_256;
    logic cov_next_mode_ignored_512;
    logic cov_sha256_low_half_ignored;

    // Deterministic xorshift32 pseudo-random generator.
    logic [31:0] prng_state;

    // ------------------------------------------------------------------------
    // Utility: record a test result.
    // ------------------------------------------------------------------------
    task automatic record_result(
        input string test_name,
        input logic  passed
    );
        begin
            test_count = test_count + 1;
            if (passed) begin
                pass_count = pass_count + 1;
                $display("PASS: %s", test_name);
            end
            else begin
                error_count = error_count + 1;
                $display("FAIL: %s", test_name);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Deterministic pseudo-random helpers.
    // ------------------------------------------------------------------------
    task automatic rand32(output logic [31:0] value);
        logic [31:0] x;
        begin
            x = prng_state;
            x = x ^ (x << 13);
            x = x ^ (x >> 17);
            x = x ^ (x << 5);

            // Never allow the xorshift state to become permanently zero.
            if (x == 32'd0)
                x = 32'h1D87_2B41;

            prng_state = x;
            value      = x;
        end
    endtask

    task automatic make_random_512(output logic [511:0] value);
        integer i;
        logic [31:0] word;
        begin
            value = '0;
            for (i = 0; i < 16; i = i + 1) begin
                rand32(word);
                value[511 - (i * 32) -: 32] = word;
            end
        end
    endtask

    task automatic make_random_1024(output logic [1023:0] value);
        integer i;
        logic [31:0] word;
        begin
            value = '0;
            for (i = 0; i < 32; i = i + 1) begin
                rand32(word);
                value[1023 - (i * 32) -: 32] = word;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Bounded waits.
    // ------------------------------------------------------------------------
    task automatic wait_dut_ready;
        integer cycles;
        begin
            cycles = 0;
            while ((dut_ready !== 1'b1) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                cycles = cycles + 1;
            end
            if (dut_ready !== 1'b1)
                $fatal(1, "TIMEOUT waiting for DUT ready");
        end
    endtask

    task automatic wait_ref256_ready;
        integer cycles;
        begin
            cycles = 0;
            while ((ref256_ready !== 1'b1) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                cycles = cycles + 1;
            end
            if (ref256_ready !== 1'b1)
                $fatal(1, "TIMEOUT waiting for SHA-256 reference ready");
        end
    endtask

    task automatic wait_ref512_ready;
        integer cycles;
        begin
            cycles = 0;
            while ((ref512_ready !== 1'b1) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                cycles = cycles + 1;
            end
            if (ref512_ready !== 1'b1)
                $fatal(1, "TIMEOUT waiting for SHA-512 reference ready");
        end
    endtask

    // ------------------------------------------------------------------------
    // Reset all DUT/reference state.
    // ------------------------------------------------------------------------
    task automatic apply_reset;
        begin
            @(negedge clk);

            rst_n        = 1'b0;
            dut_mode     = SHA2_256;
            dut_init     = 1'b0;
            dut_next     = 1'b0;
            dut_block    = '0;

            ref256_init  = 1'b0;
            ref256_next  = 1'b0;
            ref256_block = '0;

            ref512_init  = 1'b0;
            ref512_next  = 1'b0;
            ref512_block = '0;

            repeat (4) @(posedge clk);

            @(negedge clk);
            rst_n = 1'b1;

            repeat (2) @(posedge clk);
            #1;

            if ((dut_ready !== 1'b1) ||
                (dut_busy !== 1'b0) ||
                (dut_digest_valid !== 1'b0)) begin
                $display("RESET CHECK FAILED: ready=%b busy=%b digest_valid=%b",
                         dut_ready, dut_busy, dut_digest_valid);
                error_count = error_count + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Core differential transaction.
    //
    // command_kind:
    //   0 -> init
    //   1 -> next
    //   2 -> init and next simultaneously (init must win)
    //
    // dut_mode_value is the external mode_i value. For next tests this may be
    // intentionally opposite to the currently latched algorithm.
    //
    // expected_exec_mode identifies which golden reference must be used.
    // ------------------------------------------------------------------------
    task automatic run_compare_block(
        input string         test_name,
        input sha2_mode_t    expected_exec_mode,
        input sha2_mode_t    dut_mode_value,
        input integer        command_kind,
        input logic [1023:0] block_value,
        output logic [511:0] result_value,
        input logic          print_each_pass
    );
        integer dut_latency;
        integer ref_wait_cycles;
        logic [511:0] ref_value;
        logic local_pass;
        begin
            wait_dut_ready();

            if (expected_exec_mode == SHA2_256)
                wait_ref256_ready();
            else
                wait_ref512_ready();

            // Drive command and data before the accepting rising edge.
            @(negedge clk);
            dut_mode  = dut_mode_value;
            dut_block = block_value;

            dut_init = ((command_kind == 0) || (command_kind == 2));
            dut_next = ((command_kind == 1) || (command_kind == 2));

            if (expected_exec_mode == SHA2_256) begin
                ref256_block = block_value[1023:512];
                ref256_init  = ((command_kind == 0) || (command_kind == 2));
                ref256_next  = ((command_kind == 1) || (command_kind == 2));
            end
            else begin
                ref512_block = block_value;
                ref512_init  = ((command_kind == 0) || (command_kind == 2));
                ref512_next  = ((command_kind == 1) || (command_kind == 2));
            end

            // Command acceptance edge.
            @(posedge clk);
            #1;

            local_pass = 1'b1;

            if ((dut_ready !== 1'b0) || (dut_busy !== 1'b1)) begin
                $display("  ERROR %s: DUT did not enter busy after command", test_name);
                local_pass = 1'b0;
            end

            if (dut_digest_valid !== 1'b0) begin
                $display("  ERROR %s: digest_valid did not clear on accepted command",
                         test_name);
                local_pass = 1'b0;
            end

            // init_i must select mode_i. next_i must keep the already latched mode.
            if (u_dut.mode_q !== expected_exec_mode) begin
                $display("  ERROR %s: mode_q=%0d expected=%0d",
                         test_name, u_dut.mode_q, expected_exec_mode);
                local_pass = 1'b0;
            end

            // Remove command after exactly one accepted cycle.
            @(negedge clk);
            dut_init = 1'b0;
            dut_next = 1'b0;
            ref256_init = 1'b0;
            ref256_next = 1'b0;
            ref512_init = 1'b0;
            ref512_next = 1'b0;

            // DUT digest_valid is sticky; reference digest_valid may be a pulse.
            // Capture both independently.
            dut_latency = 0;
            ref_wait_cycles = 0;
            ref_value = '0;

            fork
                begin : capture_dut
                    while ((dut_digest_valid !== 1'b1) &&
                           (dut_latency < MAX_WAIT_CYCLES)) begin
                        @(posedge clk);
                        #1;
                        dut_latency = dut_latency + 1;
                    end

                    if (dut_digest_valid !== 1'b1)
                        $fatal(1, "TIMEOUT waiting for DUT digest in %s", test_name);

                    result_value = dut_digest;
                end

                begin : capture_ref
                    if (expected_exec_mode == SHA2_256) begin
                        while ((ref256_digest_valid !== 1'b1) &&
                               (ref_wait_cycles < MAX_WAIT_CYCLES)) begin
                            @(posedge clk);
                            #1;
                            ref_wait_cycles = ref_wait_cycles + 1;
                        end

                        if (ref256_digest_valid !== 1'b1)
                            $fatal(1, "TIMEOUT waiting for SHA-256 reference in %s",
                                   test_name);

                        ref_value = {256'b0, ref256_digest};
                    end
                    else begin
                        while ((ref512_digest_valid !== 1'b1) &&
                               (ref_wait_cycles < MAX_WAIT_CYCLES)) begin
                            @(posedge clk);
                            #1;
                            ref_wait_cycles = ref_wait_cycles + 1;
                        end

                        if (ref512_digest_valid !== 1'b1)
                            $fatal(1, "TIMEOUT waiting for SHA-512 reference in %s",
                                   test_name);

                        ref_value = ref512_digest;
                    end
                end
            join

            if (result_value !== ref_value) begin
                $display("  ERROR %s: DUT != golden reference", test_name);
                $display("    DUT    = %0128h", result_value);
                $display("    GOLDEN = %0128h", ref_value);
                local_pass = 1'b0;
            end

            if (expected_exec_mode == SHA2_256) begin
                if (result_value[511:256] !== 256'b0) begin
                    $display("  ERROR %s: SHA-256 upper digest half is not zero",
                             test_name);
                    local_pass = 1'b0;
                end

                if (dut_latency != SHA256_EXPECTED_LATENCY) begin
                    $display("  ERROR %s: SHA-256 latency=%0d expected=%0d",
                             test_name, dut_latency, SHA256_EXPECTED_LATENCY);
                    local_pass = 1'b0;
                end
            end
            else begin
                if (dut_latency != SHA512_EXPECTED_LATENCY) begin
                    $display("  ERROR %s: SHA-512 latency=%0d expected=%0d",
                             test_name, dut_latency, SHA512_EXPECTED_LATENCY);
                    local_pass = 1'b0;
                end
            end

            if (local_pass) begin
                if (print_each_pass)
                    record_result(test_name, 1'b1);
                else begin
                    test_count = test_count + 1;
                    pass_count = pass_count + 1;
                end
            end
            else begin
                record_result(test_name, 1'b0);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Known-answer single-block test.
    // ------------------------------------------------------------------------
    task automatic run_known_single(
        input string         test_name,
        input sha2_mode_t    mode_value,
        input logic [1023:0] block_value,
        input logic [511:0]  expected_value
    );
        logic [511:0] actual;
        logic passed;
        begin
            run_compare_block(test_name, mode_value, mode_value, 0,
                              block_value, actual, 1'b0);

            passed = (actual === expected_value);
            if (!passed) begin
                $display("  KAT expected = %0128h", expected_value);
                $display("  KAT actual   = %0128h", actual);
                error_count = error_count + 1;
                $display("FAIL: %s independent KAT", test_name);
            end
            else begin
                $display("PASS: %s (golden + independent KAT)", test_name);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Known-answer multi-block tests.
    // ------------------------------------------------------------------------
    task automatic test_sha256_known_multiblock;
        logic [511:0] r0;
        logic [511:0] r1;
        logic passed;
        begin
            run_compare_block("SHA-256 KAT multi block 0",
                              SHA2_256, SHA2_256, 0,
                              {SHA256_MB_BLOCK0, 512'b0}, r0, 1'b0);

            run_compare_block("SHA-256 KAT multi block 1",
                              SHA2_256, SHA2_256, 1,
                              {SHA256_MB_BLOCK1, 512'b0}, r1, 1'b0);

            passed = (r1[255:0] === SHA256_MB_EXPECTED) &&
                     (r1[511:256] === 256'b0);

            if (passed)
                $display("PASS: SHA-256 standard two-block chaining KAT");
            else begin
                $display("FAIL: SHA-256 standard two-block chaining KAT");
                $display("  expected = %064h", SHA256_MB_EXPECTED);
                $display("  actual   = %064h", r1[255:0]);
                error_count = error_count + 1;
            end
        end
    endtask

    task automatic test_sha512_known_multiblock;
        logic [511:0] r0;
        logic [511:0] r1;
        logic passed;
        begin
            run_compare_block("SHA-512 KAT multi block 0",
                              SHA2_512, SHA2_512, 0,
                              SHA512_MB_BLOCK0, r0, 1'b0);

            run_compare_block("SHA-512 KAT multi block 1",
                              SHA2_512, SHA2_512, 1,
                              SHA512_MB_BLOCK1, r1, 1'b0);

            passed = (r1 === SHA512_MB_EXPECTED);

            if (passed)
                $display("PASS: SHA-512 standard two-block chaining KAT");
            else begin
                $display("FAIL: SHA-512 standard two-block chaining KAT");
                $display("  expected = %0128h", SHA512_MB_EXPECTED);
                $display("  actual   = %0128h", r1);
                error_count = error_count + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Deterministic raw compression-block corner patterns.
    // These are not padded messages; they intentionally test the compression
    // core with difficult bit patterns and compare against the golden core.
    // ------------------------------------------------------------------------
    task automatic test_deterministic_patterns;
        logic [1023:0] block;
        logic [511:0]  result;
        integer i;
        begin
            $display("\n--- Deterministic raw-block corner patterns ---");

            // SHA-256 all zeros in active half; random-looking inactive half.
            block = '0;
            block[511:0] = {16{32'hDEAD_BEEF}};
            run_compare_block("SHA-256 raw all-zero active block",
                              SHA2_256, SHA2_256, 0, block, result, 1'b1);

            // SHA-256 all ones.
            block = '0;
            block[1023:512] = {512{1'b1}};
            block[511:0]    = {16{32'hA5A5_5A5A}};
            run_compare_block("SHA-256 raw all-one active block",
                              SHA2_256, SHA2_256, 0, block, result, 1'b1);

            // SHA-256 alternating AA/55.
            block[1023:512] = {32{16'hAA55}};
            block[511:0]    = {32{16'h55AA}};
            run_compare_block("SHA-256 raw alternating AA55",
                              SHA2_256, SHA2_256, 0, block, result, 1'b1);

            // SHA-256 incrementing 32-bit words.
            block = '0;
            for (i = 0; i < 16; i = i + 1)
                block[1023 - (i * 32) -: 32] = i;
            block[511:0] = {16{32'h1234_5678}};
            run_compare_block("SHA-256 raw incrementing words",
                              SHA2_256, SHA2_256, 0, block, result, 1'b1);

            // SHA-512 all zeros.
            block = '0;
            run_compare_block("SHA-512 raw all-zero block",
                              SHA2_512, SHA2_512, 0, block, result, 1'b1);

            // SHA-512 all ones.
            block = {1024{1'b1}};
            run_compare_block("SHA-512 raw all-one block",
                              SHA2_512, SHA2_512, 0, block, result, 1'b1);

            // SHA-512 alternating AA/55.
            block = {64{16'hAA55}};
            run_compare_block("SHA-512 raw alternating AA55",
                              SHA2_512, SHA2_512, 0, block, result, 1'b1);

            // SHA-512 incrementing 64-bit words.
            block = '0;
            for (i = 0; i < 16; i = i + 1)
                block[1023 - (i * 64) -: 64] = i;
            run_compare_block("SHA-512 raw incrementing words",
                              SHA2_512, SHA2_512, 0, block, result, 1'b1);
        end
    endtask

    // ------------------------------------------------------------------------
    // SHA-256 lower half of the unified 1024-bit input bus MUST be ignored.
    // ------------------------------------------------------------------------
    task automatic test_sha256_low_half_ignored;
        logic [511:0] active_block;
        logic [511:0] low_noise;
        logic [511:0] r_zero_low;
        logic [511:0] r_noise_low;
        begin
            make_random_512(active_block);
            make_random_512(low_noise);

            run_compare_block("SHA-256 low-half isolation baseline",
                              SHA2_256, SHA2_256, 0,
                              {active_block, 512'b0}, r_zero_low, 1'b0);

            run_compare_block("SHA-256 low-half isolation noisy",
                              SHA2_256, SHA2_256, 0,
                              {active_block, low_noise}, r_noise_low, 1'b0);

            if (r_zero_low === r_noise_low) begin
                cov_sha256_low_half_ignored = 1'b1;
                $display("PASS: SHA-256 block_i[511:0] is ignored");
            end
            else begin
                $display("FAIL: SHA-256 digest changed when unused lower 512 bits changed");
                error_count = error_count + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // digest_valid is intentionally sticky in this core.
    // ------------------------------------------------------------------------
    task automatic test_sticky_digest_valid;
        logic [1023:0] block;
        logic [511:0] result;
        logic [511:0] held_digest;
        integer i;
        logic passed;
        begin
            make_random_1024(block);

            run_compare_block("SHA-512 sticky digest setup",
                              SHA2_512, SHA2_512, 0, block, result, 1'b0);

            held_digest = dut_digest;
            passed = 1'b1;

            for (i = 0; i < 5; i = i + 1) begin
                @(posedge clk);
                #1;
                if ((dut_ready !== 1'b1) ||
                    (dut_busy !== 1'b0) ||
                    (dut_digest_valid !== 1'b1) ||
                    (dut_digest !== held_digest))
                    passed = 1'b0;
            end

            // New accepted command must clear digest_valid.
            make_random_1024(block);
            wait_dut_ready();
            wait_ref512_ready();

            @(negedge clk);
            dut_mode     = SHA2_512;
            dut_block    = block;
            dut_init     = 1'b1;
            ref512_block = block;
            ref512_init  = 1'b1;

            @(posedge clk);
            #1;
            if (dut_digest_valid !== 1'b0)
                passed = 1'b0;

            @(negedge clk);
            dut_init    = 1'b0;
            ref512_init = 1'b0;

            // Let this transaction complete normally so the references stay sane.
            fork
                begin
                    integer c0;
                    c0 = 0;
                    while ((dut_digest_valid !== 1'b1) &&
                           (c0 < MAX_WAIT_CYCLES)) begin
                        @(posedge clk);
                        #1;
                        c0 = c0 + 1;
                    end
                    if (dut_digest_valid !== 1'b1)
                        $fatal(1, "TIMEOUT in sticky digest test DUT completion");
                end
                begin
                    integer c1;
                    c1 = 0;
                    while ((ref512_digest_valid !== 1'b1) &&
                           (c1 < MAX_WAIT_CYCLES)) begin
                        @(posedge clk);
                        #1;
                        c1 = c1 + 1;
                    end
                    if (ref512_digest_valid !== 1'b1)
                        $fatal(1, "TIMEOUT in sticky digest test reference completion");
                end
            join

            if (dut_digest !== ref512_digest)
                passed = 1'b0;

            if (passed) begin
                cov_sticky_digest = 1'b1;
                record_result("digest_valid sticky in IDLE and clears on next command",
                              1'b1);
            end
            else begin
                record_result("digest_valid sticky in IDLE and clears on next command",
                              1'b0);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // next_i must ignore external mode_i and continue the current message mode.
    // ------------------------------------------------------------------------
    task automatic test_next_mode_latch;
        logic [1023:0] b0;
        logic [1023:0] b1;
        logic [511:0] r;
        begin
            make_random_1024(b0);
            make_random_1024(b1);

            // SHA-256 chain, but drive SHA2_512 on mode_i during next_i.
            run_compare_block("SHA-256 mode-latch first block",
                              SHA2_256, SHA2_256, 0, b0, r, 1'b0);
            run_compare_block("SHA-256 next ignores mode_i=SHA2_512",
                              SHA2_256, SHA2_512, 1, b1, r, 1'b1);

            if (u_dut.mode_q === SHA2_256)
                cov_next_mode_ignored_256 = 1'b1;
            else begin
                $display("FAIL: SHA-256 next changed latched mode");
                error_count = error_count + 1;
            end

            // New init switches to SHA-512.
            make_random_1024(b0);
            make_random_1024(b1);

            run_compare_block("SHA-512 mode-latch first block",
                              SHA2_512, SHA2_512, 0, b0, r, 1'b0);
            run_compare_block("SHA-512 next ignores mode_i=SHA2_256",
                              SHA2_512, SHA2_256, 1, b1, r, 1'b1);

            if (u_dut.mode_q === SHA2_512)
                cov_next_mode_ignored_512 = 1'b1;
            else begin
                $display("FAIL: SHA-512 next changed latched mode");
                error_count = error_count + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // init_i has priority over next_i if both are high in IDLE.
    // ------------------------------------------------------------------------
    task automatic test_init_priority;
        logic [1023:0] b0;
        logic [1023:0] b1;
        logic [511:0] r;
        begin
            // Build a non-IV previous chaining state.
            make_random_1024(b0);
            run_compare_block("init-priority preconditioning block",
                              SHA2_256, SHA2_256, 0, b0, r, 1'b0);

            // Both high: must start a NEW SHA-512 message.
            make_random_1024(b1);
            run_compare_block("init priority over next",
                              SHA2_512, SHA2_512, 2, b1, r, 1'b1);

            if (u_dut.mode_q === SHA2_512)
                cov_init_priority = 1'b1;
            else begin
                $display("FAIL: init+next did not give init priority");
                error_count = error_count + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // While busy, init/next/block/mode inputs must not restart the operation.
    // ------------------------------------------------------------------------
    task automatic test_command_ignored_while_busy(
        input sha2_mode_t mode_value
    );
        logic [1023:0] original_block;
        logic [1023:0] injected_block;
        logic [511:0] result;
        logic [511:0] ref_value;
        integer dut_cycles;
        integer ref_cycles;
        logic passed;
        begin
            make_random_1024(original_block);
            make_random_1024(injected_block);

            wait_dut_ready();
            if (mode_value == SHA2_256)
                wait_ref256_ready();
            else
                wait_ref512_ready();

            @(negedge clk);
            dut_mode  = mode_value;
            dut_block = original_block;
            dut_init  = 1'b1;
            dut_next  = 1'b0;

            if (mode_value == SHA2_256) begin
                ref256_block = original_block[1023:512];
                ref256_init  = 1'b1;
            end
            else begin
                ref512_block = original_block;
                ref512_init  = 1'b1;
            end

            @(posedge clk);
            #1;
            @(negedge clk);
            dut_init    = 1'b0;
            ref256_init = 1'b0;
            ref512_init = 1'b0;

            // Wait several rounds, then attempt an illegal command while busy.
            repeat (7) @(posedge clk);

            @(negedge clk);
            dut_mode  = (mode_value == SHA2_256) ? SHA2_512 : SHA2_256;
            dut_block = injected_block;
            dut_init  = 1'b1;
            dut_next  = 1'b1;

            @(posedge clk);
            #1;

            passed = 1'b1;

            if (dut_ready !== 1'b0)
                passed = 1'b0;

            if (u_dut.mode_q !== mode_value)
                passed = 1'b0;

            @(negedge clk);
            dut_init = 1'b0;
            dut_next = 1'b0;

            dut_cycles = 0;
            ref_cycles = 0;
            result     = '0;
            ref_value  = '0;

            fork
                begin
                    while ((dut_digest_valid !== 1'b1) &&
                           (dut_cycles < MAX_WAIT_CYCLES)) begin
                        @(posedge clk);
                        #1;
                        dut_cycles = dut_cycles + 1;
                    end
                    if (dut_digest_valid !== 1'b1)
                        $fatal(1, "TIMEOUT DUT busy-ignore test");
                    result = dut_digest;
                end
                begin
                    if (mode_value == SHA2_256) begin
                        while ((ref256_digest_valid !== 1'b1) &&
                               (ref_cycles < MAX_WAIT_CYCLES)) begin
                            @(posedge clk);
                            #1;
                            ref_cycles = ref_cycles + 1;
                        end
                        if (ref256_digest_valid !== 1'b1)
                            $fatal(1, "TIMEOUT SHA-256 ref busy-ignore test");
                        ref_value = {256'b0, ref256_digest};
                    end
                    else begin
                        while ((ref512_digest_valid !== 1'b1) &&
                               (ref_cycles < MAX_WAIT_CYCLES)) begin
                            @(posedge clk);
                            #1;
                            ref_cycles = ref_cycles + 1;
                        end
                        if (ref512_digest_valid !== 1'b1)
                            $fatal(1, "TIMEOUT SHA-512 ref busy-ignore test");
                        ref_value = ref512_digest;
                    end
                end
            join

            if (result !== ref_value)
                passed = 1'b0;

            if (passed) begin
                cov_busy_ignore = 1'b1;
                if (mode_value == SHA2_256)
                    record_result("SHA-256 ignores command/data/mode changes while busy",
                                  1'b1);
                else
                    record_result("SHA-512 ignores command/data/mode changes while busy",
                                  1'b1);
            end
            else begin
                if (mode_value == SHA2_256)
                    record_result("SHA-256 ignores command/data/mode changes while busy",
                                  1'b0);
                else
                    record_result("SHA-512 ignores command/data/mode changes while busy",
                                  1'b0);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Reset during active compression; then verify clean recovery.
    // ------------------------------------------------------------------------
    task automatic test_reset_during_compression(
        input sha2_mode_t mode_value
    );
        logic [1023:0] block;
        logic [511:0] result;
        integer i;
        logic entered_busy;
        logic passed;
        begin
            make_random_1024(block);

            wait_dut_ready();

            @(negedge clk);
            dut_mode  = mode_value;
            dut_block = block;
            dut_init  = 1'b1;

            @(posedge clk);
            #1;
            @(negedge clk);
            dut_init = 1'b0;

            entered_busy = 1'b0;
            for (i = 0; i < 10; i = i + 1) begin
                @(posedge clk);
                #1;
                if (dut_busy === 1'b1)
                    entered_busy = 1'b1;
            end

            // Reset all cores so subsequent differential tests start aligned.
            @(negedge clk);
            rst_n = 1'b0;
            dut_init = 1'b0;
            dut_next = 1'b0;
            ref256_init = 1'b0;
            ref256_next = 1'b0;
            ref512_init = 1'b0;
            ref512_next = 1'b0;

            repeat (3) @(posedge clk);

            @(negedge clk);
            rst_n = 1'b1;
            repeat (2) @(posedge clk);
            #1;

            passed = entered_busy &&
                     (dut_ready === 1'b1) &&
                     (dut_busy === 1'b0) &&
                     (dut_digest_valid === 1'b0);

            if (mode_value == SHA2_256) begin
                if (passed)
                    cov_reset_during_256 = 1'b1;
                record_result("reset during SHA-256 compression returns clean IDLE",
                              passed);

                // Recovery KAT.
                run_compare_block("SHA-256 recovery after mid-compression reset",
                                  SHA2_256, SHA2_256, 0,
                                  {SHA256_ABC_BLOCK, 512'b0}, result, 1'b0);
                record_result("SHA-256 recovery digest after reset",
                              result[255:0] === SHA256_ABC_EXPECTED);
            end
            else begin
                if (passed)
                    cov_reset_during_512 = 1'b1;
                record_result("reset during SHA-512 compression returns clean IDLE",
                              passed);

                run_compare_block("SHA-512 recovery after mid-compression reset",
                                  SHA2_512, SHA2_512, 0,
                                  SHA512_ABC_BLOCK, result, 1'b0);
                record_result("SHA-512 recovery digest after reset",
                              result === SHA512_ABC_EXPECTED);
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Randomized single-block regression.
    // SHA-256 intentionally randomizes the unused low 512 bits too.
    // ------------------------------------------------------------------------
    task automatic test_random_single_blocks;
        integer i;
        logic [511:0] active256;
        logic [511:0] inactive256;
        logic [1023:0] block512;
        logic [511:0] result;
        begin
            $display("\n--- Randomized single-block differential regression ---");

            for (i = 0; i < RANDOM_SINGLE_PER_MODE; i = i + 1) begin
                make_random_512(active256);
                make_random_512(inactive256);

                run_compare_block("random SHA-256 single block",
                                  SHA2_256, SHA2_256, 0,
                                  {active256, inactive256},
                                  result, 1'b0);

                random_single_256_blocks = random_single_256_blocks + 1;
            end

            $display("PASS: %0d randomized SHA-256 single blocks",
                     RANDOM_SINGLE_PER_MODE);

            for (i = 0; i < RANDOM_SINGLE_PER_MODE; i = i + 1) begin
                make_random_1024(block512);

                run_compare_block("random SHA-512 single block",
                                  SHA2_512, SHA2_512, 0,
                                  block512,
                                  result, 1'b0);

                random_single_512_blocks = random_single_512_blocks + 1;
            end

            $display("PASS: %0d randomized SHA-512 single blocks",
                     RANDOM_SINGLE_PER_MODE);
        end
    endtask

    // ------------------------------------------------------------------------
    // Randomized multi-block chaining regression.
    // Each intermediate chaining result is checked against the golden model.
    // ------------------------------------------------------------------------
    task automatic test_random_multiblock_mode(
        input sha2_mode_t mode_value
    );
        integer sequence_idx;
        integer block_idx;
        integer block_count;
        logic [31:0] rand_word;
        logic [1023:0] block;
        logic [511:0] result;
        begin
            for (sequence_idx = 0;
                 sequence_idx < RANDOM_MULTI_PER_MODE;
                 sequence_idx = sequence_idx + 1) begin

                rand32(rand_word);
                block_count = 2 +
                    (rand_word % (RANDOM_MULTI_MAX_BLOCKS - 1));

                for (block_idx = 0;
                     block_idx < block_count;
                     block_idx = block_idx + 1) begin

                    make_random_1024(block);

                    if (block_idx == 0) begin
                        run_compare_block("random multiblock init",
                                          mode_value, mode_value, 0,
                                          block, result, 1'b0);
                    end
                    else begin
                        // Randomize external mode_i on next operations. About
                        // half the time it intentionally disagrees with mode_q.
                        rand32(rand_word);
                        run_compare_block("random multiblock next",
                                          mode_value,
                                          rand_word[0] ? SHA2_512 : SHA2_256,
                                          1,
                                          block, result, 1'b0);
                    end

                    if (mode_value == SHA2_256)
                        random_multi_256_blocks = random_multi_256_blocks + 1;
                    else
                        random_multi_512_blocks = random_multi_512_blocks + 1;
                end
            end
        end
    endtask

    task automatic test_random_multiblock;
        begin
            $display("\n--- Randomized multi-block chaining regression ---");

            test_random_multiblock_mode(SHA2_256);
            $display("PASS: %0d random SHA-256 chaining sequences, %0d blocks total",
                     RANDOM_MULTI_PER_MODE, random_multi_256_blocks);

            test_random_multiblock_mode(SHA2_512);
            $display("PASS: %0d random SHA-512 chaining sequences, %0d blocks total",
                     RANDOM_MULTI_PER_MODE, random_multi_512_blocks);
        end
    endtask

    // ------------------------------------------------------------------------
    // Explicit rapid new-message mode switching.
    // ------------------------------------------------------------------------
    task automatic test_mode_switching;
        logic [1023:0] b0;
        logic [1023:0] b1;
        logic [511:0] r;
        begin
            make_random_1024(b0);
            make_random_1024(b1);

            run_compare_block("mode switch SHA-256 message",
                              SHA2_256, SHA2_256, 0, b0, r, 1'b0);

            run_compare_block("mode switch SHA-256 -> SHA-512",
                              SHA2_512, SHA2_512, 0, b1, r, 1'b1);
            cov_mode_switch_256_to_512 = 1'b1;

            make_random_1024(b0);

            run_compare_block("mode switch SHA-512 -> SHA-256",
                              SHA2_256, SHA2_256, 0, b0, r, 1'b1);
            cov_mode_switch_512_to_256 = 1'b1;
        end
    endtask

    // ------------------------------------------------------------------------
    // Continuous protocol/invariant monitor.
    // Sample at falling edge so NBA updates from the preceding rising edge
    // have settled.
    // ------------------------------------------------------------------------
    always @(negedge clk) begin
        if (rst_n) begin
            protocol_monitor_checks = protocol_monitor_checks + 1;

            // ready and busy must be exact complements.
            if ((dut_ready !== 1'b0) && (dut_ready !== 1'b1)) begin
                $display("MONITOR FAIL @%0t: ready is X/Z", $time);
                error_count = error_count + 1;
            end
            else if ((dut_busy !== 1'b0) && (dut_busy !== 1'b1)) begin
                $display("MONITOR FAIL @%0t: busy is X/Z", $time);
                error_count = error_count + 1;
            end
            else if (dut_ready === dut_busy) begin
                $display("MONITOR FAIL @%0t: ready=%b busy=%b are not complements",
                         $time, dut_ready, dut_busy);
                error_count = error_count + 1;
            end

            // digest_valid is allowed only when the core has returned to IDLE.
            if ((dut_digest_valid === 1'b1) && (dut_ready !== 1'b1)) begin
                $display("MONITOR FAIL @%0t: digest_valid asserted while not ready",
                         $time);
                error_count = error_count + 1;
            end

            // Round coverage.
            if ((u_dut.mode_q == SHA2_256) &&
                (u_dut.round_q == 7'd63) &&
                (dut_busy == 1'b1))
                cov_sha256_round63 = 1'b1;

            if ((u_dut.mode_q == SHA2_512) &&
                (u_dut.round_q == 7'd79) &&
                (dut_busy == 1'b1))
                cov_sha512_round79 = 1'b1;

            // SHA-256 unified 64-bit datapath invariant:
            // upper 32 bits must remain zero at register boundaries.
            if (u_dut.mode_q == SHA2_256) begin
                if ((u_dut.a_q[63:32] !== 32'b0) ||
                    (u_dut.b_q[63:32] !== 32'b0) ||
                    (u_dut.c_q[63:32] !== 32'b0) ||
                    (u_dut.d_q[63:32] !== 32'b0) ||
                    (u_dut.e_q[63:32] !== 32'b0) ||
                    (u_dut.f_q[63:32] !== 32'b0) ||
                    (u_dut.g_q[63:32] !== 32'b0) ||
                    (u_dut.h_q[63:32] !== 32'b0) ||
                    (u_dut.H0_q[63:32] !== 32'b0) ||
                    (u_dut.H1_q[63:32] !== 32'b0) ||
                    (u_dut.H2_q[63:32] !== 32'b0) ||
                    (u_dut.H3_q[63:32] !== 32'b0) ||
                    (u_dut.H4_q[63:32] !== 32'b0) ||
                    (u_dut.H5_q[63:32] !== 32'b0) ||
                    (u_dut.H6_q[63:32] !== 32'b0) ||
                    (u_dut.H7_q[63:32] !== 32'b0)) begin

                    $display("MONITOR FAIL @%0t: SHA-256 upper 32-bit invariant violated",
                             $time);
                    error_count = error_count + 1;
                end
                else begin
                    cov_sha256_zeroext = 1'b1;
                end
            end
        end
    end

    // ------------------------------------------------------------------------
    // Coverage closure checks.
    // ------------------------------------------------------------------------
    task automatic check_manual_coverage;
        logic coverage_pass;
        begin
            coverage_pass =
                cov_sha256_round63 &&
                cov_sha512_round79 &&
                cov_sha256_zeroext &&
                cov_mode_switch_256_to_512 &&
                cov_mode_switch_512_to_256 &&
                cov_init_priority &&
                cov_busy_ignore &&
                cov_sticky_digest &&
                cov_reset_during_256 &&
                cov_reset_during_512 &&
                cov_next_mode_ignored_256 &&
                cov_next_mode_ignored_512 &&
                cov_sha256_low_half_ignored;

            $display("\n================ MANUAL COVERAGE SUMMARY ================");
            $display("SHA-256 round 63 reached              : %0d", cov_sha256_round63);
            $display("SHA-512 round 79 reached              : %0d", cov_sha512_round79);
            $display("SHA-256 upper-32 zero invariant       : %0d", cov_sha256_zeroext);
            $display("Mode switch 256 -> 512                : %0d", cov_mode_switch_256_to_512);
            $display("Mode switch 512 -> 256                : %0d", cov_mode_switch_512_to_256);
            $display("init priority over next               : %0d", cov_init_priority);
            $display("Command ignored while busy            : %0d", cov_busy_ignore);
            $display("Sticky digest_valid behavior          : %0d", cov_sticky_digest);
            $display("Reset during SHA-256                   : %0d", cov_reset_during_256);
            $display("Reset during SHA-512                   : %0d", cov_reset_during_512);
            $display("SHA-256 next ignores mode_i            : %0d", cov_next_mode_ignored_256);
            $display("SHA-512 next ignores mode_i            : %0d", cov_next_mode_ignored_512);
            $display("SHA-256 unused low block half ignored : %0d", cov_sha256_low_half_ignored);
            $display("Protocol monitor sampled cycles        : %0d", protocol_monitor_checks);
            $display("==========================================================");

            if (!coverage_pass) begin
                $display("FAIL: one or more mandatory manual coverage points were not hit");
                error_count = error_count + 1;
            end
            else begin
                $display("PASS: all mandatory manual coverage points were hit");
            end
        end
    endtask

    // ------------------------------------------------------------------------
    // Main regression.
    // ------------------------------------------------------------------------
    initial begin : main_regression
        logic [511:0] result;

        clk = 1'b0;
        rst_n = 1'b0;

        dut_mode  = SHA2_256;
        dut_init  = 1'b0;
        dut_next  = 1'b0;
        dut_block = '0;

        ref256_init  = 1'b0;
        ref256_next  = 1'b0;
        ref256_block = '0;

        ref512_init  = 1'b0;
        ref512_next  = 1'b0;
        ref512_block = '0;

        error_count = 0;
        test_count  = 0;
        pass_count  = 0;

        random_single_256_blocks = 0;
        random_single_512_blocks = 0;
        random_multi_256_blocks  = 0;
        random_multi_512_blocks  = 0;
        protocol_monitor_checks  = 0;

        cov_sha256_round63          = 1'b0;
        cov_sha512_round79          = 1'b0;
        cov_sha256_zeroext          = 1'b0;
        cov_mode_switch_256_to_512  = 1'b0;
        cov_mode_switch_512_to_256  = 1'b0;
        cov_init_priority           = 1'b0;
        cov_busy_ignore             = 1'b0;
        cov_sticky_digest           = 1'b0;
        cov_reset_during_256        = 1'b0;
        cov_reset_during_512        = 1'b0;
        cov_next_mode_ignored_256   = 1'b0;
        cov_next_mode_ignored_512   = 1'b0;
        cov_sha256_low_half_ignored = 1'b0;

        prng_state = DEFAULT_RANDOM_SEED;

        $display("\n==========================================================");
        $display("UNIFIED SHA-2 CORE COMPREHENSIVE REGRESSION");
        $display("Pseudo-random seed = 0x%08h", prng_state);
        $display("Random single cases/mode = %0d", RANDOM_SINGLE_PER_MODE);
        $display("Random multi sequences/mode = %0d", RANDOM_MULTI_PER_MODE);
        $display("==========================================================");

        apply_reset();
        record_result("reset -> clean IDLE",
                      (dut_ready === 1'b1) &&
                      (dut_busy === 1'b0) &&
                      (dut_digest_valid === 1'b0));

        // ================================================================
        // GROUP A: Independent standard known-answer tests.
        // ================================================================
        $display("\n=== GROUP A: STANDARD KNOWN-ANSWER TESTS ===");

        run_known_single("SHA-256 empty message",
                         SHA2_256,
                         {SHA256_EMPTY_BLOCK, 512'b0},
                         {256'b0, SHA256_EMPTY_EXPECTED});

        run_known_single("SHA-256 abc",
                         SHA2_256,
                         {SHA256_ABC_BLOCK, 512'b0},
                         {256'b0, SHA256_ABC_EXPECTED});

        run_known_single("SHA-512 empty message",
                         SHA2_512,
                         SHA512_EMPTY_BLOCK,
                         SHA512_EMPTY_EXPECTED);

        run_known_single("SHA-512 abc",
                         SHA2_512,
                         SHA512_ABC_BLOCK,
                         SHA512_ABC_EXPECTED);

        test_sha256_known_multiblock();
        test_sha512_known_multiblock();

        // ================================================================
        // GROUP B: Deterministic compression-core corner patterns.
        // ================================================================
        $display("\n=== GROUP B: RAW-BLOCK CORNER PATTERNS ===");
        test_deterministic_patterns();
        test_sha256_low_half_ignored();

        // ================================================================
        // GROUP C: Control and protocol behavior.
        // ================================================================
        $display("\n=== GROUP C: CONTROL / PROTOCOL ===");
        test_mode_switching();
        test_next_mode_latch();
        test_init_priority();
        test_sticky_digest_valid();
        test_command_ignored_while_busy(SHA2_256);
        test_command_ignored_while_busy(SHA2_512);
        test_reset_during_compression(SHA2_256);
        test_reset_during_compression(SHA2_512);

        // ================================================================
        // GROUP D: Large randomized differential regression.
        // ================================================================
        $display("\n=== GROUP D: RANDOMIZED DIFFERENTIAL REGRESSION ===");
        test_random_single_blocks();
        test_random_multiblock();

        // ================================================================
        // Coverage closure and final summary.
        // ================================================================
        check_manual_coverage();

        $display("\n================ REGRESSION SUMMARY ======================");
        $display("Test transactions/check groups : %0d", test_count);
        $display("Passed                         : %0d", pass_count);
        $display("Errors                         : %0d", error_count);
        $display("Random SHA-256 single blocks   : %0d", random_single_256_blocks);
        $display("Random SHA-512 single blocks   : %0d", random_single_512_blocks);
        $display("Random SHA-256 chained blocks  : %0d", random_multi_256_blocks);
        $display("Random SHA-512 chained blocks  : %0d", random_multi_512_blocks);
        $display("Pseudo-random final state      : 0x%08h", prng_state);
        $display("==========================================================");

        if (error_count == 0) begin
            $display("\nALL UNIFIED SHA-2 CORE TESTS PASSED\n");
        end
        else begin
            $display("\nUNIFIED SHA-2 CORE REGRESSION FAILED: %0d error(s)\n",
                     error_count);
            $fatal(1, "tb_sha2_core failed");
        end

        $finish;
    end

    // ------------------------------------------------------------------------
    // Global watchdog. Long enough for the default randomized regression.
    // ------------------------------------------------------------------------
    initial begin
        #20_000_000ns;
        $fatal(1, "GLOBAL TIMEOUT: tb_sha2_core did not finish");
    end

endmodule

`default_nettype wire
