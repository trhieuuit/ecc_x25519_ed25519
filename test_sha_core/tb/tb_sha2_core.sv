`timescale 1ns/1ps
`default_nettype none

module tb_sha2_core;

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

        $display("\n============================================================");
        if (error_count == 0) begin
            $display("ALL SINGLE-BLOCK SHA-2 TESTS PASSED");
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
        #5000ns;
        $fatal(1, "TIMEOUT: tb_sha2_core did not finish within 5000 ns");
    end

endmodule

`default_nettype wire
