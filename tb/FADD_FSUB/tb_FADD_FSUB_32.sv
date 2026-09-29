`timescale 1 ns / 1 ps

//==========================================================//
//                 TB_FADD_FSUB_32                         //
//==========================================================//
// Testbench for:
//
//   FADD_32 : result = (A + B) mod P
//   FSUB_32 : result = (A - B) mod P
//
// where:
//   - A, B are 32-bit inputs
//   - result is 256-bit
//   - P = 2^255 - 19
//
// Test strategy:
//   1. Reset test
//   2. Directed corner cases
//   3. Exhaustive test for all 8-bit A/B combinations
//   4. Large uniform random test
//   5. Constrained A < B test
//   6. Constrained A > B test
//   7. Constrained A == B test
//   8. Check result < P
//   9. Check valid latency and one-cycle valid pulse
//
// IMPORTANT:
// With 32-bit inputs, A+B <= 2^33-2 << P.
// Therefore the FADD branch "sum >= P -> sum - P" can never be
// reached through the legal module inputs. This TB verifies FADD's
// legal 32-bit behavior, but cannot exercise that unreachable branch.
//==========================================================//

module tb_FADD_FSUB_32;

    //-------------------------------------//
    //             Parameters              //
    //-------------------------------------//
    localparam time CLK_PERIOD = 10ns;

    localparam logic [255:0] FIELD_P =
        256'h7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;

    parameter int NUM_RANDOM = 100_000;
    parameter int NUM_LT     = 10_000;
    parameter int NUM_GT     = 10_000;
    parameter int NUM_EQ     = 5_000;

    //-------------------------------------//
    //         DUT Input Signals           //
    //-------------------------------------//
    logic         CLK_i;
    logic         RST_i;
    logic         start_i;

    logic [31:0]  operand_a_i;
    logic [31:0]  operand_b_i;

    //-------------------------------------//
    //         DUT Output Signals          //
    //-------------------------------------//
    logic [255:0] add_result_o;
    logic         add_valid_o;

    logic [255:0] sub_result_o;
    logic         sub_valid_o;

    //-------------------------------------//
    //            Test Counters            //
    //-------------------------------------//
    longint unsigned test_count;
    longint unsigned pass_count;
    longint unsigned fail_count;

    longint unsigned lt_count;
    longint unsigned eq_count;
    longint unsigned gt_count;

    //-------------------------------------//
    //          Temporary Variables        //
    //-------------------------------------//
    logic [31:0] rand_a;
    logic [31:0] rand_b;
    logic [31:0] tmp32;

    int unsigned i;
    int unsigned j;

    //-------------------------------------//
    //           DUT Instances             //
    //-------------------------------------//
    FADD_32 u_FADD_32 (
        .CLK_i       (CLK_i),
        .RST_i       (RST_i),
        .start_i     (start_i),
        .operand_a_i (operand_a_i),
        .operand_b_i (operand_b_i),
        .result_o    (add_result_o),
        .valid_o     (add_valid_o)
    );

    FSUB_32 u_FSUB_32 (
        .CLK_i       (CLK_i),
        .RST_i       (RST_i),
        .start_i     (start_i),
        .operand_a_i (operand_a_i),
        .operand_b_i (operand_b_i),
        .result_o    (sub_result_o),
        .valid_o     (sub_valid_o)
    );

    //-------------------------------------//
    //            Clock Generation         //
    //-------------------------------------//
    initial begin
        CLK_i = 1'b0;

        forever #(CLK_PERIOD/2)
            CLK_i = ~CLK_i;
    end

    //-------------------------------------//
    //          FADD Reference Model       //
    //-------------------------------------//
    function automatic logic [255:0] ref_fadd (
        input logic [31:0] a,
        input logic [31:0] b
    );
        logic [255:0] a_ext;
        logic [255:0] b_ext;
        logic [255:0] sum_tmp;

        begin
            a_ext   = {224'd0, a};
            b_ext   = {224'd0, b};

            sum_tmp = a_ext + b_ext;

            //---------------------------------//
            // Mathematical modulo reduction  //
            //---------------------------------//
            if (sum_tmp >= FIELD_P)
                sum_tmp = sum_tmp - FIELD_P;

            ref_fadd = sum_tmp;
        end
    endfunction

    //-------------------------------------//
    //          FSUB Reference Model       //
    //-------------------------------------//
    function automatic logic [255:0] ref_fsub (
        input logic [31:0] a,
        input logic [31:0] b
    );
        logic [255:0] a_ext;
        logic [255:0] b_ext;
        logic [255:0] diff_tmp;

        begin
            a_ext = {224'd0, a};
            b_ext = {224'd0, b};

            //---------------------------------//
            // Mathematical modulo correction //
            //---------------------------------//
            if (a_ext >= b_ext)
                diff_tmp = a_ext - b_ext;
            else
                diff_tmp = a_ext + FIELD_P - b_ext;

            ref_fsub = diff_tmp;
        end
    endfunction

    //-------------------------------------//
    //             Check One Case          //
    //-------------------------------------//
    task automatic run_case (
        input logic [31:0] a,
        input logic [31:0] b,
        input string       test_name
    );
        logic [255:0] expected_add;
        logic [255:0] expected_sub;

        begin
            expected_add = ref_fadd(a, b);
            expected_sub = ref_fsub(a, b);

            test_count++;

            if (a < b)
                lt_count++;
            else if (a == b)
                eq_count++;
            else
                gt_count++;

            //---------------------------------//
            // Drive operands before start    //
            //---------------------------------//
            @(negedge CLK_i);

            operand_a_i = a;
            operand_b_i = b;
            start_i     = 1'b1;

            //---------------------------------//
            // First rising edge:
            // DUT must only capture operands //
            //---------------------------------//
            @(posedge CLK_i);
            #1;

            if ((add_valid_o !== 1'b0) ||
                (sub_valid_o !== 1'b0)) begin

                $error(
                    "[VALID EARLY] %s A=%h B=%h ADD_VALID=%b SUB_VALID=%b",
                    test_name, a, b, add_valid_o, sub_valid_o
                );

                fail_count++;
            end

            //---------------------------------//
            // Remove start pulse             //
            //---------------------------------//
            @(negedge CLK_i);
            start_i = 1'b0;

            //---------------------------------//
            // Second rising edge:
            // result must become valid       //
            //---------------------------------//
            @(posedge CLK_i);
            #1;

            if ((add_valid_o !== 1'b1) ||
                (sub_valid_o !== 1'b1)) begin

                $error(
                    "[VALID MISSING] %s A=%h B=%h ADD_VALID=%b SUB_VALID=%b",
                    test_name, a, b, add_valid_o, sub_valid_o
                );

                fail_count++;
            end

            //---------------------------------//
            // Check FADD                     //
            //---------------------------------//
            if (add_result_o !== expected_add) begin
                $error(
                    "[FADD FAIL] %s A=%h B=%h DUT=%064h EXPECTED=%064h",
                    test_name,
                    a,
                    b,
                    add_result_o,
                    expected_add
                );

                fail_count++;
            end

            //---------------------------------//
            // Check FSUB                     //
            //---------------------------------//
            if (sub_result_o !== expected_sub) begin
                $error(
                    "[FSUB FAIL] %s A=%h B=%h DUT=%064h EXPECTED=%064h",
                    test_name,
                    a,
                    b,
                    sub_result_o,
                    expected_sub
                );

                fail_count++;
            end

            //---------------------------------//
            // Canonical field range check    //
            //---------------------------------//
            if (add_result_o >= FIELD_P) begin
                $error(
                    "[FADD RANGE FAIL] %s RESULT=%064h >= P",
                    test_name,
                    add_result_o
                );

                fail_count++;
            end

            if (sub_result_o >= FIELD_P) begin
                $error(
                    "[FSUB RANGE FAIL] %s RESULT=%064h >= P",
                    test_name,
                    sub_result_o
                );

                fail_count++;
            end

            //---------------------------------//
            // Additional mathematical checks //
            //---------------------------------//

            // For legal 32-bit FADD inputs:
            // A+B is always smaller than P.
            if (add_result_o !== ({224'd0, a} + {224'd0, b})) begin
                $error(
                    "[FADD 32-BIT PROPERTY FAIL] %s",
                    test_name
                );

                fail_count++;
            end

            // If A >= B:
            // (A-B) mod P must equal A-B.
            if (a >= b) begin
                if (sub_result_o !== ({224'd0, a} - {224'd0, b})) begin
                    $error(
                        "[FSUB A>=B PROPERTY FAIL] %s A=%h B=%h",
                        test_name, a, b
                    );

                    fail_count++;
                end
            end

            // If A < B:
            // (A-B) mod P must equal A+P-B.
            else begin
                if (sub_result_o !==
                    ({224'd0, a} + FIELD_P - {224'd0, b})) begin

                    $error(
                        "[FSUB A<B PROPERTY FAIL] %s A=%h B=%h",
                        test_name, a, b
                    );

                    fail_count++;
                end
            end

            //---------------------------------//
            // Count case as passed only when //
            // all main DUT outputs match     //
            //---------------------------------//
            if ((add_result_o === expected_add) &&
                (sub_result_o === expected_sub) &&
                (add_valid_o  === 1'b1) &&
                (sub_valid_o  === 1'b1)) begin

                pass_count++;
            end

            //---------------------------------//
            // valid_o must be a 1-cycle pulse//
            //---------------------------------//
            @(posedge CLK_i);
            #1;

            if ((add_valid_o !== 1'b0) ||
                (sub_valid_o !== 1'b0)) begin

                $error(
                    "[VALID WIDTH FAIL] %s ADD_VALID=%b SUB_VALID=%b",
                    test_name,
                    add_valid_o,
                    sub_valid_o
                );

                fail_count++;
            end
        end
    endtask

    //-------------------------------------//
    //             Main Test               //
    //-------------------------------------//
    initial begin
        //---------------------------------//
        // Initialization                 //
        //---------------------------------//
        RST_i       = 1'b0;
        start_i     = 1'b0;
        operand_a_i = 32'd0;
        operand_b_i = 32'd0;

        test_count  = 0;
        pass_count  = 0;
        fail_count  = 0;

        lt_count    = 0;
        eq_count    = 0;
        gt_count    = 0;

        //---------------------------------//
        // Reset Test                     //
        //---------------------------------//
        repeat (3)
            @(posedge CLK_i);

        #1;

        if ((add_result_o !== 256'd0) ||
            (sub_result_o !== 256'd0) ||
            (add_valid_o  !== 1'b0)   ||
            (sub_valid_o  !== 1'b0)) begin

            $fatal(1, "[RESET FAIL]");
        end

        RST_i = 1'b1;

        @(posedge CLK_i);
        #1;

        $display("");
        $display("==============================================");
        $display("      FADD / FSUB 32-BIT TEST START");
        $display("==============================================");
        $display("P = %064h", FIELD_P);
        $display("");

        //---------------------------------//
        // Directed Corner Cases          //
        //---------------------------------//
        run_case(32'h00000000, 32'h00000000, "ZERO_ZERO");
        run_case(32'h00000001, 32'h00000000, "ONE_ZERO");
        run_case(32'h00000000, 32'h00000001, "ZERO_ONE");

        run_case(32'hFFFFFFFF, 32'h00000000, "MAX_ZERO");
        run_case(32'h00000000, 32'hFFFFFFFF, "ZERO_MAX");
        run_case(32'hFFFFFFFF, 32'hFFFFFFFF, "MAX_MAX");

        run_case(32'h80000000, 32'h7FFFFFFF, "MSB_GT");
        run_case(32'h7FFFFFFF, 32'h80000000, "MSB_LT");

        run_case(32'h12345678, 32'h12345678, "EQUAL_RANDOM");
        run_case(32'h12345679, 32'h12345678, "DIFF_PLUS_ONE");
        run_case(32'h12345678, 32'h12345679, "DIFF_MINUS_ONE");

        // Explicit 33-bit addition result:
        // 0xFFFFFFFF + 0x00000001 = 0x1_00000000
        run_case(32'hFFFFFFFF, 32'h00000001, "ADD_33_BIT_CARRY");

        //---------------------------------//
        // Exhaustive 8-bit Subspace      //
        //---------------------------------//
        // Tests every pair:
        // A = 0..255
        // B = 0..255
        //
        // Total = 65,536 cases.
        //---------------------------------//
        for (i = 0; i < 256; i++) begin
            for (j = 0; j < 256; j++) begin
                run_case(
                    i[31:0],
                    j[31:0],
                    "EXHAUSTIVE_8BIT"
                );
            end
        end

        //---------------------------------//
        // Large Uniform Random Test      //
        //---------------------------------//
        for (i = 0; i < NUM_RANDOM; i++) begin
            rand_a = $urandom();
            rand_b = $urandom();

            run_case(
                rand_a,
                rand_b,
                "RANDOM"
            );
        end

        //---------------------------------//
        // Force A < B Cases              //
        //---------------------------------//
        for (i = 0; i < NUM_LT; i++) begin
            rand_a = $urandom();
            rand_b = $urandom();

            if (rand_a > rand_b) begin
                tmp32  = rand_a;
                rand_a = rand_b;
                rand_b = tmp32;
            end

            if (rand_a == rand_b) begin
                if (rand_b != 32'hFFFFFFFF)
                    rand_b = rand_b + 32'd1;
                else
                    rand_a = rand_a - 32'd1;
            end

            run_case(
                rand_a,
                rand_b,
                "FORCED_A_LT_B"
            );
        end

        //---------------------------------//
        // Force A > B Cases              //
        //---------------------------------//
        for (i = 0; i < NUM_GT; i++) begin
            rand_a = $urandom();
            rand_b = $urandom();

            if (rand_a < rand_b) begin
                tmp32  = rand_a;
                rand_a = rand_b;
                rand_b = tmp32;
            end

            if (rand_a == rand_b) begin
                if (rand_a != 32'hFFFFFFFF)
                    rand_a = rand_a + 32'd1;
                else
                    rand_b = rand_b - 32'd1;
            end

            run_case(
                rand_a,
                rand_b,
                "FORCED_A_GT_B"
            );
        end

        //---------------------------------//
        // Force A == B Cases             //
        //---------------------------------//
        for (i = 0; i < NUM_EQ; i++) begin
            rand_a = $urandom();
            rand_b = rand_a;

            run_case(
                rand_a,
                rand_b,
                "FORCED_A_EQ_B"
            );
        end

        //---------------------------------//
        // Final Summary                  //
        //---------------------------------//
        $display("");
        $display("==============================================");
        $display("               TEST SUMMARY");
        $display("==============================================");
        $display("Total test cases : %0d", test_count);
        $display("Passed cases     : %0d", pass_count);
        $display("Error count      : %0d", fail_count);
        $display("");
        $display("A < B cases      : %0d", lt_count);
        $display("A = B cases      : %0d", eq_count);
        $display("A > B cases      : %0d", gt_count);
        $display("==============================================");

        if (fail_count == 0) begin
            $display("RESULT: ALL TESTS PASSED");
        end
        else begin
            $fatal(
                1,
                "RESULT: TEST FAILED, error count = %0d",
                fail_count
            );
        end

        $finish;
    end

endmodule
