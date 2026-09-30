`timescale 1 ns / 1 ps

//==========================================================//
//              TESTBENCH - X25519 FSUB                    //
//==========================================================//

module tb_FSub_25519;

    //======================================================//
    //                   PARAMETERS                         //
    //======================================================//

    localparam time CLK_PERIOD = 10ns;

    localparam logic [255:0] FIELD_P =
        256'h7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;

    localparam int NUM_RANDOM = 1000;


    //======================================================//
    //                  DUT SIGNALS                         //
    //======================================================//

    logic clk_i;
    logic rst_ni;

    logic start_i;

    logic [31:0] opa_i;
    logic [31:0] opb_i;

    logic        data_valid_i;

    logic [2:0]  src_limb_o;

    logic [31:0] result_o;
    logic [2:0]  dst_limb_o;

    logic        result_valid_o;

    logic [255:0] result_full_o;

    logic busy_o;
    logic done_o;


    //======================================================//
    //              SOURCE OPERANDS                         //
    //======================================================//

    logic [255:0] operand_a_source;
    logic [255:0] operand_b_source;


    //======================================================//
    //                TEST COUNTERS                         //
    //======================================================//

    integer test_count;
    integer pass_count;
    integer fail_count;

    integer a_gt_b_count;
    integer a_eq_b_count;
    integer a_lt_b_count;

    integer stall_test_count;
    integer random_test_count;


    //======================================================//
    //                     DUT                              //
    //======================================================//

    FSub_25519 dut (

        .clk_i              (clk_i),
        .rst_ni             (rst_ni),

        .start_i            (start_i),

        .opa_i              (opa_i),
        .opb_i              (opb_i),

        .data_valid_i       (data_valid_i),

        .src_limb_o         (src_limb_o),

        .result_o           (result_o),
        .dst_limb_o         (dst_limb_o),

        .result_valid_o     (result_valid_o),

        .result_full_o      (result_full_o),

        .busy_o             (busy_o),
        .done_o             (done_o)

    );


    //======================================================//
    //                     CLOCK                            //
    //======================================================//

    initial begin

        clk_i = 1'b0;

        forever
            #(CLK_PERIOD / 2)
            clk_i = ~clk_i;

    end


    //======================================================//
    //            SOURCE REGISTER FILE MODEL                //
    //======================================================//
    //
    // DUT requests:
    //
    //      src_limb_o = 0 ... 7
    //
    // Testbench returns:
    //
    //      opa_i = A[src_limb_o]
    //      opb_i = B[src_limb_o]
    //
    //======================================================//

    always_comb begin

        opa_i =
            operand_a_source[
                src_limb_o*32 +: 32
            ];

        opb_i =
            operand_b_source[
                src_limb_o*32 +: 32
            ];

    end


    //======================================================//
    //               REFERENCE MODEL                        //
    //======================================================//
    //
    // if A >= B:
    //
    //      R = A - B
    //
    // if A < B:
    //
    //      R = A - B + P
    //
    //======================================================//

    function automatic logic [255:0] reference_fsub (

        input logic [255:0] a,
        input logic [255:0] b

    );

        logic [256:0] temp;

        begin

            //-------------------------------------//
            // A >= B
            //-------------------------------------//

            if (a >= b) begin

                reference_fsub =
                    a - b;

            end

            //-------------------------------------//
            // A < B
            //-------------------------------------//

            else begin

                temp =
                    {1'b0, a}
                    +
                    {1'b0, FIELD_P}
                    -
                    {1'b0, b};

                reference_fsub =
                    temp[255:0];

            end

        end

    endfunction


    //======================================================//
    //              RANDOM FIELD ELEMENT                    //
    //======================================================//

    function automatic logic [255:0]
        random_field_element();

        logic [255:0] value;

        begin

            value = {

                $urandom,
                $urandom,
                $urandom,
                $urandom,
                $urandom,
                $urandom,
                $urandom,
                $urandom

            };


            //-------------------------------------//
            // X25519 field element < 2^255
            //-------------------------------------//

            value[255] = 1'b0;


            //-------------------------------------//
            // Ensure canonical:
            //
            //      value < P
            //-------------------------------------//

            if (value >= FIELD_P)

                value =
                    value - FIELD_P;


            return value;

        end

    endfunction


    //======================================================//
    //                    RESET TASK                        //
    //======================================================//

    task automatic reset_dut;

        begin

            rst_ni       = 1'b0;

            start_i      = 1'b0;
            data_valid_i = 1'b0;

            operand_a_source = 256'd0;
            operand_b_source = 256'd0;


            repeat (3)
                @(posedge clk_i);


            @(negedge clk_i);

            rst_ni = 1'b1;


            @(posedge clk_i);

            #1;


            //-------------------------------------//
            // Check reset state
            //-------------------------------------//

            if (busy_o !== 1'b0) begin

                $display(
                    "[RESET FAIL] busy_o = %b",
                    busy_o
                );

            end


            if (done_o !== 1'b0) begin

                $display(
                    "[RESET FAIL] done_o = %b",
                    done_o
                );

            end


            if (result_valid_o !== 1'b0) begin

                $display(
                    "[RESET FAIL] result_valid_o = %b",
                    result_valid_o
                );

            end


            if (result_full_o !== 256'd0) begin

                $display(
                    "[RESET FAIL] result_full_o != 0"
                );

            end


            $display(
                "[INFO] RESET complete"
            );

        end

    endtask


    //======================================================//
    //                   SINGLE TEST                        //
    //======================================================//

    task automatic run_test (

        input logic [255:0] a,
        input logic [255:0] b,

        input string test_name,

        // Maximum random stall cycles before
        // each input limb
        input integer max_stall

    );

        logic [255:0] expected;

        logic [255:0] stream_result;
        logic [255:0] full_result_snapshot;

        integer stall_cycles;
        integer output_count;
        integer timeout;

        bit case_failed;

        begin

            case_failed = 1'b0;


            //================================================//
            //            CHECK INPUT RANGE                    //
            //================================================//

            if (a >= FIELD_P) begin

                $display(
                    "[TB ERROR] %s : A >= P",
                    test_name
                );

                fail_count++;

                return;

            end


            if (b >= FIELD_P) begin

                $display(
                    "[TB ERROR] %s : B >= P",
                    test_name
                );

                fail_count++;

                return;

            end


            test_count++;


            //================================================//
            //              REFERENCE MODEL                    //
            //================================================//

            expected =
                reference_fsub(a, b);


            //================================================//
            //              COVERAGE CLASS                     //
            //================================================//

            if (a > b)

                a_gt_b_count++;

            else if (a == b)

                a_eq_b_count++;

            else

                a_lt_b_count++;


            if (max_stall > 0)

                stall_test_count++;


            //================================================//
            //               WAIT UNTIL IDLE                   //
            //================================================//

            while (busy_o)

                @(posedge clk_i);


            //================================================//
            //                SET OPERANDS                      //
            //================================================//

            operand_a_source = a;
            operand_b_source = b;

            data_valid_i = 1'b0;


            //================================================//
            //                  START                          //
            //================================================//

            @(negedge clk_i);

            start_i = 1'b1;


            @(posedge clk_i);

            #1;


            //-------------------------------------//
            // DUT must become busy
            //-------------------------------------//

            if (!busy_o) begin

                $display(
                    "[ERROR] %s : busy_o did not assert",
                    test_name
                );

                case_failed = 1'b1;

            end


            @(negedge clk_i);

            start_i = 1'b0;


            //================================================//
            //              SEND 8 INPUT LIMBS                 //
            //================================================//

            for (int limb = 0; limb < 8; limb++) begin


                //-------------------------------------//
                // Random stall
                //-------------------------------------//

                if (max_stall > 0)

                    stall_cycles =
                        $urandom_range(
                            0,
                            max_stall
                        );

                else

                    stall_cycles = 0;


                //-------------------------------------//
                // Hold data_valid low
                //-------------------------------------//

                repeat (stall_cycles) begin

                    data_valid_i = 1'b0;


                    //---------------------------------//
                    // DUT must keep requesting
                    // the same limb
                    //---------------------------------//

                    if (
                        src_limb_o
                        !==
                        limb[2:0]
                    ) begin

                        $display(
                            "[ERROR] %s : src_limb changed during stall.",
                            "Expected=%0d Actual=%0d",
                            test_name,
                            limb,
                            src_limb_o
                        );

                        case_failed = 1'b1;

                    end


                    @(posedge clk_i);

                    #1;

                    @(negedge clk_i);

                end


                //-------------------------------------//
                // Check requested limb
                //-------------------------------------//

                if (
                    src_limb_o
                    !==
                    limb[2:0]
                ) begin

                    $display(
                        "[ERROR] %s : Wrong source limb. ",
                        "Expected=%0d Actual=%0d",
                        test_name,
                        limb,
                        src_limb_o
                    );

                    case_failed = 1'b1;

                end


                //-------------------------------------//
                // Make current limb valid
                //-------------------------------------//

                data_valid_i = 1'b1;


                //-------------------------------------//
                // DUT consumes limb at rising edge
                //-------------------------------------//

                @(posedge clk_i);

                #1;


                //-------------------------------------//
                // Remove data_valid
                //-------------------------------------//

                @(negedge clk_i);

                data_valid_i = 1'b0;

            end


            //================================================//
            //              CAPTURE OUTPUT                     //
            //================================================//

            stream_result =
                256'd0;

            full_result_snapshot =
                256'd0;

            output_count = 0;

            timeout = 0;


            forever begin

                @(posedge clk_i);

                #1;

                timeout++;


                //-------------------------------------//
                // Timeout protection
                //-------------------------------------//

                if (timeout > 50) begin

                    $display(
                        "[FAIL] %s : OUTPUT TIMEOUT",
                        test_name
                    );

                    fail_count++;

                    return;

                end


                //-------------------------------------//
                // Capture streamed limb
                //-------------------------------------//

                if (result_valid_o) begin


                    //---------------------------------//
                    // Expected order:
                    //
                    // 0 -> 1 -> ... -> 7
                    //---------------------------------//

                    if (
                        dst_limb_o
                        !==
                        output_count[2:0]
                    ) begin

                        $display(
                            "[ERROR] %s : Wrong dst_limb. ",
                            "Expected=%0d Actual=%0d",
                            test_name,
                            output_count,
                            dst_limb_o
                        );

                        case_failed = 1'b1;

                    end


                    //---------------------------------//
                    // Rebuild full result
                    //---------------------------------//

                    stream_result[
                        dst_limb_o*32 +: 32
                    ] = result_o;


                    //---------------------------------//
                    // result_full_o should already
                    // contain the complete answer
                    //---------------------------------//

                    if (output_count == 0) begin

                        full_result_snapshot =
                            result_full_o;

                    end

                    else begin

                        //---------------------------------//
                        // It must remain stable during
                        // all 8 output cycles
                        //---------------------------------//

                        if (
                            result_full_o
                            !==
                            full_result_snapshot
                        ) begin

                            $display(
                                "[ERROR] %s : result_full_o changed ",
                                "during ST_OUT",
                                test_name
                            );

                            case_failed = 1'b1;

                        end

                    end


                    output_count++;


                    //---------------------------------//
                    // done_o may only assert
                    // with final limb 7
                    //---------------------------------//

                    if (done_o) begin

                        if (
                            dst_limb_o
                            !==
                            3'd7
                        ) begin

                            $display(
                                "[ERROR] %s : done_o asserted before ",
                                "limb 7",
                                test_name
                            );

                            case_failed = 1'b1;

                        end

                        break;

                    end

                end

            end


            //================================================//
            //            OUTPUT COUNT CHECK                   //
            //================================================//

            if (output_count != 8) begin

                $display(
                    "[ERROR] %s : Expected 8 output limbs, got %0d",
                    test_name,
                    output_count
                );

                case_failed = 1'b1;

            end


            //================================================//
            //         CHECK COMPLETE 256-BIT RESULT           //
            //================================================//

            if (
                result_full_o
                !==
                expected
            ) begin

                $display("");
                $display(
                    "[ERROR] %s : result_full_o mismatch ",
                    test_name
                );

                $display(
                    "       A        = %064h",
                    a
                );

                $display(
                    "       B        = %064h",
                    b
                );

                $display(
                    "       EXPECTED = %064h",
                    expected
                );

                $display(
                    "       DUT FULL = %064h",
                    result_full_o
                );

                case_failed = 1'b1;

            end


            //================================================//
            //           CHECK STREAM RESULT                   //
            //================================================//

            if (
                stream_result
                !==
                expected
            ) begin

                $display("");
                $display(
                    "[ERROR] %s : streamed result mismatch",
                    test_name
                );

                $display(
                    "       A        = %064h",
                    a
                );

                $display(
                    "       B        = %064h",
                    b
                );

                $display(
                    "       EXPECTED = %064h",
                    expected
                );

                $display(
                    "       STREAM   = %064h",
                    stream_result
                );

                case_failed = 1'b1;

            end


            //================================================//
            //        RESULT MUST BE CANONICAL                 //
            //================================================//

            if (
                result_full_o
                >=
                FIELD_P
            ) begin

                $display(
                    "[ERROR] %s : result >= P",
                    test_name
                );

                case_failed = 1'b1;

            end


            //================================================//
            //       INTERNAL BORROW RELATION CHECK            //
            //================================================//
            //
            // For canonical operands:
            //
            // A < B  -> final borrow = 1
            // A >= B -> final borrow = 0
            //
            //================================================//

            if (
                dut.diff_borrow_r
                !==
                (a < b)
            ) begin

                $display(
                    "[ERROR] %s : diff_borrow_r incorrect. ",
                    "Expected=%b Actual=%b",
                    test_name,
                    (a < b),
                    dut.diff_borrow_r
                );

                case_failed = 1'b1;

            end


            //================================================//
            //          FINAL PASS / FAIL                      //
            //================================================//

            if (!case_failed) begin

                pass_count++;

                $display(
                    "[PASS] %-25s ",
                    "A=%064h ",
                    "B=%064h ",
                    "R=%064h",
                    test_name,
                    a,
                    b,
                    expected
                );

            end

            else begin

                fail_count++;

                $display(
                    "[FAIL] %s",
                    test_name
                );

            end


            //================================================//
            //          CHECK RETURN TO IDLE                   //
            //================================================//

            @(posedge clk_i);

            #1;


            if (done_o !== 1'b0) begin

                $display(
                    "[ERROR] %s : ",
                    "done_o longer than one output cycle",
                    test_name
                );

            end


            if (result_valid_o !== 1'b0) begin

                $display(
                    "[ERROR] %s : ",
                    "result_valid_o still asserted",
                    test_name
                );

            end


            if (busy_o !== 1'b0) begin

                $display(
                    "[ERROR] %s : ",
                    "busy_o still asserted",
                    test_name
                );

            end

        end

    endtask


    //======================================================//
    //                  MAIN TEST                           //
    //======================================================//

    initial begin

        //==================================================//
        //                 INITIALIZATION                   //
        //==================================================//

        rst_ni       = 1'b0;

        start_i      = 1'b0;
        data_valid_i = 1'b0;

        operand_a_source = 256'd0;
        operand_b_source = 256'd0;

        test_count = 0;
        pass_count = 0;
        fail_count = 0;

        a_gt_b_count = 0;
        a_eq_b_count = 0;
        a_lt_b_count = 0;

        stall_test_count = 0;
        random_test_count = 0;


        //==================================================//
        //                    RESET                         //
        //==================================================//

        reset_dut();


        //==================================================//
        //             BASIC TEST CASES                     //
        //==================================================//

        //-------------------------------------//
        // 0 - 0 = 0
        //-------------------------------------//

        run_test(
            256'd0,
            256'd0,
            "0 - 0",
            0
        );


        //-------------------------------------//
        // 1 - 0 = 1
        //-------------------------------------//

        run_test(
            256'd1,
            256'd0,
            "1 - 0",
            0
        );


        //-------------------------------------//
        // 1 - 1 = 0
        //-------------------------------------//

        run_test(
            256'd1,
            256'd1,
            "1 - 1",
            0
        );


        //-------------------------------------//
        // A < B
        //
        // 0 - 1 mod P = P - 1
        //-------------------------------------//

        run_test(
            256'd0,
            256'd1,
            "0 - 1",
            0
        );


        //==================================================//
        //           CANONICAL BOUNDARY TESTS               //
        //==================================================//

        //-------------------------------------//
        // Maximum A
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            256'd0,
            "(P-1) - 0",
            0
        );


        //-------------------------------------//
        // Equal maximum operands
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            FIELD_P - 1,
            "(P-1)-(P-1)",
            0
        );


        //-------------------------------------//
        // Difference = 1
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            FIELD_P - 2,
            "(P-1)-(P-2)",
            0
        );


        //-------------------------------------//
        // A < B by 1
        //
        // Expected P - 1
        //-------------------------------------//

        run_test(
            FIELD_P - 2,
            FIELD_P - 1,
            "(P-2)-(P-1)",
            0
        );


        //-------------------------------------//
        // Largest negative difference:
        //
        // 0 - (P-1) mod P = 1
        //-------------------------------------//

        run_test(
            256'd0,
            FIELD_P - 1,
            "0-(P-1)",
            0
        );


        //==================================================//
        //              BORROW TESTS                        //
        //==================================================//

        //-------------------------------------//
        // Borrow limb 0 -> limb 1
        //
        // A = 0x1_00000000
        // B = 1
        //
        // Result = FFFFFFFF
        //-------------------------------------//

        run_test(
            256'h0000000000000000000000000000000000000000000000000000000100000000,
            256'd1,
            "borrow limb0->1",
            0
        );


        //-------------------------------------//
        // Borrow through 64-bit boundary
        //-------------------------------------//

        run_test(
            256'h0000000000000000000000000000000000000000000000010000000000000000,
            256'd1,
            "borrow 64-bit",
            0
        );


        //-------------------------------------//
        // Borrow through 128-bit boundary
        //-------------------------------------//

        run_test(
            256'h0000000000000000000000000000000100000000000000000000000000000000,
            256'd1,
            "borrow 128-bit",
            0
        );


        //-------------------------------------//
        // Long borrow chain through almost
        // the complete 256-bit datapath
        //-------------------------------------//

        run_test(
            256'h0000000100000000000000000000000000000000000000000000000000000000,
            256'd1,
            "long borrow chain",
            0
        );


        //==================================================//
        // SPECIAL B + BORROW OVERFLOW TEST                 //
        //==================================================//
        //
        // This case specifically exercises:
        //
        //      opb_i = FFFFFFFF
        //      borrow_r = 1
        //
        // Therefore:
        //
        //      B + borrow
        //
        //      = FFFFFFFF + 1
        //
        //      = 1_00000000
        //
        // This verifies why sub_rhs_w must be 33-bit.
        //
        //==================================================//

        run_test(
            256'h000000000000000000000000000000000000000000000000FFFFFFFF00000000,
            256'h000000000000000000000000000000000000000000000000FFFFFFFF00000001,
            "B=FFFFFFFF + borrow",
            0
        );


        //==================================================//
        //              DATA VALID STALLS                   //
        //==================================================//

        run_test(
            256'h123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0,
            256'h023456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE00,
            "A>B with stalls",
            4
        );


        run_test(
            256'h023456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE00,
            256'h123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0,
            "A<B with stalls",
            4
        );


        run_test(
            FIELD_P - 1,
            FIELD_P - 1,
            "A=B with stalls",
            5
        );


        //==================================================//
        //                 RANDOM TESTS                     //
        //==================================================//

        for (
            int t = 0;
            t < NUM_RANDOM;
            t++
        ) begin

            logic [255:0] rand_a;
            logic [255:0] rand_b;


            rand_a =
                random_field_element();


            rand_b =
                random_field_element();


            random_test_count++;


            run_test(

                rand_a,

                rand_b,

                $sformatf(
                    "RANDOM_%0d",
                    t
                ),

                2

            );

        end


        //==================================================//
        //                 FINAL REPORT                     //
        //==================================================//

        $display("");

        $display(
            "============================================================"
        );

        $display(
            "                X25519 FSUB TEST REPORT"
        );

        $display(
            "============================================================"
        );


        $display(
            "Total tests       : %0d",
            test_count
        );

        $display(
            "Passed            : %0d",
            pass_count
        );

        $display(
            "Failed            : %0d",
            fail_count
        );


        $display(
            "------------------------------------------------------------"
        );


        $display(
            "A > B cases       : %0d",
            a_gt_b_count
        );

        $display(
            "A = B cases       : %0d",
            a_eq_b_count
        );

        $display(
            "A < B cases       : %0d",
            a_lt_b_count
        );


        $display(
            "Tests with stalls : %0d",
            stall_test_count
        );


        $display(
            "Random tests      : %0d",
            random_test_count
        );


        $display(
            "============================================================"
        );


        if (fail_count == 0)

            $display(
                "                 ALL TESTS PASSED"
            );

        else

            $display(
                "                 TEST FAILED"
            );


        $display(
            "============================================================"
        );


        $finish;

    end


    //======================================================//
    //                 GLOBAL TIMEOUT                       //
    //======================================================//

    initial begin

        #10ms;

        $display(
            "[FATAL] GLOBAL TESTBENCH TIMEOUT"
        );

        $finish;

    end

endmodule