`timescale 1 ns / 1 ps

//==========================================================//
//            TESTBENCH - X25519 FADD                      //
//==========================================================//

module tb_FAdd_25519;

    //======================================================//
    //                   PARAMETERS                         //
    //======================================================//

    localparam time CLK_PERIOD = 10ns;

    localparam logic [255:0] FIELD_P =
        256'h7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;

    localparam int NUM_RANDOM = 100;


    //======================================================//
    //                 DUT SIGNALS                          //
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
    //               SOURCE OPERANDS                        //
    //======================================================//

    logic [255:0] operand_a_source;
    logic [255:0] operand_b_source;


    //======================================================//
    //               TEST COUNTERS                          //
    //======================================================//

    integer test_count;
    integer pass_count;
    integer fail_count;

    integer sum_lt_p_count;
    integer sum_eq_p_count;
    integer sum_gt_p_count;

    integer stall_test_count;
    integer random_test_count;


    //======================================================//
    //                      DUT                             //
    //======================================================//

    FAdd_25519 dut (

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
    // FADD asks for limb src_limb_o.
    //
    // TB immediately selects:
    //
    //      A[src_limb_o]
    //      B[src_limb_o]
    //
    // data_valid_i controls whether DUT is allowed to
    // consume the selected limb.
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
    //              REFERENCE MODEL                         //
    //======================================================//

    function automatic logic [255:0] reference_fadd (

        input logic [255:0] a,
        input logic [255:0] b

    );

        logic [256:0] full_sum;

        begin

            full_sum =
                {1'b0, a}
                +
                {1'b0, b};

            //-------------------------------------//
            // A,B < P
            //
            // therefore:
            //
            // A+B < 2P
            //
            // so subtract P at most once.
            //-------------------------------------//

            if (full_sum >= {1'b0, FIELD_P})

                reference_fadd =
                    full_sum - {1'b0, FIELD_P};

            else

                reference_fadd =
                    full_sum[255:0];

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
            // X25519 field is below 2^255
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
    //                 RESET TASK                           //
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
            // Reset checks
            //-------------------------------------//

            if (busy_o !== 1'b0) begin

                $display(
                    "[FAIL] RESET: busy_o = %b",
                    busy_o
                );

                fail_count++;

            end

            if (done_o !== 1'b0) begin

                $display(
                    "[FAIL] RESET: done_o = %b",
                    done_o
                );

                fail_count++;

            end

            if (result_valid_o !== 1'b0) begin

                $display(
                    "[FAIL] RESET: result_valid_o = %b",
                    result_valid_o
                );

                fail_count++;

            end

            if (result_full_o !== 256'd0) begin

                $display(
                    "[FAIL] RESET: result_full_o != 0"
                );

                fail_count++;

            end

        end

    endtask


    //======================================================//
    //                 SINGLE TEST                          //
    //======================================================//
    //
    // max_stall:
    //
    //      0 -> data every cycle
    //
    //      N -> randomly stall 0..N cycles before
    //           supplying each input limb
    //
    //======================================================//

    task automatic run_test (

        input logic [255:0] a,
        input logic [255:0] b,

        input string test_name,

        input integer max_stall

    );

        logic [255:0] expected;
        logic [255:0] stream_result;
        logic [255:0] full_result_snapshot;

        logic [256:0] full_sum;

        integer stall_cycles;
        integer output_count;
        integer timeout;

        begin

            //================================================//
            //        Check test input assumption              //
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
            //             Reference Result                    //
            //================================================//

            expected =
                reference_fadd(a, b);

            full_sum =
                {1'b0, a}
                +
                {1'b0, b};


            //-------------------------------------//
            // Coverage classification
            //-------------------------------------//

            if (full_sum < {1'b0, FIELD_P})

                sum_lt_p_count++;

            else if (full_sum == {1'b0, FIELD_P})

                sum_eq_p_count++;

            else

                sum_gt_p_count++;


            if (max_stall > 0)

                stall_test_count++;


            //================================================//
            //              Wait DUT IDLE                      //
            //================================================//

            while (busy_o)

                @(posedge clk_i);


            //================================================//
            //                Apply operands                   //
            //================================================//

            operand_a_source = a;
            operand_b_source = b;

            data_valid_i = 1'b0;


            //================================================//
            //               START pulse                       //
            //================================================//

            @(negedge clk_i);

            start_i = 1'b1;

            @(posedge clk_i);

            #1;


            //-------------------------------------//
            // DUT should now be busy
            //-------------------------------------//

            if (!busy_o) begin

                $display(
                    "[FAIL] %s : busy_o did not assert",
                    test_name
                );

                fail_count++;

            end


            @(negedge clk_i);

            start_i = 1'b0;


            //================================================//
            //           Send 8 input limbs                    //
            //================================================//

            for (int limb = 0; limb < 8; limb++) begin

                //-------------------------------------//
                // Random input stall
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
                    // DUT must keep requesting the
                    // same limb while input is invalid
                    //---------------------------------//

                    if (src_limb_o !== limb[2:0]) begin

                        $display(
                            "[FAIL] %s : ",
                            "src_limb changed during stall. ",
                            "Expected=%0d Actual=%0d",
                            test_name,
                            limb,
                            src_limb_o
                        );

                        fail_count++;

                    end

                    @(posedge clk_i);

                    #1;

                    @(negedge clk_i);

                end


                //-------------------------------------//
                // Check requested limb
                //-------------------------------------//

                if (src_limb_o !== limb[2:0]) begin

                    $display(
                        "[FAIL] %s : ",
                        "Wrong source limb. ",
                        "Expected=%0d Actual=%0d",
                        test_name,
                        limb,
                        src_limb_o
                    );

                    fail_count++;

                end


                //-------------------------------------//
                // Supply valid A/B limb
                //-------------------------------------//

                data_valid_i = 1'b1;

                @(posedge clk_i);

                #1;


                //-------------------------------------//
                // Current limb consumed
                //-------------------------------------//

                @(negedge clk_i);

                data_valid_i = 1'b0;

            end


            //================================================//
            //         Wait for streamed result                //
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
                // Capture output limb
                //-------------------------------------//

                if (result_valid_o) begin

                    //---------------------------------//
                    // Output order must be 0 -> 7
                    //---------------------------------//

                    if (dst_limb_o !== output_count[2:0]) begin

                        $display(
                            "[FAIL] %s : ",
                            "Wrong dst_limb. ",
                            "Expected=%0d Actual=%0d",
                            test_name,
                            output_count,
                            dst_limb_o
                        );

                        fail_count++;

                    end


                    //---------------------------------//
                    // Rebuild 256-bit stream result
                    //---------------------------------//

                    stream_result[
                        dst_limb_o*32 +: 32
                    ] = result_o;


                    //---------------------------------//
                    // result_full_o must already be
                    // valid during ST_OUT
                    //---------------------------------//

                    if (output_count == 0)

                        full_result_snapshot =
                            result_full_o;

                    else begin

                        if (
                            result_full_o
                            !==
                            full_result_snapshot
                        ) begin

                            $display(
                                "[FAIL] %s : ",
                                "result_full_o changed ",
                                "during output stream",
                                test_name
                            );

                            fail_count++;

                        end

                    end


                    output_count++;


                    //---------------------------------//
                    // done must only occur at limb 7
                    //---------------------------------//

                    if (done_o) begin

                        if (dst_limb_o !== 3'd7) begin

                            $display(
                                "[FAIL] %s : ",
                                "done_o asserted before ",
                                "limb 7",
                                test_name
                            );

                            fail_count++;

                        end

                        break;

                    end

                end

            end


            //================================================//
            //             Number of output limbs              //
            //================================================//

            if (output_count != 8) begin

                $display(
                    "[FAIL] %s : ",
                    "Expected 8 output limbs, got %0d",
                    test_name,
                    output_count
                );

                fail_count++;

            end


            //================================================//
            //             Compare full result                 //
            //================================================//

            if (
                result_full_o !== expected
            ) begin

                $display("");
                $display(
                    "[FAIL] %s : result_full_o mismatch",
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
                    "       FULL DUT = %064h",
                    result_full_o
                );

                fail_count++;

            end


            //================================================//
            //          Compare streamed result                //
            //================================================//

            else if (
                stream_result !== expected
            ) begin

                $display("");
                $display(
                    "[FAIL] %s : streamed result mismatch",
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

                fail_count++;

            end


            //================================================//
            //                PASS                             //
            //================================================//

            else begin

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


            //================================================//
            //      Result must be canonical < P              //
            //================================================//

            if (result_full_o >= FIELD_P) begin

                $display(
                    "[FAIL] %s : result >= P",
                    test_name
                );

                fail_count++;

            end


            //================================================//
            //           Check end of transaction              //
            //================================================//

            @(posedge clk_i);

            #1;


            if (done_o !== 1'b0) begin

                $display(
                    "[FAIL] %s : done_o longer than 1 cycle",
                    test_name
                );

                fail_count++;

            end


            if (result_valid_o !== 1'b0) begin

                $display(
                    "[FAIL] %s : ",
                    "result_valid_o longer than expected",
                    test_name
                );

                fail_count++;

            end


            if (busy_o !== 1'b0) begin

                $display(
                    "[FAIL] %s : busy_o still high",
                    test_name
                );

                fail_count++;

            end

        end

    endtask


    //======================================================//
    //                   MAIN TEST                          //
    //======================================================//

    initial begin

        //-------------------------------------//
        // Initialization
        //-------------------------------------//

        rst_ni       = 1'b0;
        start_i      = 1'b0;
        data_valid_i = 1'b0;

        operand_a_source = 256'd0;
        operand_b_source = 256'd0;

        test_count = 0;
        pass_count = 0;
        fail_count = 0;

        sum_lt_p_count = 0;
        sum_eq_p_count = 0;
        sum_gt_p_count = 0;

        stall_test_count = 0;
        random_test_count = 0;


        //==================================================//
        //                  RESET                           //
        //==================================================//

        reset_dut();


        //==================================================//
        //             BASIC DIRECTED TESTS                 //
        //==================================================//

        run_test(
            256'd0,
            256'd0,
            "0 + 0",
            0
        );


        run_test(
            256'd1,
            256'd0,
            "1 + 0",
            0
        );


        run_test(
            256'd0,
            256'd1,
            "0 + 1",
            0
        );


        run_test(
            256'd1,
            256'd1,
            "1 + 1",
            0
        );


        //==================================================//
        //            MODULO BOUNDARY TESTS                 //
        //==================================================//

        //-------------------------------------//
        // SUM = P - 1
        //
        // No modulo subtraction selected
        //-------------------------------------//

        run_test(
            FIELD_P - 2,
            256'd1,
            "SUM = P-1",
            0
        );


        //-------------------------------------//
        // SUM = P
        //
        // Expected result = 0
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            256'd1,
            "SUM = P",
            0
        );


        //-------------------------------------//
        // SUM = P + 1
        //
        // Expected result = 1
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            256'd2,
            "SUM = P+1",
            0
        );


        //-------------------------------------//
        // Maximum possible canonical sum
        //
        // (P-1) + (P-1)
        //
        // result = P-2
        //-------------------------------------//

        run_test(
            FIELD_P - 1,
            FIELD_P - 1,
            "(P-1)+(P-1)",
            0
        );


        //==================================================//
        //              CARRY TESTS                         //
        //==================================================//

        //-------------------------------------//
        // Carry limb 0 -> limb 1
        //-------------------------------------//

        run_test(
            256'h00000000000000000000000000000000000000000000000000000000FFFFFFFF,
            256'd1,
            "carry limb0->1",
            0
        );


        //-------------------------------------//
        // Carry across two limbs
        //-------------------------------------//

        run_test(
            256'h000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF,
            256'd1,
            "carry 64-bit",
            0
        );


        //-------------------------------------//
        // Carry across four limbs
        //-------------------------------------//

        run_test(
            256'h00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            256'd1,
            "carry 128-bit",
            0
        );


        //-------------------------------------//
        // Long carry chain
        //-------------------------------------//

        run_test(
            256'h00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            256'd1,
            "long carry chain",
            0
        );


        //==================================================//
        //            DATA_VALID STALL TESTS                //
        //==================================================//

        run_test(
            256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
            256'h1111111111111111111111111111111111111111111111111111111111111111,
            "input stalls",
            4
        );


        run_test(
            FIELD_P - 1,
            256'd1,
            "SUM=P with stalls",
            5
        );


        //==================================================//
        //                  RANDOM                          //
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

            //-------------------------------------//
            // Random tests also use random
            // data_valid stalls.
            //-------------------------------------//

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
        //                 REPORT                           //
        //==================================================//

        $display("");
        $display(
            "============================================================"
        );

        $display(
            "               X25519 FADD TEST REPORT"
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
            "SUM < P           : %0d",
            sum_lt_p_count
        );

        $display(
            "SUM = P           : %0d",
            sum_eq_p_count
        );

        $display(
            "SUM > P           : %0d",
            sum_gt_p_count
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