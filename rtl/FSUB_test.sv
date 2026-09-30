`timescale 1 ns / 1 ps

//==========================================================//
//              X25519 FIELD SUBTRACTION                   //
//==========================================================//
//
// R = (A - B) mod p
//
// p = 2^255 - 19
//
// 256-bit field element
// 8 x 32-bit limbs
//
// limb 0 = [31:0]       LSW
// ...
// limb 7 = [255:224]    MSW
//
// Assumption:
//
//      0 <= A < p
//      0 <= B < p
//
// Algorithm:
//
//      DIFF = A - B
//
//      if (A >= B)
//          R = DIFF
//
//      else
//          R = DIFF + p
//
//==========================================================//

module FSub_25519 (

    input  logic        clk_i,
    input  logic        rst_ni,

    // Start one complete field subtraction:
    // R = (A - B) mod p
    input  logic        start_i,

    // ------------------------------------------------------------
    // Input limb from shared BRAM / register file
    // ------------------------------------------------------------
    input  logic [31:0] opa_i,
    input  logic [31:0] opb_i,

    // Indicates opa_i/opb_i are valid for src_limb_o
    input  logic        data_valid_i,

    // Which 32-bit limb FSUB is requesting: 0 ... 7
    output logic [2:0]  src_limb_o,

    // ------------------------------------------------------------
    // 32-bit streamed result
    // ------------------------------------------------------------
    output logic [31:0] result_o,

    // Which result limb is currently output
    output logic [2:0]  dst_limb_o,

    output logic        result_valid_o,

    // ------------------------------------------------------------
    // Complete 256-bit result
    // ------------------------------------------------------------
    output logic [255:0] result_full_o,

    // ------------------------------------------------------------
    // Control / status
    // ------------------------------------------------------------
    output logic        busy_o,
    output logic        done_o
);


    //======================================================//
    //                     FSM                              //
    //======================================================//
    //
    // IDLE
    //   |
    //   v
    // SUB     : A - B
    //   |
    //   v
    // MOD     : DIFF + p
    //   |
    //   v
    // OUT     : Output final result
    //
    //======================================================//

    typedef enum logic [1:0] {

        ST_IDLE = 2'd0,
        ST_SUB  = 2'd1,
        ST_MOD  = 2'd2,
        ST_OUT  = 2'd3

    } state_t;

    state_t state_r;


    //======================================================//
    //                INTERNAL STORAGE                      //
    //======================================================//

    //-------------------------------------//
    // Raw subtraction result:
    //
    //      DIFF = A - B
    //
    // If A < B, this contains the
    // 256-bit wrapped result.
    //-------------------------------------//

    logic [31:0] diff_mem [0:7];


    //-------------------------------------//
    // Modular correction candidate:
    //
    //      MOD = DIFF + p
    //-------------------------------------//

    logic [31:0] mod_mem [0:7];


    //-------------------------------------//
    // Final canonical 256-bit result
    //-------------------------------------//

    logic [255:0] result_r;


    //======================================================//
    //                 LIMB COUNTER                         //
    //======================================================//

    logic [2:0] limb_r;


    //======================================================//
    //             CARRY / BORROW                           //
    //======================================================//

    //-------------------------------------//
    // Borrow chain for:
    //
    //      A - B
    //-------------------------------------//

    logic borrow_r;


    //-------------------------------------//
    // Carry chain for:
    //
    //      DIFF + p
    //-------------------------------------//

    logic carry_r;


    //-------------------------------------//
    // Final borrow of complete A - B
    //
    // 0 -> A >= B
    // 1 -> A < B
    //-------------------------------------//

    logic diff_borrow_r;


    //-------------------------------------//
    // Final carry of DIFF + p
    //
    // Kept mainly for debug/verification.
    //-------------------------------------//

    logic mod_carry_r;


    //======================================================//
    //                FIELD PRIME                           //
    //======================================================//
    //
    // p = 2^255 - 19
    //
    // 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    //
    // Limb order, LSW first:
    //
    // p[0] = FFFFFFED
    // p[1] = FFFFFFFF
    // ...
    // p[6] = FFFFFFFF
    // p[7] = 7FFFFFFF
    //
    //======================================================//

    logic [31:0] p_word_w;

    always_comb begin

        case (limb_r)

            3'd0:
                p_word_w = 32'hFFFF_FFED;

            3'd1:
                p_word_w = 32'hFFFF_FFFF;

            3'd2:
                p_word_w = 32'hFFFF_FFFF;

            3'd3:
                p_word_w = 32'hFFFF_FFFF;

            3'd4:
                p_word_w = 32'hFFFF_FFFF;

            3'd5:
                p_word_w = 32'hFFFF_FFFF;

            3'd6:
                p_word_w = 32'hFFFF_FFFF;

            3'd7:
                p_word_w = 32'h7FFF_FFFF;

            default:
                p_word_w = 32'd0;

        endcase

    end


    //======================================================//
    //               32-BIT SUBTRACTOR                      //
    //======================================================//
    //
    // One 32-bit subtraction per valid input limb:
    //
    //      A[i] - B[i] - borrow
    //
    //======================================================//

    logic [31:0] sub_result_w;

    logic [32:0] sub_rhs_w;

    logic        sub_borrow_w;


    //-------------------------------------//
    // 32-bit subtraction result
    //-------------------------------------//

    assign sub_result_w =
        opa_i
        -
        opb_i
        -
        borrow_r;


    //-------------------------------------//
    // RHS:
    //
    //      B + borrow_in
    //
    // 33-bit so overflow cannot be lost.
    //-------------------------------------//

    assign sub_rhs_w =
        {1'b0, opb_i}
        +
        {32'd0, borrow_r};


    //-------------------------------------//
    // Borrow detection
    //
    // borrow = 1 if:
    //
    //      A < B + borrow_in
    //-------------------------------------//

    assign sub_borrow_w = {1'b0, opa_i} < sub_rhs_w;


    //======================================================//
    //                  32-BIT ADDER                        //
    //======================================================//
    //
    // Used for modular correction:
    //
    //      DIFF[i] + P[i] + carry
    //
    //======================================================//

    logic [32:0] add_ext_w;

    logic [31:0] add_result_w;

    logic        add_carry_w;


    assign add_ext_w =
        {1'b0, diff_mem[limb_r]}
        +
        {1'b0, p_word_w}
        +
        {32'd0, carry_r};


    assign add_result_w = add_ext_w[31:0];


    assign add_carry_w = add_ext_w[32];


    //======================================================//
    //                     STATUS                           //
    //======================================================//

    assign busy_o = (state_r != ST_IDLE);


    //======================================================//
    //                SOURCE LIMB                           //
    //======================================================//
    //
    // FSUB requests external operand limbs only
    // during ST_SUB.
    //
    //======================================================//

    always_comb begin

        if (state_r == ST_SUB)

            src_limb_o = limb_r;

        else

            src_limb_o = 3'd0;

    end


    //======================================================//
    //              COMPLETE RESULT                         //
    //======================================================//

    assign result_full_o = result_r;


    //======================================================//
    //               STREAMED OUTPUT                        //
    //======================================================//

    always_comb begin

        result_o       = 32'd0;
        dst_limb_o     = 3'd0;

        result_valid_o = 1'b0;
        done_o         = 1'b0;


        //-------------------------------------//
        // Output one final result limb
        // every clock during ST_OUT
        //-------------------------------------//

        if (state_r == ST_OUT) begin

            dst_limb_o = limb_r;


            result_o = result_r[limb_r*32 +: 32];


            result_valid_o = 1'b1;


            //---------------------------------//
            // Last output limb
            //---------------------------------//

            if (limb_r == 3'd7)

                done_o = 1'b1;

        end

    end


    //======================================================//
    //                     CONTROL                          //
    //======================================================//

    integer i;

    always_ff @(posedge clk_i or negedge rst_ni) begin

        if (!rst_ni) begin

            state_r <= ST_IDLE;

            limb_r <= 3'd0;

            borrow_r <= 1'b0;
            carry_r  <= 1'b0;

            diff_borrow_r <= 1'b0;
            mod_carry_r   <= 1'b0;

            result_r <= 256'd0;


            //---------------------------------//
            // Clear internal storage
            //---------------------------------//

            for (i = 0; i < 8; i = i + 1) begin

                diff_mem[i] <= 32'd0;
                mod_mem[i]  <= 32'd0;

            end

        end


        else begin

            case (state_r)


                //======================================//
                //                IDLE                  //
                //======================================//

                ST_IDLE: begin

                    if (start_i) begin

                        //---------------------------------//
                        // Start from LSW
                        //---------------------------------//

                        limb_r <= 3'd0;

                        borrow_r <= 1'b0;
                        carry_r  <= 1'b0;

                        diff_borrow_r <= 1'b0;
                        mod_carry_r   <= 1'b0;

                        state_r <= ST_SUB;

                    end

                end


                //======================================//
                //                 SUB                  //
                //======================================//
                //
                // One input limb per data_valid_i.
                //
                //      DIFF[i]
                //
                //      = A[i]
                //      - B[i]
                //      - borrow
                //
                //======================================//

                ST_SUB: begin

                    if (data_valid_i) begin

                        //---------------------------------//
                        // Save raw subtraction limb
                        //---------------------------------//

                        diff_mem[limb_r] <= sub_result_w;


                        //---------------------------------//
                        // Last limb?
                        //---------------------------------//

                        if (limb_r == 3'd7) begin

                            //---------------------------------//
                            // Save final borrow:
                            //
                            // 0 -> A >= B
                            // 1 -> A < B
                            //---------------------------------//

                            diff_borrow_r <= sub_borrow_w;


                            //---------------------------------//
                            // Prepare correction stage
                            //---------------------------------//

                            limb_r <= 3'd0;

                            borrow_r <= 1'b0;
                            carry_r  <= 1'b0;

                            state_r <= ST_MOD;

                        end

                        else begin

                            //---------------------------------//
                            // Borrow -> next limb
                            //---------------------------------//

                            borrow_r <= sub_borrow_w;


                            limb_r <= limb_r + 3'd1;

                        end

                    end

                end


                //======================================//
                //                 MOD                  //
                //======================================//
                //
                // Build correction candidate:
                //
                //      MOD = DIFF + p
                //
                // This stage is always executed so that
                // latency does not depend on A >= B.
                //
                //======================================//

                ST_MOD: begin

                    //---------------------------------//
                    // Store current corrected limb
                    //---------------------------------//

                    mod_mem[limb_r] <= add_result_w;


                    //---------------------------------//
                    // Last limb?
                    //---------------------------------//

                    if (limb_r == 3'd7) begin

                        //---------------------------------//
                        // Save final carry
                        //---------------------------------//

                        mod_carry_r <= add_carry_w;


                        //=================================//
                        // BUILD FINAL 256-BIT RESULT
                        //=================================//
                        //
                        // diff_borrow_r = 0
                        //
                        //      A >= B
                        //
                        //      result = A - B
                        //
                        //
                        // diff_borrow_r = 1
                        //
                        //      A < B
                        //
                        //      result = A - B + p
                        //
                        //=================================//

                        if (diff_borrow_r) begin

                            //---------------------------------//
                            // A < B
                            //
                            // Use corrected result.
                            //
                            // mod_mem[7] has not yet updated
                            // because of non-blocking <=,
                            // therefore use add_result_w
                            // directly for limb 7.
                            //---------------------------------//

                            result_r <= {

                                add_result_w,
                                mod_mem[6],
                                mod_mem[5],
                                mod_mem[4],
                                mod_mem[3],
                                mod_mem[2],
                                mod_mem[1],
                                mod_mem[0]

                            };

                        end

                        else begin

                            //---------------------------------//
                            // A >= B
                            //
                            // Raw subtraction is already
                            // canonical because:
                            //
                            // 0 <= A-B < p
                            //---------------------------------//

                            result_r <= {

                                diff_mem[7],
                                diff_mem[6],
                                diff_mem[5],
                                diff_mem[4],
                                diff_mem[3],
                                diff_mem[2],
                                diff_mem[1],
                                diff_mem[0]

                            };

                        end


                        //---------------------------------//
                        // Prepare output stage
                        //---------------------------------//

                        limb_r <= 3'd0;

                        carry_r <= 1'b0;

                        state_r <= ST_OUT;

                    end

                    else begin

                        //---------------------------------//
                        // Carry -> next limb
                        //---------------------------------//

                        carry_r <= add_carry_w;


                        limb_r <= limb_r + 3'd1;

                    end

                end


                //======================================//
                //               OUTPUT                 //
                //======================================//

                ST_OUT: begin

                    if (limb_r == 3'd7) begin

                        //---------------------------------//
                        // Final output limb
                        //---------------------------------//

                        limb_r <= 3'd0;

                        state_r <= ST_IDLE;

                    end

                    else begin

                        //---------------------------------//
                        // Next output limb
                        //---------------------------------//

                        limb_r <= limb_r + 3'd1;

                    end

                end


                //======================================//
                //               DEFAULT                //
                //======================================//

                default: begin

                    state_r <= ST_IDLE;

                    limb_r <= 3'd0;

                    borrow_r <= 1'b0;
                    carry_r  <= 1'b0;

                end

            endcase

        end

    end


    //======================================================//
    //               OPTIONAL ASSERTION                     //
    //======================================================//

`ifndef SYNTHESIS

    //-------------------------------------//
    // For canonical A,B:
    //
    // If A < B:
    //
    // DIFF = 2^256 + A - B
    //
    // DIFF + p
    //
    // = 2^256 + (A - B + p)
    //
    // therefore final carry should be 1.
    //
    // If A >= B:
    //
    // DIFF < p
    //
    // DIFF + p < 2p < 2^256
    //
    // therefore final carry should be 0.
    //
    // So:
    //
    //      add_carry_w == diff_borrow_r
    //
    //-------------------------------------//

    always_ff @(posedge clk_i) begin

        if (
            rst_ni
            &&
            state_r == ST_MOD
            &&
            limb_r == 3'd7
        ) begin

            assert (
                add_carry_w
                ==
                diff_borrow_r
            )

            else
                $error(
                    "FSUB ERROR: final correction carry ",
                    "does not match original subtraction borrow."
                );

        end

    end

`endif

endmodule