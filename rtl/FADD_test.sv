`timescale 1 ns / 1 ps

//==========================================================//
//              X25519 FIELD ADDITION                      //
//==========================================================//
//
// R = (A + B) mod p
//
// p = 2^255 - 19
//
// 256-bit field element
// 8 x 32-bit limbs
//
// limb 0 = [31:0]
// ...
// limb 7 = [255:224]
//
//==========================================================//

module FAdd_25519 (

    input  logic        clk_i,
    input  logic        rst_ni,

    input  logic        start_i,

    // ------------------------------------------------------------
    // Input limb
    // ------------------------------------------------------------
    input  logic [31:0] opa_i,
    input  logic [31:0] opb_i,

    input  logic        data_valid_i,

    output logic [2:0]  src_limb_o,

    // ------------------------------------------------------------
    // 32-bit streamed result
    // ------------------------------------------------------------
    output logic [31:0] result_o,
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

    typedef enum logic [1:0] {

        ST_IDLE = 2'd0,
        ST_ADD  = 2'd1,
        ST_MOD  = 2'd2,
        ST_OUT  = 2'd3

    } state_t;

    state_t state_r;


    //======================================================//
    //                INTERNAL STORAGE                      //
    //======================================================//

    // Raw:
    // SUM = A + B
    logic [31:0] sum_mem [0:7];

    // Candidate:
    // MOD = SUM - P
    logic [31:0] mod_mem [0:7];

    // Final 256-bit modular result
    logic [255:0] result_r;


    //======================================================//
    //                 LIMB COUNTER                         //
    //======================================================//

    logic [2:0] limb_r;


    //======================================================//
    //             CARRY / BORROW                           //
    //======================================================//

    logic carry_r;
    logic borrow_r;

    logic sum_carry_r;
    logic mod_borrow_r;


    //======================================================//
    //                FIELD PRIME                           //
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
    //                  32-BIT ADDER                        //
    //======================================================//

    logic [32:0] add_ext_w;

    logic [31:0] add_result_w;
    logic        add_carry_w;

    assign add_ext_w =
        {1'b0, opa_i}
        +
        {1'b0, opb_i}
        +
        {32'd0, carry_r};

    assign add_result_w = add_ext_w[31:0];

    assign add_carry_w = add_ext_w[32];


    //======================================================//
    //               32-BIT SUBTRACTOR                      //
    //======================================================//

    logic [31:0] sub_result_w;

    logic [32:0] sub_rhs_w;

    logic        sub_borrow_w;

    //-------------------------------------//
    // SUM[i] - P[i] - borrow             //
    //-------------------------------------//

    assign sub_result_w =
        sum_mem[limb_r]
        -
        p_word_w
        -
        borrow_r;

    //-------------------------------------//
    // P[i] + borrow                      //
    //-------------------------------------//

    assign sub_rhs_w =
        {1'b0, p_word_w}
        +
        {32'd0, borrow_r};

    //-------------------------------------//
    // Borrow detection                   //
    //-------------------------------------//

    assign sub_borrow_w = {1'b0, sum_mem[limb_r]} < sub_rhs_w;


    //======================================================//
    //                    STATUS                            //
    //======================================================//

    assign busy_o = (state_r != ST_IDLE);


    //======================================================//
    //                SOURCE LIMB                           //
    //======================================================//

    always_comb begin

        if (state_r == ST_ADD)

            src_limb_o = limb_r;

        else

            src_limb_o = 3'd0;

    end


    //======================================================//
    //              COMPLETE RESULT                         //
    //======================================================//

    assign result_full_o = result_r;


    //======================================================//
    //              32-BIT OUTPUT                           //
    //======================================================//

    always_comb begin

        result_o       = 32'd0;
        dst_limb_o     = 3'd0;

        result_valid_o = 1'b0;
        done_o         = 1'b0;

        //-------------------------------------//
        // Stream final result_r              //
        //-------------------------------------//

        if (state_r == ST_OUT) begin

            dst_limb_o = limb_r;

            result_o = result_r[limb_r*32 +: 32];

            result_valid_o = 1'b1;

            //---------------------------------//
            // Last 32-bit limb               //
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

            carry_r  <= 1'b0;
            borrow_r <= 1'b0;

            sum_carry_r  <= 1'b0;
            mod_borrow_r <= 1'b0;

            result_r <= 256'd0;

            for (i = 0; i < 8; i = i + 1) begin

                sum_mem[i] <= 32'd0;
                mod_mem[i] <= 32'd0;

            end

        end

        else begin

            case (state_r)

                //======================================//
                //                IDLE                  //
                //======================================//

                ST_IDLE: begin

                    if (start_i) begin

                        limb_r <= 3'd0;

                        carry_r  <= 1'b0;
                        borrow_r <= 1'b0;

                        sum_carry_r  <= 1'b0;
                        mod_borrow_r <= 1'b0;

                        state_r <= ST_ADD;

                    end

                end


                //======================================//
                //                 ADD                  //
                //======================================//

                ST_ADD: begin

                    if (data_valid_i) begin

                        //---------------------------------//
                        // Store current A+B limb         //
                        //---------------------------------//

                        sum_mem[limb_r] <= add_result_w;

                        //---------------------------------//
                        // Last limb?                     //
                        //---------------------------------//

                        if (limb_r == 3'd7) begin

                            sum_carry_r
                                <= add_carry_w;

                            limb_r <= 3'd0;

                            carry_r  <= 1'b0;
                            borrow_r <= 1'b0;

                            state_r <= ST_MOD;

                        end

                        else begin

                            carry_r <= add_carry_w;

                            limb_r <= limb_r + 3'd1;

                        end

                    end

                end


                //======================================//
                //                 MOD                  //
                //======================================//
                //
                // candidate:
                //
                //      SUM - P
                //
                //======================================//

                ST_MOD: begin

                    //---------------------------------//
                    // Save current MOD limb          //
                    //---------------------------------//

                    mod_mem[limb_r] <= sub_result_w;

                    //---------------------------------//
                    // Final limb                     //
                    //---------------------------------//

                    if (limb_r == 3'd7) begin

                        mod_borrow_r <= sub_borrow_w;


                        //=================================//
                        // BUILD FINAL 256-BIT RESULT     //
                        //=================================//
                        //
                        // sub_borrow = 1
                        //
                        //      SUM < P
                        //
                        //      result = SUM
                        //
                        // sub_borrow = 0
                        //
                        //      SUM >= P
                        //
                        //      result = SUM - P
                        //
                        // Notice:
                        //
                        // mod_mem[7] has NOT yet been
                        // updated because <= is a
                        // non-blocking assignment.
                        //
                        // Therefore use sub_result_w
                        // directly for limb 7.
                        //=================================//

                        if (sub_borrow_w) begin

                            result_r <= {
                                sum_mem[7],
                                sum_mem[6],
                                sum_mem[5],
                                sum_mem[4],
                                sum_mem[3],
                                sum_mem[2],
                                sum_mem[1],
                                sum_mem[0]
                            };

                        end

                        else begin

                            result_r <= {
                                sub_result_w,
                                mod_mem[6],
                                mod_mem[5],
                                mod_mem[4],
                                mod_mem[3],
                                mod_mem[2],
                                mod_mem[1],
                                mod_mem[0]
                            };

                        end


                        //---------------------------------//
                        // Prepare output phase           //
                        //---------------------------------//

                        limb_r <= 3'd0;

                        borrow_r <= 1'b0;

                        state_r <= ST_OUT;

                    end

                    else begin

                        borrow_r <= sub_borrow_w;

                        limb_r <= limb_r + 3'd1;

                    end

                end


                //======================================//
                //               OUTPUT                 //
                //======================================//

                ST_OUT: begin

                    if (limb_r == 3'd7) begin

                        limb_r <= 3'd0;

                        state_r <= ST_IDLE;

                    end

                    else begin

                        limb_r <= limb_r + 3'd1;

                    end

                end


                //======================================//
                //              DEFAULT                 //
                //======================================//

                default: begin

                    state_r <= ST_IDLE;

                    limb_r <= 3'd0;

                    carry_r  <= 1'b0;
                    borrow_r <= 1'b0;

                end

            endcase

        end

    end

endmodule