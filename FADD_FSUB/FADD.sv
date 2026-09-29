`timescale 1 ns / 1 ps

//==========================================================//
//                        FADD 32                           //
//==========================================================//
module FADD_32 (
    input  logic         CLK_i,
    input  logic         RST_i,
    input  logic         start_i,

    input  logic [31:0]  operand_a_i,
    input  logic [31:0]  operand_b_i,

    output logic [255:0] result_o,
    output logic         valid_o
);

    //-------------------------------------//
    //            Parameters               //
    //-------------------------------------//
    localparam logic [255:0] FIELD_P =
        256'h7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;

    //-------------------------------------//
    //         Register Declarations       //
    //-------------------------------------//
    logic [255:0] sum_r;
    logic         busy_r;

    //-------------------------------------//
    //          Wire Declarations          //
    //-------------------------------------//
    logic [255:0] operand_a_w;
    logic [255:0] operand_b_w;

    //-------------------------------------//
    //          Input Extension            //
    //-------------------------------------//
    assign operand_a_w = {224'd0, operand_a_i};
    assign operand_b_w = {224'd0, operand_b_i};

    //-------------------------------------//
    //              Control                //
    //-------------------------------------//
    always_ff @(posedge CLK_i or negedge RST_i) begin
        if (!RST_i) begin
            sum_r    <= 256'd0;
            busy_r   <= 1'b0;
            result_o <= 256'd0;
            valid_o  <= 1'b0;
        end
        else begin
            valid_o <= 1'b0;

            //-------------------------------------//
            //          Addition Stage             //
            //-------------------------------------//
            if (!busy_r) begin
                if (start_i) begin
                    sum_r  <= operand_a_w + operand_b_w;
                    busy_r <= 1'b1;
                end
            end

            //-------------------------------------//
            //       Modular Reduction Stage       //
            //-------------------------------------//
            else begin
                if (sum_r >= FIELD_P)
                    result_o <= sum_r - FIELD_P;
                else
                    result_o <= sum_r;

                valid_o <= 1'b1;
                busy_r  <= 1'b0;
            end
        end
    end

endmodule