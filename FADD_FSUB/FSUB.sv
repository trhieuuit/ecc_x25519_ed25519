`timescale 1 ns / 1 ps

//==========================================================//
//                        FSUB 32                           //
//==========================================================//
module FSUB_32 (
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
    logic [255:0] diff_r;
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
            diff_r   <= 256'd0;
            busy_r   <= 1'b0;
            result_o <= 256'd0;
            valid_o  <= 1'b0;
        end
        else begin
            valid_o <= 1'b0;

            //-------------------------------------//
            //        Subtraction Stage            //
            //-------------------------------------//
            if (!busy_r) begin
                if (start_i) begin

                    if (operand_a_w >= operand_b_w)
                        diff_r <= operand_a_w - operand_b_w;
                    else
                        diff_r <= operand_a_w
                                + FIELD_P
                                - operand_b_w;

                    busy_r <= 1'b1;
                end
            end

            //-------------------------------------//
            //       Modular Reduction Stage       //
            //-------------------------------------//
            else begin
                if (diff_r >= FIELD_P)
                    result_o <= diff_r - FIELD_P;
                else
                    result_o <= diff_r;

                valid_o <= 1'b1;
                busy_r  <= 1'b0;
            end
        end
    end

endmodule