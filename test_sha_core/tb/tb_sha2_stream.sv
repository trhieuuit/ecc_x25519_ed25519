`timescale 1ns/1ps
`default_nettype none

module tb_sha2_stream;
    import sha2_pkg::*;

    localparam time CLK_PERIOD = 10ns;

    logic clk;
    logic rst_n;
    logic start;
    sha2_mode_t mode;
    logic [7:0] data;
    logic data_valid;
    logic finish;

    wire start_ready;
    wire data_ready;
    wire finish_ready;
    wire busy;
    wire [511:0] digest;
    wire digest_valid;

    integer errors;

    always #(CLK_PERIOD/2) clk = ~clk;

    sha2_stream dut (
        .clk_i          (clk),
        .rst_ni         (rst_n),
        .start_i        (start),
        .start_ready_o  (start_ready),
        .mode_i         (mode),
        .data_i         (data),
        .data_valid_i   (data_valid),
        .data_ready_o   (data_ready),
        .finish_i       (finish),
        .finish_ready_o (finish_ready),
        .busy_o         (busy),
        .digest_o       (digest),
        .digest_valid_o (digest_valid)
    );

    task automatic reset_dut;
        begin
            clk        = 1'b0;
            rst_n      = 1'b0;
            start      = 1'b0;
            mode       = SHA2_256;
            data       = 8'h00;
            data_valid = 1'b0;
            finish     = 1'b0;
            errors     = 0;
            repeat (4) @(posedge clk);
            @(negedge clk);
            rst_n = 1'b1;
            repeat (2) @(posedge clk);
        end
    endtask

    task automatic start_message(input sha2_mode_t selected_mode);
        begin
            @(negedge clk);
            mode  = selected_mode;
            start = 1'b1;
            do @(posedge clk); while (!start_ready);
            @(negedge clk);
            start = 1'b0;
        end
    endtask

    task automatic send_byte(input logic [7:0] value);
        begin
            @(negedge clk);
            data       = value;
            data_valid = 1'b1;
            do @(posedge clk); while (!data_ready);
            @(negedge clk);
            data_valid = 1'b0;
        end
    endtask

    task automatic send_repeated_byte(input integer count, input logic [7:0] value);
        integer i;
        begin
            for (i = 0; i < count; i = i + 1)
                send_byte(value);
        end
    endtask

    task automatic finish_message;
        begin
            @(negedge clk);
            data_valid = 1'b0;
            finish     = 1'b1;
            do @(posedge clk); while (!finish_ready);
            @(negedge clk);
            finish = 1'b0;
            wait (digest_valid === 1'b1);
            #1;
        end
    endtask

    task automatic check_digest(
        input string test_name,
        input logic [511:0] expected
    );
        begin
            if (digest !== expected) begin
                $display("FAIL: %s", test_name);
                $display("  expected = %0128h", expected);
                $display("  actual   = %0128h", digest);
                errors = errors + 1;
            end
            else begin
                $display("PASS: %s", test_name);
            end
        end
    endtask

    initial begin
        reset_dut();

        // Empty message: tests zero-length input and the basic padding path.
        start_message(SHA2_256);
        finish_message();
        check_digest("SHA-256 empty", {
            256'b0,
            256'he3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        });

        start_message(SHA2_512);
        finish_message();
        check_digest("SHA-512 empty",
            512'hcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e);

        // Familiar known-answer tests for "abc".
        start_message(SHA2_256);
        send_byte(8'h61);
        send_byte(8'h62);
        send_byte(8'h63);
        finish_message();
        check_digest("SHA-256 abc", {
            256'b0,
            256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        });

        start_message(SHA2_512);
        send_byte(8'h61);
        send_byte(8'h62);
        send_byte(8'h63);
        finish_message();
        check_digest("SHA-512 abc",
            512'hddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f);

        // Padding boundary tests: 56 bytes for SHA-256 and 112 bytes for
        // SHA-512 require an additional length-only block.
        start_message(SHA2_256);
        send_repeated_byte(56, 8'h61);
        finish_message();
        check_digest("SHA-256 56 x 'a' (two-block padding)", {
            256'b0,
            256'hb35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a
        });

        start_message(SHA2_512);
        send_repeated_byte(112, 8'h61);
        finish_message();
        check_digest("SHA-512 112 x 'a' (two-block padding)",
            512'hc01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca);

        // Exact-block tests: the data block is compressed first, followed by
        // a separate padding block because the message length is block-aligned.
        start_message(SHA2_256);
        send_repeated_byte(64, 8'h61);
        finish_message();
        check_digest("SHA-256 64 x 'a' (exact block)", {
            256'b0,
            256'hffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb
        });

        start_message(SHA2_512);
        send_repeated_byte(128, 8'h61);
        finish_message();
        check_digest("SHA-512 128 x 'a' (exact block)",
            512'hb73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321);

        if (errors == 0)
            $display("\nALL SHA-2 STREAM/PADDING TESTS PASSED");
        else
            $display("\nSHA-2 STREAM/PADDING TESTS FAILED: %0d error(s)", errors);

        $finish;
    end
endmodule

`default_nettype wire
