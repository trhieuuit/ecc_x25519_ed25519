`timescale 1ns/1ps
`default_nettype none

module tb_hmac_sha256;

    localparam time CLK_PERIOD = 10ns;
    localparam integer MAX_WAIT_CYCLES = 50000;

    logic clk;
    logic rst_n;

    logic start;
    wire  start_ready;

    logic [7:0] key;
    logic       key_valid;
    wire        key_ready;
    logic       key_finish;
    wire        key_finish_ready;

    logic [7:0] data;
    logic       data_valid;
    wire        data_ready;
    logic       finish;
    wire        finish_ready;

    wire        busy;
    wire [255:0] hmac;
    wire         hmac_valid;

    integer errors;

    always #(CLK_PERIOD/2) clk = ~clk;

    hmac_sha256 dut (
        .clk_i              (clk),
        .rst_ni             (rst_n),
        .start_i            (start),
        .start_ready_o      (start_ready),
        .key_i              (key),
        .key_valid_i        (key_valid),
        .key_ready_o        (key_ready),
        .key_finish_i       (key_finish),
        .key_finish_ready_o (key_finish_ready),
        .data_i             (data),
        .data_valid_i       (data_valid),
        .data_ready_o       (data_ready),
        .finish_i           (finish),
        .finish_ready_o     (finish_ready),
        .busy_o             (busy),
        .hmac_o             (hmac),
        .hmac_valid_o       (hmac_valid)
    );

    task automatic reset_dut;
        begin
            rst_n      = 1'b0;
            start      = 1'b0;
            key        = 8'h00;
            key_valid  = 1'b0;
            key_finish = 1'b0;
            data       = 8'h00;
            data_valid = 1'b0;
            finish     = 1'b0;
            repeat (4) @(posedge clk);
            @(negedge clk);
            rst_n = 1'b1;
            repeat (2) @(posedge clk);
        end
    endtask

    task automatic start_hmac;
        integer cycles;
        logic accepted;
        begin
            @(negedge clk);
            start    = 1'b1;
            cycles   = 0;
            accepted = 1'b0;
            while ((!accepted) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                if (start_ready === 1'b1)
                    accepted = 1'b1;
                cycles = cycles + 1;
            end
            if (!accepted)
                $fatal(1, "TIMEOUT waiting for start_ready");
            @(negedge clk);
            start = 1'b0;
        end
    endtask

    task automatic send_key_byte(input logic [7:0] value);
        integer cycles;
        logic accepted;
        begin
            @(negedge clk);
            key       = value;
            key_valid = 1'b1;
            cycles    = 0;
            accepted  = 1'b0;
            while ((!accepted) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                if (key_ready === 1'b1)
                    accepted = 1'b1;
                cycles = cycles + 1;
            end
            if (!accepted)
                $fatal(1, "TIMEOUT waiting for key_ready");
            @(negedge clk);
            key_valid = 1'b0;
        end
    endtask

    task automatic end_key;
        integer cycles;
        logic accepted;
        begin
            @(negedge clk);
            key_finish = 1'b1;
            cycles     = 0;
            accepted   = 1'b0;
            while ((!accepted) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                if (key_finish_ready === 1'b1)
                    accepted = 1'b1;
                cycles = cycles + 1;
            end
            if (!accepted)
                $fatal(1, "TIMEOUT waiting for key_finish_ready");
            @(negedge clk);
            key_finish = 1'b0;
        end
    endtask

    task automatic send_data_byte(input logic [7:0] value);
        integer cycles;
        logic accepted;
        begin
            @(negedge clk);
            data       = value;
            data_valid = 1'b1;
            cycles     = 0;
            accepted   = 1'b0;
            while ((!accepted) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                if (data_ready === 1'b1)
                    accepted = 1'b1;
                cycles = cycles + 1;
            end
            if (!accepted)
                $fatal(1, "TIMEOUT waiting for data_ready");
            @(negedge clk);
            data_valid = 1'b0;
        end
    endtask

    task automatic end_message;
        integer cycles;
        logic accepted;
        begin
            @(negedge clk);
            finish   = 1'b1;
            cycles   = 0;
            accepted = 1'b0;
            while ((!accepted) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                if (finish_ready === 1'b1)
                    accepted = 1'b1;
                cycles = cycles + 1;
            end
            if (!accepted)
                $fatal(1, "TIMEOUT waiting for finish_ready");
            @(negedge clk);
            finish = 1'b0;
        end
    endtask

    task automatic wait_and_check(
        input string test_name,
        input logic [255:0] expected
    );
        integer cycles;
        begin
            cycles = 0;
            while ((hmac_valid !== 1'b1) && (cycles < MAX_WAIT_CYCLES)) begin
                @(posedge clk);
                cycles = cycles + 1;
            end
            if (cycles >= MAX_WAIT_CYCLES)
                $fatal(1, "TIMEOUT waiting for hmac_valid");

            #1;
            if (hmac !== expected) begin
                $display("FAIL: %s", test_name);
                $display("  expected = %064h", expected);
                $display("  actual   = %064h", hmac);
                errors = errors + 1;
            end
            else begin
                $display("PASS: %s", test_name);
            end
        end
    endtask

    task automatic send_repeated_key(input integer count, input logic [7:0] value);
        integer i;
        begin
            for (i = 0; i < count; i = i + 1)
                send_key_byte(value);
        end
    endtask

    task automatic send_repeated_data(input integer count, input logic [7:0] value);
        integer i;
        begin
            for (i = 0; i < count; i = i + 1)
                send_data_byte(value);
        end
    endtask

    initial begin
        clk        = 1'b0;
        rst_n      = 1'b0;
        start      = 1'b0;
        key        = 8'h00;
        key_valid  = 1'b0;
        key_finish = 1'b0;
        data       = 8'h00;
        data_valid = 1'b0;
        finish     = 1'b0;
        errors     = 0;

        reset_dut();

        // RFC 4231 Test Case 1
        // key = 20 bytes of 0x0b, data = "Hi There"
        start_hmac();
        send_repeated_key(20, 8'h0b);
        end_key();
        send_data_byte("H");
        send_data_byte("i");
        send_data_byte(" ");
        send_data_byte("T");
        send_data_byte("h");
        send_data_byte("e");
        send_data_byte("r");
        send_data_byte("e");
        end_message();
        wait_and_check("RFC 4231 TC1",
            256'hb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7);

        // RFC 4231 Test Case 2
        // key = "Jefe", data = "what do ya want for nothing?"
        start_hmac();
        send_key_byte("J");
        send_key_byte("e");
        send_key_byte("f");
        send_key_byte("e");
        end_key();
        send_data_byte("w"); send_data_byte("h"); send_data_byte("a"); send_data_byte("t");
        send_data_byte(" "); send_data_byte("d"); send_data_byte("o"); send_data_byte(" ");
        send_data_byte("y"); send_data_byte("a"); send_data_byte(" "); send_data_byte("w");
        send_data_byte("a"); send_data_byte("n"); send_data_byte("t"); send_data_byte(" ");
        send_data_byte("f"); send_data_byte("o"); send_data_byte("r"); send_data_byte(" ");
        send_data_byte("n"); send_data_byte("o"); send_data_byte("t"); send_data_byte("h");
        send_data_byte("i"); send_data_byte("n"); send_data_byte("g"); send_data_byte("?");
        end_message();
        wait_and_check("RFC 4231 TC2",
            256'h5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843);

        // RFC 4231 Test Case 3
        // key = 20 bytes of 0xaa, data = 50 bytes of 0xdd.
        start_hmac();
        send_repeated_key(20, 8'haa);
        end_key();
        send_repeated_data(50, 8'hdd);
        end_message();
        wait_and_check("RFC 4231 TC3",
            256'h773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe);

        // RFC 4231 Test Case 6: verifies key_len > 64 byte normalization.
        // key = 131 bytes of 0xaa.
        start_hmac();
        send_repeated_key(131, 8'haa);
        end_key();
        // "Test Using Larger Than Block-Size Key - Hash Key First"
        send_data_byte("T"); send_data_byte("e"); send_data_byte("s"); send_data_byte("t");
        send_data_byte(" "); send_data_byte("U"); send_data_byte("s"); send_data_byte("i");
        send_data_byte("n"); send_data_byte("g"); send_data_byte(" "); send_data_byte("L");
        send_data_byte("a"); send_data_byte("r"); send_data_byte("g"); send_data_byte("e");
        send_data_byte("r"); send_data_byte(" "); send_data_byte("T"); send_data_byte("h");
        send_data_byte("a"); send_data_byte("n"); send_data_byte(" "); send_data_byte("B");
        send_data_byte("l"); send_data_byte("o"); send_data_byte("c"); send_data_byte("k");
        send_data_byte("-"); send_data_byte("S"); send_data_byte("i"); send_data_byte("z");
        send_data_byte("e"); send_data_byte(" "); send_data_byte("K"); send_data_byte("e");
        send_data_byte("y"); send_data_byte(" "); send_data_byte("-"); send_data_byte(" ");
        send_data_byte("H"); send_data_byte("a"); send_data_byte("s"); send_data_byte("h");
        send_data_byte(" "); send_data_byte("K"); send_data_byte("e"); send_data_byte("y");
        send_data_byte(" "); send_data_byte("F"); send_data_byte("i"); send_data_byte("r");
        send_data_byte("s"); send_data_byte("t");
        end_message();
        wait_and_check("RFC 4231 TC6 long key",
            256'h60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54);

        if (errors == 0)
            $display("\nALL HMAC-SHA256 TESTS PASSED");
        else
            $display("\nHMAC-SHA256 TESTS FAILED: %0d error(s)", errors);

        $finish;
    end

endmodule

`default_nettype wire
