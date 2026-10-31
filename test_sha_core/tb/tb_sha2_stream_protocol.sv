`timescale 1ns/1ps
`default_nettype none

// ============================================================================
// Protocol/stress testbench for sha2_stream.
//
// Tests:
//   1. Continuous streaming across several blocks with backpressure.
//   2. Input data/valid remain stable while data_ready_o is low.
//   3. Consecutive SHA-256 and SHA-512 messages without resetting the DUT.
//   4. Reset while the compression core is busy, then recover and hash again.
//   5. Long messages spanning multiple full data blocks.
//
// The testbench intentionally uses a one-byte-per-transfer source. The source
// updates data only after a valid && ready handshake; during a stall it holds
// data_valid and data stable.
// ============================================================================

module tb_sha2_stream_protocol;
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
    integer stall_cycles;
    integer stalls_before_test;

    logic stalled_prev;
    logic [7:0] stalled_data_prev;
    logic digest_valid_prev;

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

    // Protocol monitors. If a transfer was stalled at the previous sampled
    // rising edge, valid must remain high and data must remain unchanged at
    // the next sampled rising edge (unless reset is active).
    always @(posedge clk) begin
        if (!rst_n) begin
            stalled_prev     <= 1'b0;
            stalled_data_prev <= 8'h00;
            digest_valid_prev <= 1'b0;
        end
        else begin
            if (stalled_prev) begin
                if (data_valid !== 1'b1) begin
                    $display("FAIL: data_valid dropped while waiting for data_ready");
                    errors = errors + 1;
                end
                if (data !== stalled_data_prev) begin
                    $display("FAIL: data_i changed while data_ready was low (old=%02h new=%02h)",
                             stalled_data_prev, data);
                    errors = errors + 1;
                end
            end

            if (data_valid && !data_ready)
                stall_cycles = stall_cycles + 1;

            stalled_prev <= data_valid && !data_ready;
            if (data_valid && !data_ready)
                stalled_data_prev <= data;

            if (digest_valid && digest_valid_prev) begin
                $display("FAIL: digest_valid_o was high for more than one cycle");
                errors = errors + 1;
            end
            digest_valid_prev <= digest_valid;
        end
    end

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
            stall_cycles = 0;
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

    function automatic [7:0] pattern_byte(input integer index, input integer pattern_id);
        begin
            case (pattern_id)
                0: pattern_byte = index;          // 00, 01, 02, ... modulo 256
                1: pattern_byte = index * 7 + 3;  // different deterministic pattern
                default: pattern_byte = index ^ 8'hA5;
            endcase
        end
    endfunction

    // Continuous source. It never deasserts valid or changes data in response
    // to a stall; it advances to the next byte only after a handshake.
    task automatic send_pattern_stream(input integer count, input integer pattern_id);
        integer index;
        begin
            index = 0;
            if (count > 0) begin
                @(negedge clk);
                data       = pattern_byte(0, pattern_id);
                data_valid = 1'b1;

                while (index < count) begin
                    @(posedge clk);
                    if (data_valid && data_ready) begin
                        index = index + 1;
                        @(negedge clk);
                        if (index < count) begin
                            data       = pattern_byte(index, pattern_id);
                            data_valid = 1'b1;
                        end
                        else begin
                            data_valid = 1'b0;
                        end
                    end
                    // If not ready, do not assign data or data_valid. They
                    // remain stable until a later handshake.
                end
            end
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

    task automatic check_no_stall_missing(input string test_name, input integer old_stall_count);
        begin
            if (stall_cycles <= old_stall_count) begin
                $display("FAIL: %s did not exercise backpressure", test_name);
                errors = errors + 1;
            end
            else begin
                $display("PASS: %s (observed %0d stalled cycles)",
                         test_name, stall_cycles - old_stall_count);
            end
        end
    endtask

    initial begin
        reset_dut();

        // TEST 1: 200-byte SHA-256 message (three complete data blocks plus a
        // partial block). The source streams continuously through backpressure.
        stalls_before_test = stall_cycles;
        start_message(SHA2_256);
        send_pattern_stream(200, 0);
        finish_message();
        check_digest("SHA-256 200-byte continuous multi-block stream", {
            256'b0,
            256'h1901da1c9f699b48f6b2636e65cbf73abf99d0441ef67f5c540a42f7051dec6f
        });
        check_no_stall_missing("SHA-256 continuous source backpressure", stalls_before_test);

        // TEST 2: Immediately start a second message, with a different mode,
        // without resetting the DUT. This is a 300-byte SHA-512 stream.
        stalls_before_test = stall_cycles;
        start_message(SHA2_512);
        send_pattern_stream(300, 1);
        finish_message();
        check_digest("SHA-512 300-byte continuous multi-block stream",
            512'h46e56ad30db9ef50f8b6762ba55839737f3fba34ab47863c9daff7b3f58f97fe3465a52dd364560db47f802909ced49093322621ea0aebf8e0696b85ca8f81f0);
        check_no_stall_missing("SHA-512 continuous source backpressure", stalls_before_test);
        $display("PASS: consecutive SHA-256 then SHA-512 messages without reset (if digests match)");

        // TEST 3: Abort a message by asserting reset while the compression core
        // is actively processing a full SHA-256 block.
        start_message(SHA2_256);
        send_repeated_byte(64, 8'h5A);
        wait (dut.core_busy_w === 1'b1);
        @(negedge clk);
        rst_n      = 1'b0;
        data_valid = 1'b0;
        finish     = 1'b0;
        start      = 1'b0;
        repeat (3) @(posedge clk);
        @(negedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        if (start_ready !== 1'b1 || busy !== 1'b0 || digest_valid !== 1'b0) begin
            $display("FAIL: reset did not return sha2_stream to a clean idle state");
            errors = errors + 1;
        end
        else begin
            $display("PASS: reset during active compression returns to idle");
        end

        // TEST 4: A fresh message after reset must not inherit the aborted state.
        start_message(SHA2_256);
        send_byte(8'h61);
        send_byte(8'h62);
        send_byte(8'h63);
        finish_message();
        check_digest("SHA-256 abc after mid-compression reset", {
            256'b0,
            256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        });

        if (errors == 0)
            $display("\nALL SHA-2 STREAM PROTOCOL/STRESS TESTS PASSED");
        else
            $display("\nSHA-2 STREAM PROTOCOL/STRESS TESTS FAILED: %0d error(s)", errors);

        $finish;
    end
endmodule

`default_nettype wire
