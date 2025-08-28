const std = @import("std");

pub fn readFile(allocator: std.mem.Allocator, filepath: []const u8) ![]u8 {
    var filepath_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const file_abspath = try std.fs.realpath(filepath, &filepath_buffer);
    const file = try std.fs.openFileAbsolute(file_abspath, .{});
    var buffer: [1024]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    return reader.allocRemaining(allocator, .unlimited);
}

const ModMode = enum(u2) {
    memory_mode_no_displacement_usually = 0b00,
    memory_mode_8_bit_displacement = 0b01,
    memory_mode_16_bit_displacement = 0b10,
    register_mode = 0b11,
};

const Register = enum(u8) {
    AL = 0b00000000,
    CL = 0b00000001,
    DL = 0b00000010,
    BL = 0b00000011,
    AH = 0b00000100,
    CH = 0b00000101,
    DH = 0b00000110,
    BH = 0b00000111,
    AX = 0b00001000,
    CX = 0b00001001,
    DX = 0b00001010,
    BX = 0b00001011,
    SP = 0b00001100,
    BP = 0b00001101,
    SI = 0b00001110,
    DI = 0b00001111,

    pub fn lowercase_repr(register: Register) [2]u8 {
        return switch (register) {
            .AL => "al".*,
            .CL => "cl".*,
            .DL => "dl".*,
            .BL => "bl".*,
            .AH => "ah".*,
            .CH => "ch".*,
            .DH => "dh".*,
            .BH => "bh".*,
            .AX => "ax".*,
            .CX => "cx".*,
            .DX => "dx".*,
            .BX => "bx".*,
            .SP => "sp".*,
            .BP => "bp".*,
            .SI => "si".*,
            .DI => "di".*,
        };
    }
};

const MovRegToReg = struct {
    src: Register,
    dst: Register,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("mov {s}, {s}", .{ this.dst.lowercase_repr(), this.src.lowercase_repr() });
    }
};

const Instruction = union(enum) {
    mov_reg_to_reg: MovRegToReg,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (this) {
            .mov_reg_to_reg => |mov_reg_to_reg| try writer.print("{f}", .{mov_reg_to_reg}),
        }
    }
};

const RegMemToFromRegOpCode = 0b00100010;

const Decoder = struct {
    buffer: []const u8,
    pos: isize,

    pub fn init(instruction_bytes: []const u8) !Decoder {
        if (instruction_bytes.len == 0) {
            return error.InstructionBytesMustBeNonZeroLen;
        }
        return .{
            .buffer = instruction_bytes,
            .pos = -1,
        };
    }

    pub fn nextInstruction(decoder: *Decoder) ?Instruction {
        const first_byte: u8 = decoder.nextByte() catch return null;
        if (first_byte >> 2 == RegMemToFromRegOpCode) {
            return decoder.decodeMovRegMemToFromReg(first_byte);
        }
        return null;
    }

    fn decodeMovRegMemToFromReg(decoder: *Decoder, first_byte: u8) Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            d_bit: u1,
            op_code: u6,
        };
        const fb: FirstByte = @bitCast(first_byte);
        std.debug.assert(fb.op_code == RegMemToFromRegOpCode);

        const second_byte = decoder.nextByte() catch return .{ .mov_reg_to_reg = .{ .src = .AL, .dst = .DL } };
        const SecondByte = packed struct {
            rm: u3,
            reg: u3,
            mod: u2,
        };

        const sb: SecondByte = @bitCast(second_byte);

        std.debug.assert(sb.mod == @intFromEnum(ModMode.register_mode));

        const reg: Register = @enumFromInt((@as(u8, @intCast(fb.w_bit)) << 3) | @as(u8, @intCast(sb.reg)));
        const rm: Register = @enumFromInt((@as(u8, @intCast(fb.w_bit)) << 3) | @as(u8, @intCast(sb.rm)));
        if (fb.d_bit == 0b0) {
            return .{ .mov_reg_to_reg = .{ .src = reg, .dst = rm } };
        } else {
            return .{ .mov_reg_to_reg = .{ .src = rm, .dst = reg } };
        }
    }

    const NextByteError = error{
        EndOfStream,
    };

    fn nextByte(decoder: *Decoder) NextByteError!u8 {
        decoder.pos += 1;
        if (decoder.buffer.len > decoder.pos) {
            return decoder.buffer[@as(usize, @intCast(decoder.pos))];
        }
        return NextByteError.EndOfStream;
    }
};

const Asm16BitsFile = struct {
    file: std.fs.File,
    file_writer: std.fs.File.Writer,

    pub fn init(filepath: []const u8, writer_buffer: []u8) !Asm16BitsFile {
        const file = try std.fs.cwd().createFile(filepath, .{});
        const file_writer = file.writer(writer_buffer);

        var asm_file = Asm16BitsFile{
            .file = file,
            .file_writer = file_writer,
        };
        try asm_file.write_header();

        return asm_file;
    }

    fn write_header(asm_file: *Asm16BitsFile) !void {
        try asm_file.file_writer.interface.print("bits 16\n", .{});
    }

    pub fn deinit(asm_file: *Asm16BitsFile) !void {
        try asm_file.file_writer.interface.flush();
        asm_file.file.close();
    }
};

pub fn main() !void {
    const allocator: std.mem.Allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        std.debug.print("Usage\n\n\tcomputer_enhance <filepath>\n", .{});
        return;
    }

    const input_filepath = args[1];
    const contents = try readFile(allocator, input_filepath);
    defer allocator.free(contents);

    var asm_file_buffer = [_]u8{0} ** 256;
    const asm_filename = try std.fmt.bufPrint(&asm_file_buffer, "{s}_decoded.asm", .{std.fs.path.basename(input_filepath)});
    var asm_file = try Asm16BitsFile.init(asm_filename, &asm_file_buffer);
    defer asm_file.deinit() catch std.debug.print("asm file deinit failed", .{});

    var decoder = try Decoder.init(contents);

    var instruction = decoder.nextInstruction();
    while (instruction != null) : (instruction = decoder.nextInstruction()) {
        try asm_file.file_writer.interface.print("{f}\n", .{instruction.?});
    }
}

test "decode" {
    // first byte mov reg/mem to/from reg, d bit = 0b1 => reg is dst, w bit is 0b1 => wide registers
    // mod = 0b11 -> reg to reg mov, reg = 0b010 => so wide reg is DX, rm = 0b101 => so wide reg is BP
    const data: [2]u8 = .{ 0b10001011, 0b11010101 };

    const expected_instruction = Instruction{ .mov_reg_to_reg = .{ .src = .BP, .dst = .DX } };

    var decoder = try Decoder.init(&data);
    const decoded_instruction = decoder.nextInstruction();
    try std.testing.expect(decoded_instruction != null);
    try std.testing.expectEqual(expected_instruction, decoded_instruction.?);
}
