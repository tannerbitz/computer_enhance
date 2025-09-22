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

    pub fn lowercaseRepr(register: Register) [2]u8 {
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

const DirectAddress = struct {
    address: u16,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("[{d}]", .{this.address});
    }
};

const Operand = union(enum) {
    reg: Register,
    effective_address: EffectiveAddress,
    direct_address: DirectAddress,
    immediate: i32, // this has to be a signed 32 bit value because it need to be able to hold the
    // most negative value a 16 bit signed extension value of an 8 bit value can be => -128
    // and it must be able to most the most positive value of a 16 bit unsigned int value

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (this) {
            .reg => |val| try writer.print("{s}", .{val.lowercaseRepr()}),
            .effective_address => |val| try writer.print("{f}", .{val}),
            .direct_address => |val| try writer.print("{f}", .{val}),
            .immediate => |val| try writer.print("{d}", .{val}),
        }
    }

    pub fn hasKnownSize(operand: Operand) bool {
        return switch (operand) {
            .reg => true,

            .effective_address, .direct_address, .immediate => false,
        };
    }
};

const Operation = enum {
    mov,
    add,
    sub,
    cmp,

    pub fn asString(op: Operation) []const u8 {
        switch (op) {
            .mov => return "mov",
            .add => return "add",
            .sub => return "sub",
            .cmp => return "cmp",
        }
    }
};

const Instruction = struct {
    op: Operation,
    src: Operand,
    dst: Operand,
    width: OperationWidth,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        const width_needed = !this.src.hasKnownSize() and !this.dst.hasKnownSize();

        if (width_needed) {
            try writer.print("{s} {s} {f}, {f}", .{ this.op.asString(), this.width.asString(), this.dst, this.src });
        } else {
            try writer.print("{s} {f}, {f}", .{ this.op.asString(), this.dst, this.src });
        }
    }
};

const OperationWidth = enum {
    byte,
    word,

    pub fn asString(this: @This()) *const [4:0]u8 {
        return switch (this) {
            .byte => "byte",
            .word => "word",
        };
    }
};

const EffectiveAddress = struct {
    base_index: EffectiveAddressBaseIndex,
    displacement: i16,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        if (this.displacement == 0) {
            try writer.print("[{f}]", .{this.base_index});
        } else if (this.displacement > 0) {
            try writer.print("[{f} + {d}]", .{ this.base_index, this.displacement });
        } else {
            try writer.print("[{f} - {d}]", .{ this.base_index, @abs(this.displacement) });
        }
    }
};

const EffectiveAddressBaseIndex = enum(u3) {
    bx_si = 0b000,
    bx_di = 0b001,
    bp_si = 0b010,
    bp_di = 0b011,
    si = 0b100,
    di = 0b101,
    bp = 0b110,
    bx = 0b111,

    pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (this) {
            .bx_si => try writer.print("bx + si", .{}),
            .bx_di => try writer.print("bx + di", .{}),
            .bp_si => try writer.print("bp + si", .{}),
            .bp_di => try writer.print("bp + di", .{}),
            .si => try writer.print("si", .{}),
            .di => try writer.print("di", .{}),
            .bp => try writer.print("bp", .{}),
            .bx => try writer.print("bx", .{}),
        }
    }
};

const MovRegMemToFromRegOpCode = 0b00100010;
const MovImmediateToRegOpCode = 0b1011;
const MovImmediateToRegOrMemOpCode = 0b1100011;
const MovMemoryToAccumulatorOpCode = 0b1010000;
const MovAccumulatorToMemoryOpCode = 0b1010001;

const AddRegMemWithRegToEitherOpCode = 0b000000;
const CommonImmediateToRegMemOpCode = 0b100000;
const AddImmediateToAccumulatorOpCode = 0b0000010;

const SubRegMemWithRegToEitherOpCode = 0b001010;
const SubImmediateFromAccumulatorOpCode = 0b0010110;

const CmpRegMemAndRegOpCode = 0b001110;
const CmpImmediateAndAccumulatorOpCode = 0b0011110;

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

    pub fn nextInstruction(decoder: *Decoder) !?Instruction {
        const first_byte: u8 = decoder.nextByte() catch return null;
        // mov
        if (first_byte >> 2 == MovRegMemToFromRegOpCode) {
            return try decoder.decodeMovRegMemToFromReg(first_byte);
        }
        if (first_byte >> 4 == MovImmediateToRegOpCode) {
            return try decoder.decodeMovImmediateToReg(first_byte);
        }
        if (first_byte >> 1 == MovImmediateToRegOrMemOpCode) {
            return try decoder.decodeMovImmediateToRegOrMem(first_byte);
        }
        if (first_byte >> 1 == MovMemoryToAccumulatorOpCode) {
            return try decoder.decodeMovMemoryToAccumulator(first_byte);
        }
        if (first_byte >> 1 == MovAccumulatorToMemoryOpCode) {
            return try decoder.decodeMovAccumulatorToMemory(first_byte);
        }

        // add
        if (first_byte >> 2 == AddRegMemWithRegToEitherOpCode) {
            return try decoder.decodeAddRegMemWithRegToEither(first_byte);
        }
        if (first_byte >> 2 == CommonImmediateToRegMemOpCode) {
            return try decoder.decodeImmediateToRegMemCommon(first_byte);
        }
        if (first_byte >> 1 == AddImmediateToAccumulatorOpCode) {
            return try decoder.decodeAddImmediateToAccumulator(first_byte);
        }

        // sub
        if (first_byte >> 2 == SubRegMemWithRegToEitherOpCode) {
            return try decoder.decodeSubRegMemWithRegToEither(first_byte);
        }
        if (first_byte >> 1 == SubImmediateFromAccumulatorOpCode) {
            return try decoder.decodeSubImmediateFromAccumulator(first_byte);
        }

        // cmp
        if (first_byte >> 2 == CmpRegMemAndRegOpCode) {
            return try decoder.decodeCmpRegMemAndMem(first_byte);
        }
        if (first_byte >> 1 == CmpImmediateAndAccumulatorOpCode) {
            return try decoder.decodeCmpImmediateAndAccumulator(first_byte);
        }

        return error.NoOpCodeMatch;
    }

    fn decodeCmpImmediateAndAccumulator(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            op_code: u7,
        };

        const fb: FirstByte = @bitCast(first_byte);
        const is_wide: bool = (fb.w_bit == 0b1);

        const immediate_low_byte: u16 = @as(u16, try decoder.nextByte());
        var immediate: i32 = undefined;
        if (is_wide) {
            const immediate_high_byte: u16 = @as(u16, try decoder.nextByte()) << 8;
            immediate = @intCast(immediate_high_byte | immediate_low_byte);
        } else {
            immediate = @intCast(immediate_low_byte);
        }

        return .{
            .op = .cmp,
            .dst = .{ .reg = if (is_wide) .AX else .AL },
            .src = .{ .immediate = immediate },
            .width = if (is_wide) .word else .byte,
        };
    }

    fn decodeImmediateToRegMemCommon(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            s_bit: u1,
            op_code: u6,
        };

        const fb: FirstByte = @bitCast(first_byte);

        const is_wide: bool = (fb.w_bit == 0b1);
        const needs_sign_extension = is_wide and fb.s_bit == 0b1;

        const SecondByte = packed struct {
            rm: u3,
            op_constant: u3,
            mod: u2,
        };
        const second_byte = try decoder.nextByte();
        const sb: SecondByte = @bitCast(second_byte);

        const dst_operand = try decoder.decodeRegMemCommon(fb.w_bit, sb.mod, sb.rm);

        var immediate: i32 = undefined;
        const immediate_low_byte = try decoder.nextByte();
        if (!is_wide) {
            immediate = @intCast(immediate_low_byte);
        } else {
            if (needs_sign_extension) {
                immediate = @intCast(signExtend8BitDisplacement(immediate_low_byte));
            } else {
                const immediate_high_byte: u16 = @as(u16, try decoder.nextByte()) << 8;
                const immediate_unsigned: u16 = immediate_high_byte | @as(u16, immediate_low_byte);
                immediate = @intCast(immediate_unsigned);
            }
        }

        const op: Operation = switch (sb.op_constant) {
            0b000 => .add,
            0b101 => .sub,
            0b111 => .cmp,
            else => unreachable,
        };

        return Instruction{
            .op = op,
            .dst = dst_operand,
            .src = .{ .immediate = immediate },
            .width = if (is_wide) .word else .byte,
        };
    }

    fn decodeSubImmediateFromAccumulator(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeImmediateToAccumulatorCommon(first_byte);
        instruction.op = .sub;
        return instruction;
    }

    fn decodeAddImmediateToAccumulator(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeImmediateToAccumulatorCommon(first_byte);
        instruction.op = .add;
        return instruction;
    }

    fn decodeImmediateToAccumulatorCommon(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            op_code: u7,
        };
        const fb: FirstByte = @bitCast(first_byte);
        const is_wide = fb.w_bit == 0b1;

        var immediate: i32 = undefined;
        const immediate_low_byte: u8 = try decoder.nextByte();
        if (is_wide) {
            const immediate_high_byte: u8 = try decoder.nextByte();
            immediate = @intCast(@as(u16, @intCast(immediate_high_byte)) << 8 | @as(u16, immediate_low_byte));
        } else {
            immediate = @intCast(immediate_low_byte);
        }

        return .{
            .op = undefined,
            .dst = .{ .reg = if (is_wide) .AX else .AL },
            .src = .{ .immediate = immediate },
            .width = if (is_wide) .word else .byte,
        };
    }

    fn decodeMovAccumulatorToMemory(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            op_code: u7,
        };
        const fb: FirstByte = @bitCast(first_byte);
        std.debug.assert(fb.op_code == MovAccumulatorToMemoryOpCode);
        const is_wide = fb.w_bit == 0b1;

        const address_low_byte: u8 = try decoder.nextByte();
        if (is_wide) {
            const address_high_byte: u8 = try decoder.nextByte();
            const address: u16 = @as(u16, @intCast(address_high_byte)) << 8 | @as(u16, @intCast(address_low_byte));
            return Instruction{
                .op = .mov,
                .dst = .{ .direct_address = .{ .address = address } },
                .src = .{ .reg = .AX },
                .width = .word,
            };
        }
        return Instruction{
            .op = .mov,
            .dst = .{ .direct_address = .{ .address = @intCast(address_low_byte) } },
            .src = .{ .reg = .AL },
            .width = .byte,
        };
    }

    fn decodeMovMemoryToAccumulator(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            op_code: u7,
        };
        const fb: FirstByte = @bitCast(first_byte);
        std.debug.assert(fb.op_code == MovMemoryToAccumulatorOpCode);
        const is_wide = fb.w_bit == 0b1;

        const address_low_byte: u8 = try decoder.nextByte();
        if (is_wide) {
            const address_high_byte: u8 = try decoder.nextByte();
            const address: u16 = @as(u16, @intCast(address_high_byte)) << 8 | @as(u16, @intCast(address_low_byte));
            return Instruction{
                .op = .mov,
                .dst = .{ .reg = .AX },
                .src = .{ .direct_address = .{ .address = address } },
                .width = .word,
            };
        }
        return Instruction{
            .op = .mov,
            .dst = .{ .reg = .AL },
            .src = .{ .direct_address = .{ .address = @intCast(address_low_byte) } },
            .width = .byte,
        };
    }

    fn decodeMovImmediateToRegOrMem(decoder: *Decoder, first_byte: u8) !Instruction {
        // this instruction copies a one or two byte immediate value to an effective
        // address. The total instruction length is either 5 or 6 bytes depending on the
        // width of the immediate/effective address to which it will be copied
        // The encoding is as follows:
        // [ 7 bit opcode | 1 bit width ] [ 2 bit mod | 0 0 0 | 3 bit r/m] [ displacement low byte] [ displacement high byte] [ immediate data low byte ] [immediate data high byte (if necessary)]

        const FirstByte = packed struct {
            w_bit: u1,
            op_code: u7,
        };

        const fb: FirstByte = @bitCast(first_byte);
        std.debug.assert(fb.op_code == MovImmediateToRegOrMemOpCode);

        const is_wide: bool = (fb.w_bit == 0b1);

        const SecondByte = packed struct {
            rm: u3,
            op_constant: u3,
            mod: u2,
        };
        const second_byte = try decoder.nextByte();
        const sb: SecondByte = @bitCast(second_byte);
        std.debug.assert(sb.op_constant == 0b000);

        const reg_or_mem = try decoder.decodeRegMemCommon(fb.w_bit, sb.mod, sb.rm);

        var instruction: Instruction = .{
            .op = .mov,
            .dst = reg_or_mem,
            .src = undefined,
            .width = undefined,
        };
        const immediate_low_byte = try decoder.nextByte();
        if (is_wide) {
            const immediate_high_byte = try decoder.nextByte();
            instruction.src = .{
                .immediate = @intCast(@as(u16, @intCast(immediate_high_byte)) << 8 | @as(u16, @intCast(immediate_low_byte))),
            };
            instruction.width = .word;
        } else {
            instruction.src = .{ .immediate = @intCast(immediate_low_byte) };
            instruction.width = .byte;
        }
        return instruction;
    }

    fn signExtend8BitDisplacement(displacement: u8) i16 {
        const sign_bit: u1 = @intCast(displacement >> 7);

        var sign_ext_data: [2]u8 = .{ displacement, 0x00 };
        if (sign_bit == 0b1) {
            sign_ext_data[1] = 0xFF;
        }
        return @bitCast(sign_ext_data);
    }

    fn decodeRegMemCommon(decoder: *Decoder, w_bit: u1, mod: u2, rm: u3) !Operand {
        switch (@as(ModMode, @enumFromInt(mod))) {
            .register_mode => {
                return .{ .reg = @enumFromInt((@as(u8, @intCast(w_bit)) << 3) | @as(u8, @intCast(rm))) };
            },
            .memory_mode_no_displacement_usually => {
                if (rm == 0b110) { // direct addressing
                    const low_byte = try decoder.nextByte();
                    const high_byte = try decoder.nextByte();
                    const direct_address: u16 = @as(u16, @intCast(high_byte)) << 8 | @as(u16, @intCast(low_byte));
                    return .{ .direct_address = .{ .address = direct_address } };
                }
                return .{
                    .effective_address = .{
                        .base_index = @enumFromInt(rm),
                        .displacement = 0,
                    },
                };
            },
            .memory_mode_8_bit_displacement => {
                const displacement: i16 = signExtend8BitDisplacement(try decoder.nextByte());
                return .{
                    .effective_address = .{
                        .base_index = @enumFromInt(rm),
                        .displacement = displacement,
                    },
                };
            },
            .memory_mode_16_bit_displacement => {
                const low_byte = try decoder.nextByte();
                const high_byte = try decoder.nextByte();
                const displacement: i16 = @as(i16, @intCast(high_byte)) << 8 | @as(i16, @intCast(low_byte));
                return .{
                    .effective_address = .{
                        .base_index = @enumFromInt(rm),
                        .displacement = displacement,
                    },
                };
            },
        }
    }

    pub fn decodeAddRegMemWithRegToEither(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeRegMemToFromRegCommon(first_byte);
        instruction.op = .add;
        return instruction;
    }

    pub fn decodeCmpRegMemAndMem(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeRegMemToFromRegCommon(first_byte);
        instruction.op = .cmp;
        return instruction;
    }

    pub fn decodeSubRegMemWithRegToEither(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeRegMemToFromRegCommon(first_byte);
        instruction.op = .sub;
        return instruction;
    }

    fn decodeRegMemToFromRegCommon(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            w_bit: u1,
            d_bit: u1,
            op_code: u6,
        };
        const fb: FirstByte = @bitCast(first_byte);

        const second_byte = try decoder.nextByte();
        const SecondByte = packed struct {
            rm: u3,
            reg: u3,
            mod: u2,
        };

        const sb: SecondByte = @bitCast(second_byte);
        const reg: Operand = .{
            .reg = @enumFromInt((@as(u8, @intCast(fb.w_bit)) << 3) | @as(u8, @intCast(sb.reg))),
        };
        const reg_or_mem = try decoder.decodeRegMemCommon(fb.w_bit, sb.mod, sb.rm);

        var inst: Instruction = .{
            .op = undefined,
            .width = if (fb.w_bit == 0) .byte else .word,
            .src = undefined,
            .dst = undefined,
        };
        if (fb.d_bit == 0b0) {
            inst.dst = reg_or_mem;
            inst.src = reg;
        } else {
            inst.dst = reg;
            inst.src = reg_or_mem;
        }

        return inst;
    }

    fn decodeMovRegMemToFromReg(decoder: *Decoder, first_byte: u8) !Instruction {
        var instruction = try decoder.decodeRegMemToFromRegCommon(first_byte);
        instruction.op = .mov;
        return instruction;
    }

    pub fn decodeMovImmediateToReg(decoder: *Decoder, first_byte: u8) !Instruction {
        const FirstByte = packed struct {
            reg: u3,
            w: u1,
            op_code: u4,
        };
        const fb: FirstByte = @bitCast(first_byte);
        std.debug.assert(fb.op_code == MovImmediateToRegOpCode);

        const reg: Register = @enumFromInt((@as(u8, @intCast(fb.w)) << 3) | @as(u8, @intCast(fb.reg)));
        var instruction = Instruction{
            .op = .mov,
            .dst = .{ .reg = reg },
            .src = undefined,
            .width = undefined,
        };
        switch (fb.w) {
            0b0 => {
                const val = try decoder.nextByte();
                instruction.width = .byte;
                instruction.src = .{ .immediate = signExtend8BitDisplacement(val) };
            },
            0b1 => {
                const immediate_low_byte: u16 = @as(u16, try decoder.nextByte());
                const immediate_high_byte: u16 = @as(u16, try decoder.nextByte()) << 8;
                instruction.width = .word;
                instruction.src = .{ .immediate = @intCast(immediate_high_byte | immediate_low_byte) };
            },
        }
        return instruction;
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
        std.debug.print("Usage\n\n\tdecoder <filepath>\n", .{});
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

    while (try decoder.nextInstruction()) |instruction| {
        try asm_file.file_writer.interface.print("{f}\n", .{instruction});
    }
}
