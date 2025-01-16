const std = @import("std");
const bit_set = std.bit_set;

const Allocator = std.mem.Allocator;

const Reg = enum(u4) {
    AL = 0b0000,
    CL = 0b0001,
    DL = 0b0010,
    BL = 0b0011,
    AH = 0b0100,
    CH = 0b0101,
    DH = 0b0110,
    BH = 0b0111,
    AX = 0b1000,
    CX = 0b1001,
    DX = 0b1010,
    BX = 0b1011,
    SP = 0b1100,
    BP = 0b1101,
    SI = 0b1110,
    DI = 0b1111,
};

const Mod = enum(u2) {
    MEM_NO_DISP = 0b00,
    MEM_8BIT_DISP = 0b01,
    MEM_16BIT_DISP = 0b10,
    REG = 0b11,
};

const Reg2RegMove = struct {
    src: Reg,
    dest: Reg,
};

const CpuOp = union(enum) {
    r2r_move: Reg2RegMove,
    eof: void,
};

const DecodeFailure = error{
    NoMatchingOp,
    UnexpectedEndByte,
};

const BytecodeLexer = struct {
    bytestream: []const u8,
    byte: u8,
    pos: u8,
    read_pos: u8,

    pub fn init(bytes: []const u8) BytecodeLexer {
        var lexer = BytecodeLexer{
            .bytestream = bytes,
            .byte = 0,
            .pos = 0,
            .read_pos = 0,
        };
        lexer.readByte();
        return lexer;
    }

    fn readByte(self: *BytecodeLexer) void {
        if (self.read_pos >= self.bytestream.len) {
            self.byte = 0;
            return;
        }
        self.byte = self.bytestream[self.read_pos];
        self.pos = self.read_pos;
        self.read_pos += 1;
    }

    pub fn nextCpuOp(self: *BytecodeLexer) DecodeFailure!CpuOp {
        if (self.byte == 0) {
            const cpu_op: CpuOp = .eof;
            return cpu_op;
        }
        const op_code: u8 = self.byte >> 2;
        if ((op_code & @intFromEnum(OpCode.MOV_REGMEM_TOFROM_REG)) != 0) {
            return self.decodeMoveRegMemToFromReg();
        } else {
            return DecodeFailure.NoMatchingOp;
        }
    }

    fn decodeMoveRegMemToFromReg(self: *BytecodeLexer) DecodeFailure!CpuOp {
        const low_byte: u8 = self.peekByte();

        const ModMask: u8 = 0b11000000;
        const mod: u2 = @truncate((low_byte & ModMask) >> 6);
        if (mod == @intFromEnum(Mod.REG)) {
            return self.decodeMoveRegToReg();
        }
        return DecodeFailure.NoMatchingOp;
    }

    fn decodeMoveRegToReg(self: *BytecodeLexer) DecodeFailure!CpuOp {
        //     Intel 8086/8088 Instruction Decode
        // ---------------------------------------------
        // |    FIRST BYTE       |     SECOND BYTE     |
        // ---------------------------------------------
        // |   OPCODE    | D | W | MOD |  REG  |  R/M  |
        // ---------------------------------------------
        // | 7 6 5 4 3 2 | 1 | 0 | 7 6 | 5 4 3 | 2 1 0 |
        // ---------------------------------------------
        //
        // Notes:
        // R/M: register/memory
        // D = 1 --> REG is the destination, R/M is the source
        // D = 0 --> R/M is the destination, REG is the source
        //
        // W distinguishes between byte and word operation, 0 = byte op, 1 = word op
        //
        const high_byte = self.byte;
        self.readByte();
        const low_byte = self.byte;
        self.readByte();

        const DMask = 0b00000010;
        const WMask = 0b00000001;

        const d: u1 = @truncate((high_byte & DMask) >> 1);
        const w: u1 = @truncate(high_byte & WMask);

        const RegMask: u8 = 0b00111000;
        const RMMask: u8 = 0b00000111;

        const reg_field: u3 = @truncate((low_byte & RegMask) >> 3);
        const rm_field: u3 = @truncate((low_byte & RMMask));

        const rm_reg: Reg = @enumFromInt(@as(u4, (@as(u4, w) << 3) | @as(u4, rm_field)));
        const reg_reg: Reg = @enumFromInt(@as(u4, (@as(u4, w) << 3) | @as(u4, reg_field)));

        if (d == 0) {
            return CpuOp{ .r2r_move = .{
                .src = reg_reg,
                .dest = rm_reg,
            } };
        } else {
            return CpuOp{ .r2r_move = .{
                .src = rm_reg,
                .dest = reg_reg,
            } };
        }
    }

    fn peekByte(self: BytecodeLexer) u8 {
        if (self.read_pos >= self.bytestream.len) {
            return 0;
        }
        return self.bytestream[self.read_pos];
    }
};

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    const args = try std.process.argsAlloc(alloc);

    defer std.process.argsFree(alloc, args);

    if (args.len < 2) return error.ExpectedArgument;

    const input_file = try std.fs.cwd().openFile(args[1], .{ .mode = .read_only });
    defer input_file.close();
    const reader = input_file.reader();
    const buffer = try reader.readAllAlloc(alloc, 2);
    defer alloc.free(buffer);

    var output_file = try std.fs.cwd().createFile("output.asm", .{ .read = true });
    defer output_file.close();
    const asm_writer = output_file.writer();
    _ = try asm_writer.write("bits 16\n");
    var lexer: BytecodeLexer = BytecodeLexer.init(buffer);
    var cpu_op = try lexer.nextCpuOp();
    while (cpu_op != .eof) : (cpu_op = try lexer.nextCpuOp()) {
        const fstr = try to_string(cpu_op.r2r_move, alloc);
        defer alloc.free(fstr);
        _ = try asm_writer.print("{s}\n", .{fstr});
    }
}

//     Intel 8086/8088 Instruction Decode
// ---------------------------------------------
// |    FIRST BYTE       |     SECOND BYTE     |
// ---------------------------------------------
// |   OPCODE    | D | W | MOD |  REG  |  R/M  |
// ---------------------------------------------
// | 7 6 5 4 3 2 | 1 | 0 | 7 6 | 5 4 3 | 2 1 0 |
// ---------------------------------------------
//
// Notes:
// R/M: register/memory
// D = 1 --> REG is the destination, R/M is the source
// D = 0 --> R/M is the destination, REG is the source
//
// W distinguishes between byte and word operation, 0 = byte op, 1 = word op
//
fn to_string(rr_move: Reg2RegMove, alloc: Allocator) ![]u8 {
    const reg_src_upper: []const u8 = @tagName(rr_move.src);
    const reg_dest_upper: []const u8 = @tagName(rr_move.dest);
    var reg_src: []u8 = try alloc.alloc(u8, reg_src_upper.len);
    var reg_dest: []u8 = try alloc.alloc(u8, reg_dest_upper.len);
    defer alloc.free(reg_src);
    defer alloc.free(reg_dest);
    for (reg_src_upper, 0..) |c, i| {
        reg_src[i] = std.ascii.toLower(c);
    }
    for (reg_dest_upper, 0..) |c, i| {
        reg_dest[i] = std.ascii.toLower(c);
    }

    const fstr: []u8 = try alloc.alloc(u8, 100);
    _ = try std.fmt.bufPrint(fstr, "mov {s},{s}", .{ reg_dest, reg_src });
    return fstr;
}

const OpCode = enum(u8) {
    MOV_REGMEM_TOFROM_REG = 0b00100010,
};

test "test reg to reg move printer" {
    const alloc = std.testing.allocator;

    const r2r: Reg2RegMove = .{
        .src = Reg.AL,
        .dest = Reg.CL,
    };

    const fstr = try to_string(r2r, alloc);
    defer alloc.free(fstr);
    try std.testing.expectStringStartsWith(fstr, "mov al,cl");
}

test "test reg to reg move decode" {
    // reg to reg move
    // d = 1 --> reg is dest
    // w = 0 --> 1 byte registers
    // reg = AL
    // rm = BH
    // expected: MOV AL,BH
    const input: [2]u8 = .{ 0b10001010, 0b11000111 };

    const expected = CpuOp{ .r2r_move = .{
        .dest = Reg.AL,
        .src = Reg.BH,
    } };

    var lexer: BytecodeLexer = BytecodeLexer.init(&input);
    const op: CpuOp = try lexer.nextCpuOp();

    try std.testing.expectEqual(expected, op);
}
