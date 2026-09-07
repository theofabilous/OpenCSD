const std = @import("std");
const opencsd = @import("opencsd");
const capstone = @import("capstone");

const Io = std.Io;

pub const TargetQuery = struct {
    cpu_arch: Target.Cpu.Arch,
    cpu_model: ?*const Target.Cpu.Model = null,
    cpu_features_add: Target.Cpu.Feature.Set = .empty,
    cpu_features_sub: Target.Cpu.Feature.Set = .empty,

    pub const Family = enum(@typeInfo(Target.Cpu.Arch.Family).@"enum".tag_type) {
        /// Includes thumb
        arm = @intFromEnum(Target.Cpu.Arch.Family.arm),
        aarch64 = @intFromEnum(Target.Cpu.Arch.Family.aarch64),
    };

    const Target = std.Target;

    fn isValidArch(cpu_arch: Target.Cpu.Arch) bool {
        return switch (cpu_arch.family()) {
            .arm, .aarch64 => true,
            else => false,
        };
    }

    pub fn family(tq: TargetQuery) Family {
        return @enumFromInt(@intFromEnum(tq.cpu_arch.family()));
    }

    /// Convert the `cpu_features_add` and `cpu_features_sub` fields into an
    /// `--mattr=`-style value string.
    pub fn toLlvmAttrs(tq: TargetQuery, list: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
        const all_features: []const Target.Cpu.Feature = switch (tq.family()) {
            inline else => |arch_family| &@field(std.Target, @tagName(arch_family)).all_features,
        };
        for (0..2) |round| {
            const prefix_char: u8, const set: *const std.Target.Cpu.Feature.Set = switch (round) {
                0 => .{ '+', &tq.cpu_features_add },
                1 => .{ '-', &tq.cpu_features_sub },
                else => unreachable,
            };
            for (0.., all_features) |i, *feature| {
                const llvm_name = feature.llvm_name orelse continue;
                const index: std.Target.Cpu.Feature.Set.Index = @intCast(i);
                if (set.isEnabled(index)) {
                    if (list.items.len > 0) try list.append(gpa, ',');
                    try list.append(gpa, prefix_char);
                    try list.appendSlice(gpa, llvm_name);
                }
            }
        }
    }
};

const Context = struct {
    io: Io,
    allocator: std.mem.Allocator,
    terminal: Io.Terminal,
    elf: *opencsd.ElfContext,
};

fn loggerPrint(
    p_context: ?*const anyopaque,
    strp: [*c]const u8,
    str_len: c_int
) callconv(.c) void {
    const ctx: *const Context = @alignCast(@ptrCast(p_context.?));
    if (strp == null) return;
    const str: [:0]const u8 = if (str_len > 0) strp[0..@intCast(str_len):0] else std.mem.span(strp);
    ctx.terminal.writer.writeAll(str) catch {};
}

fn printTraceElemInner(
    ctx: *const Context,
    trcindex: opencsd.trc_index_t,
    chan: u8,
    raw_elem: *const opencsd.generic_trace_elem
) (Io.Writer.Error||Io.Terminal.SetColorError)!void {
    const writer = ctx.terminal.writer;
    defer ctx.terminal.setColor(.reset) catch {};
    try writer.print("Idx:{}; TrcID:0x{X:02}; ", .{trcindex, chan});
    const ws = try writer.writableSliceGreedy(@min(writer.buffer.len, 1024));

    const ret = opencsd.gen_elem_str(raw_elem, ws.ptr, @intCast(ws.len - 2));
    if (ret == opencsd.OK) {
        const n = std.mem.findScalar(u8, ws, 0).?;
        ws[n] = '\n';
        writer.advance(n + 1);
    } else {
        try writer.writeAll("[unable to create elem string]\n");
    }

    const elem: *const opencsd.GenericTraceElement = @alignCast(@ptrCast(raw_elem));
    switch (elem.type) {
        .INSTR_RANGE => x: {
            switch (elem.last_instr_type) {
                .BR, .BR_INDIRECT => {
                    if (elem.flag_bits.last_instr_exec == 1) {
                        try writer.writeAll("  > branch taken\n");
                    } else {
                        try writer.writeAll("  > branch NOT taken\n");
                    }
                },
                else => {},
            }
            const query: opencsd.ElfContext.AddressRangeQuery = .init(.{elem.start_address, elem.end_address});
            const instr_list = (ctx.elf.disassembleAddressRange(query) catch null) orelse break :x;
            defer _ = capstone.cs_free(instr_list.ptr, instr_list.len);
            var max_width: usize = 0;
            for (instr_list) |*instr| max_width = @max(max_width, std.mem.sliceTo(&instr.mnemonic, 0).len);

            for (instr_list) |*instr| {
                try ctx.terminal.setColor(.dim);
                try writer.print("0x{X:08}    ", .{ instr.address });
                try ctx.terminal.setColor(.reset);
                try ctx.terminal.setColor(.bold);
                try ctx.terminal.setColor(.blue);
                try writer.printValue("s", .{
                    .width = max_width + 1,
                    .alignment = .left,
                    .fill = ' ',
                }, std.mem.sliceTo(&instr.mnemonic, 0), 1);
                try ctx.terminal.setColor(.reset);
                try writer.writeByte(' ');
                try writer.writeAll(std.mem.sliceTo(&instr.op_str, 0));
                try writer.writeByte('\n');
            }
            try writer.writeByte('\n');
        },
        else => {},
    }
}

fn printTraceElem(
    p_context: ?*const anyopaque,
    trcindex: opencsd.trc_index_t,
    chan: u8,
    opt_elem: ?*const opencsd.generic_trace_elem
) callconv(.c) opencsd.datapath_resp_t {
    const ctx: *const Context = @alignCast(@ptrCast(p_context.?));
    const elem = opt_elem orelse {
        // ...?
        return opencsd.RESP_CONT;
    };
    printTraceElemInner(ctx, trcindex, chan, elem) catch |err| switch (err) {
        error.WriteFailed => return opencsd.RESP_WARN_CONT,
        error.Unexpected, error.Canceled => return opencsd.RESP_FATAL_SYS_ERR,
    };
    return opencsd.RESP_CONT;
}

fn csTry(e: capstone.cs_err) error{CapstoneError}!void {
    if (e == capstone.CS_ERR_OK) return;
    return error.CapstoneError;
}

pub const CONFIGR = packed struct (u32) {
    _res0: u1 = 0,
    /// Instruction P0 field. Controls whether load and store instructions are traced
    /// as P0 instructions.
    ///
    /// Requires TRCIDR0.INSTP0.
    instp0: INSTP0,
    /// Branch broadcast enable.
    ///
    /// Requires TRCIDR0.TRCBB.
    bb: bool,
    /// Enable cycle counting in instruction trace.
    /// See also TRCCCCTLR for threshold value.
    ///
    /// Requires TRCIDR0.TRCCCI
    cci: bool,
    _res1: u1 = 0,
    /// Enable context ID tracing.
    ///
    /// Requires TRCIDR2.CIDSIZE
    cid: bool,
    /// Enable VID tracing
    vmid: bool,
    cond: COND,
    /// Global timestamp tracing
    ts: bool,
    /// Return stack tracing
    rs: bool,
    /// Q element enable
    qe: QE,
    /// VID selection control
    vmidopt: u1,
    /// Data address tracing
    da: bool,
    /// Data value tracing
    dv: bool,
    _: u14 = 0,

    pub const QE = enum(u2) {
        disabled = 0b00,
        with_instruction_counts = 0b01,
        with_and_without_instruction_counts = 0b11,
    };

    pub const INSTP0 = enum (u2) {
        none = 0b00,
        load = 0b01,
        store = 0b10,
        load_and_store = 0b11,
    };

    pub const COND = packed struct (u3) {
        /// Conditional load instructions are traced
        load: bool,
        /// Conditional store instructions are traced
        store: bool,
        other: bool,

        pub const all: COND = .{ .load = true, .store = true, .other = true };
        pub const none: COND = .{ .load = false, .store = false, .other = false };
    };
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    std.debug.assert(args.len >= 3);
    const trace_bin_path = args[1];
    const program_elf_path = args[2];

    try opencsd.checkError(opencsd.def_errlog_init(opencsd.ERR_SEV_INFO, 1));

    var ret: opencsd.err_t = opencsd.OK;
    _ = &ret;

    const dfmt_flags: opencsd.DecodeTree.DeformatterFlags = .{
        .has_fsyncs = true,
    };
    const dt: opencsd.DecodeTree = try .create(.FRAME_FORMATTED, dfmt_flags);
    defer dt.destroy();

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = Io.File.stdout().writerStreaming(init.io, &stdout_buffer);

    const envEnabled = struct {
        fn call(opt_value: ?[]const u8) ?bool {
            const value = opt_value orelse return null;
            const true_values = [_][]const u8{ "1", "ON", "on", "YES", "yes" };
            const false_values = [_][]const u8{ "0", "OFF", "off", "NO", "no" };
            for (true_values) |tv| if (std.mem.eql(u8, value, tv)) return true;
            for (false_values) |fv| if (std.mem.eql(u8, value, fv)) return false;
            return null;
        }
    }.call;

    const no_color: bool = envEnabled(init.environ_map.get("NOCOLOR")) orelse false;
    const color_force: bool = envEnabled(init.environ_map.get("CLICOLOR_FORCE")) orelse false;
    const terminal: Io.Terminal = .{
        .mode = Io.Terminal.Mode.detect(io, .stdout(), no_color, color_force) catch .no_color,
        .writer = &stdout_file_writer.interface,
    };

    var elf_context: opencsd.ElfContext = try .open(program_elf_path, io, init.gpa, .{});
    defer elf_context.deinit(init.gpa);
    const arch_info = elf_context.getArchVersionAndCoreProfile();

    var context: Context = .{
        .allocator = init.gpa,
        .io = init.io,
        .terminal = terminal,
        .elf = &elf_context,
    };

    try opencsd.checkError(opencsd.def_errlog_set_strprint_cb(dt.handle, @ptrCast(&context), &loggerPrint));

    try elf_context.setupMemoryAccessor(dt);
    defer elf_context.removeMemoryAccessor(dt);

    const configr = std.mem.zeroInit(CONFIGR, .{
        .ts = true,
        .bb = true,
        .cci = true,
    });
    const trace_config: opencsd.etmv4_cfg = .{
        .arch_ver = arch_info.arch_ver orelse opencsd.c.ARCH_V8,
        .core_prof = arch_info.core_profile,
        .reg_traceidr = 1,
        .reg_idr0 = 0x280006E1,
        .reg_idr8 = 0,
        .reg_idr9 = 0,
        .reg_idr12 = 1,
        .reg_idr13 = 0,
        .reg_configr = @bitCast(configr),
    };
    const trace_protocol: opencsd.trace_protocol_t = opencsd.PROTOCOL_ETMV4I;
    _ = &trace_protocol;

    const CSID = try dt.createDecoder(opencsd.BUILTIN_DCD_ETMV4I, opencsd.CREATE_FLG_FULL_DECODER, &trace_config);

    const print_packets = true;

    if (print_packets) {
        try opencsd.checkError(opencsd.dt_set_pkt_protocol_printer(dt.handle, CSID, 1));
        try opencsd.checkError(opencsd.dt_set_raw_frame_printer(dt.handle, opencsd.DFRMTR_PACKED_RAW_OUT | opencsd.DFRMTR_UNPACKED_RAW_OUT));
    }

    try opencsd.checkError(opencsd.dt_set_gen_elem_outfn(dt.handle, &printTraceElem, &context));

    try elf_context.openCapstoneHandle();

    var trace_file = try Io.Dir.openFile(.cwd(), io, trace_bin_path, .{
        .mode = .read_only,
        .allow_directory = true,
    });
    defer trace_file.close(io);

    var trace_file_reader_buffer: [1024]u8 = undefined;
    var trace_file_reader = trace_file.reader(io, &trace_file_reader_buffer);

    var response: opencsd.DataPath.Response = .CONT;
    while (!trace_file_reader.atEnd()) {
        response = switch (response.classify()) {
            .continue_processing => dt.processFileReaderData(&trace_file_reader, dfmt_flags) catch |err| switch (err) {
                error.EndOfStream => |e| {
                    // This *is* reachable -- looks like File.Reader doesn't fill in the .size field
                    // until it actually hits some sort of end-of-stream condition, so the `!atEnd()`
                    // check in the while loop condition passes until we try reading more
                    if (trace_file_reader.atEnd()) {
                        break;
                    } else {
                        return e;
                    }
                },
                else => |e| return e,
            },
            .wait => dt.processData(.FLUSH).response,
            .fatal => break,
        };
    }

    if (!response.isFatal()) {
        _ = dt.processData(.EOT);
    }

    context.terminal.writer.flush() catch {};
    try opencsd.checkError(ret);
}
