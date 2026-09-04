const std = @import("std");
const opencsd = @import("opencsd");

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
    writer: *Io.Writer,
    dump: Objdump = .empty,
};

fn loggerPrint(
    p_context: ?*const anyopaque,
    strp: [*c]const u8,
    str_len: c_int
) callconv(.c) void {
    const ctx: *const Context = @alignCast(@ptrCast(p_context.?));
    if (strp == null) return;
    const str: [:0]const u8 = if (str_len > 0) strp[0..@intCast(str_len):0] else std.mem.span(strp);
    ctx.writer.writeAll(str) catch {};
}

fn fillRegions(
    file: Io.File,
    io: Io,
    gpa: std.mem.Allocator,
    regions: *std.ArrayList(opencsd.file_mem_region_t),
) !void {
    var buffer: [512]u8 = undefined;
    var elf_file_reader = file.reader(io, &buffer);
    const header = try std.elf.Header.read(&elf_file_reader.interface);
    var it = header.iterateProgramHeaders(&elf_file_reader);
    while (try it.next()) |phdr_raw| {
        const phdr: std.elf.Elf64.Phdr = @bitCast(phdr_raw);
        if (phdr.flags.X and phdr.type == .LOAD and phdr.memsz > 0 and phdr.memsz == phdr.filesz) {
            try regions.append(gpa, .{
                .file_offset = @intCast(phdr.offset),
                .region_size = @intCast(phdr.memsz),
                .start_address = @intCast(phdr.vaddr),
            });
        }
    }
    std.mem.sort(opencsd.file_mem_region_t, regions.items, {}, struct {
        fn call(_: void, lhs: opencsd.file_mem_region_t, rhs: opencsd.file_mem_region_t) bool {
            return lhs.start_address < rhs.start_address;
        }
    }.call);
}

fn printTraceElemInner(
    ctx: *const Context,
    trcindex: opencsd.trc_index_t,
    chan: u8,
    raw_elem: *const opencsd.generic_trace_elem
) Io.Writer.Error!void {
    try ctx.writer.print("Idx:{}; TrcID:0x{X:02}; ", .{trcindex, chan});
    const ws = try ctx.writer.writableSliceGreedy(@min(ctx.writer.buffer.len, 1024));

    const ret = opencsd.gen_elem_str(raw_elem, ws.ptr, @intCast(ws.len - 2));
    if (ret == opencsd.OK) {
        const n = std.mem.findScalar(u8, ws, 0).?;
        ws[n] = '\n';
        ctx.writer.advance(n + 1);
    } else {
        try ctx.writer.writeAll("[unable to create elem string]\n");
    }

    const elem: *const opencsd.GenericTraceElement = @alignCast(@ptrCast(raw_elem));
    switch (elem.type) {
        .INSTR_RANGE => switch (elem.last_instr_type) {
            .BR, .BR_INDIRECT => {
                if (elem.flag_bits.last_instr_exec == 1) {
                    try ctx.writer.writeAll("    > branch taken\n");
                } else {
                    try ctx.writer.writeAll("    > branch NOT taken\n");
                }
                x: {
                    const chunk: *const Objdump.Chunk = for (ctx.dump.chunks) |*chunk| {
                        if (chunk.start <= elem.start_address and chunk.stop >= elem.end_address) {
                            break chunk;
                        }
                    } else break :x;
                    var addr_index: usize = for (0.., chunk.addrs) |i, offs| {
                        const addr: u64 = chunk.start + @as(u64, offs);
                        if (addr == elem.start_address) break i;
                        if (addr > elem.start_address) break :x;
                    } else break :x;

                    while (addr_index < chunk.addrs.len) : (addr_index += 1) {
                        const curr_addr = chunk.start + @as(u64, chunk.addrs[addr_index]);
                        if (curr_addr >= elem.end_address) break;
                        std.debug.assert(curr_addr >= elem.start_address);
                        const strp = chunk.strps[addr_index];
                        const line = std.mem.sliceTo(chunk.output[strp..], '\n');
                        try ctx.writer.print("0x{X:08}:\t{s}\n", .{ curr_addr, line });
                    }
                    try ctx.writer.writeByte('\n');
                }
            },
            else => {},
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
    };
    return opencsd.RESP_CONT;
}

const ObjdumpOptions = struct {
    exe: []const u8 = "objdump",
    target_query: ?TargetQuery = null,
};

const Objdump = struct {
    chunks: []const Chunk,

    const empty: Objdump = .{ .chunks = &.{} };

    fn deinit(objdump: *const Objdump, gpa: std.mem.Allocator) void {
        for (objdump.chunks) |chunk| chunk.deinit(gpa);
        gpa.free(objdump.chunks);
    }

    const Chunk = struct {
        output: []const u8,
        start: u64,
        stop: u64,
        /// A sorted list of offsets starting from `start`, i.e. a value of 6 here corresponds to the address `start+6`
        addrs: []const u32,
        /// The offset of the disassembled instruction string within `output`
        strps: []const u32,

        fn deinit(chunk: *const Chunk, gpa: std.mem.Allocator) void {
            gpa.free(chunk.output);
            gpa.free(chunk.addrs);
            gpa.free(chunk.strps);
        }
    };
};

fn dumpChunk(
    elf_filepath: [:0]const u8,
    io: Io,
    gpa: std.mem.Allocator,
    tmp_arena: std.mem.Allocator,
    region: *const opencsd.file_mem_region_t,
    aw: *Io.Writer.Allocating,
    options: ObjdumpOptions,
) !Objdump.Chunk {
    _ = &gpa;
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(tmp_arena, &.{
        options.exe,
        "--no-show-raw-insn",
        "-d",
        try std.fmt.allocPrint(tmp_arena, "--start-address={}", .{region.start_address}),
        // TODO: is this argument end exclusive?
        try std.fmt.allocPrint(tmp_arena, "--stop-address={}", .{region.start_address+region.region_size}),
    });

    if (options.target_query) |*tq| {
        if (tq.cpu_model != null and tq.cpu_model.?.llvm_name != null) {
            const arg = try std.fmt.allocPrint(tmp_arena, "--mcpu={s}", .{tq.cpu_model.?.llvm_name.?});
            try argv.append(tmp_arena, arg);
        }

        if (!tq.cpu_features_add.isEmpty() or !tq.cpu_features_sub.isEmpty()) {
            var attrs: std.ArrayList(u8) = .empty;
            try tq.toLlvmAttrs(&attrs, tmp_arena);
            if (attrs.items.len > 0) {
                try attrs.insertSlice(tmp_arena, 0, "--mattr=");
                try argv.append(tmp_arena, attrs.items);
            }
        }
    }

    try argv.append(tmp_arena, elf_filepath);

    std.debug.assert(aw.writer.end == 0);
    try aw.ensureTotalCapacity((region.region_size * (8 + 1 + 4)) / 4);

    {
        var child = try std.process.spawn(io, .{
            .argv = argv.items,
            .stdout = .pipe,
        });
        defer child.kill(io);

        var stdout_buffer: [0x4000]u8 = undefined;
        var stdout_file_reader = child.stdout.?.readerStreaming(io, &stdout_buffer);
        _ = try stdout_file_reader.interface.streamRemaining(&aw.writer);

        const term = try child.wait(io);
        switch (term) {
            .exited => |code| if (code != 0) return error.ChildProcessError,
            else => return error.Unexpected,
        }
    }

    var addrs: std.ArrayList(u32) = try .initCapacity(gpa, region.region_size / 8);
    defer addrs.deinit(gpa);
    var strps: std.ArrayList(u32) = try .initCapacity(gpa, region.region_size / 8);
    defer strps.deinit(gpa);

    var it = std.mem.splitScalar(u8, aw.written(), '\n');
    const baseptr = aw.written().ptr;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const next_non_ws = std.mem.findNonePos(u8, line, colon+1, " \t") orelse continue;
        if (next_non_ws == '<') {
            continue;
        }
        const index = (line.ptr + next_non_ws) - baseptr;
        const addr = std.fmt.parseInt(u64, line[0..colon], 16) catch |err| switch (err) {
            error.InvalidCharacter => continue,
            else => |e| return e,
        };
        const addr_offset: u32 = @intCast(addr - region.start_address);
        try addrs.append(gpa, addr_offset);
        try strps.append(gpa, @intCast(index));
    }

    const output = try gpa.dupe(u8, aw.written());
    errdefer gpa.free(output);
    const addrs_duped = try addrs.toOwnedSlice(gpa);
    errdefer gpa.free(addrs_duped);
    const strps_duped = try strps.toOwnedSlice(gpa);
    errdefer gpa.free(strps_duped);
    return .{
        .output = output,
        .start = region.start_address,
        .stop = region.start_address + region.region_size,
        .addrs = addrs_duped,
        .strps = strps_duped,
    };
}

fn collectObjdump(
    elf_filepath: [:0]const u8,
    io: Io,
    gpa: std.mem.Allocator,
    regions: []const opencsd.file_mem_region_t,
    options: ObjdumpOptions,
) !Objdump {
    var tmp_arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer tmp_arena_instance.deinit();
    const tmp_arena = tmp_arena_instance.allocator();

    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();

    const chunks_buffer = try gpa.alloc(Objdump.Chunk, regions.len);
    var chunks: std.ArrayList(Objdump.Chunk) = .initBuffer(chunks_buffer);

    errdefer {
        for (chunks.items) |chunk| chunk.deinit(gpa);
        gpa.free(chunks_buffer);
    }

    for (regions) |region| {
        _ = tmp_arena_instance.reset(.retain_capacity);
        aw.clearRetainingCapacity();
        const chunk = try dumpChunk(elf_filepath, io, gpa, tmp_arena, &region, &aw, options);
        try chunks.appendBounded(chunk);
    }

    return .{ .chunks = chunks_buffer };
}

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

    const dt: opencsd.DecodeTree = try .create(.FRAME_FORMATTED, .{
        .has_fsyncs = true,
    });
    defer dt.destroy();

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = Io.File.stdout().writerStreaming(init.io, &stdout_buffer);

    var context: Context = .{
        .allocator = init.gpa,
        .io = init.io,
        .writer = &stdout_file_writer.interface,
    };

    try opencsd.checkError(opencsd.def_errlog_set_strprint_cb(dt.handle, @ptrCast(&context), &loggerPrint));

    const trace_config: opencsd.etmv4_cfg = .{
        .arch_ver = opencsd.c.ARCH_V8,
        .core_prof = opencsd.c.profile_CortexM,
        .reg_traceidr = 1,
        .reg_idr0 = 0x280006E1,
        .reg_idr8 = 0,
        .reg_idr9 = 0,
        .reg_idr12 = 1,
        .reg_idr13 = 0,
    };
    const trace_protocol: opencsd.trace_protocol_t = opencsd.PROTOCOL_ETMV4I;
    _ = &trace_protocol;

    const CSID = try dt.createDecoder(opencsd.BUILTIN_DCD_ETMV4I, opencsd.CREATE_FLG_FULL_DECODER, &trace_config);
    _ = &CSID;

    try opencsd.checkError(opencsd.dt_set_gen_elem_outfn(dt.handle, &printTraceElem, &context));

    var regions: std.ArrayList(opencsd.file_mem_region_t) = .empty;
    {
        const elf_file = try Io.Dir.openFile(.cwd(), io, program_elf_path, .{
            .mode = .read_only,
            .allow_directory = false,
        });
        defer elf_file.close(io);
        try fillRegions(elf_file, io, arena, &regions);
        for (regions.items) |region| {
            std.debug.print("fileoff: 0x{X:08}, vmaddr: 0x{X:08}, size: 0x{X:08}\n", .{
                region.file_offset,
                region.start_address,
                region.region_size,
            });
        }
    }
    try opencsd.checkError(opencsd.dt_add_binfile_region_mem_acc(
        dt.handle,
        regions.items.ptr,
        @intCast(regions.items.len),
        opencsd.MEM_SPACE_ANY,
        program_elf_path.ptr,
    ));
    defer {
        if (regions.items.len > 0) {
            _ = opencsd.dt_remove_mem_acc(
                dt.handle,
                regions.items[0].start_address,
                opencsd.MEM_SPACE_ANY
            );
        }
    }

    var dump_options: ObjdumpOptions = .{
        .target_query = .{
            .cpu_arch = .thumb,
            .cpu_model = &std.Target.arm.cpu.cortex_m33,
            .cpu_features_add = std.Target.arm.featureSet(&.{
                .fp_armv8d16sp,
                .dsp,
            }),
        },
    };
    if (init.environ_map.get("OBJDUMP")) |dump_exe| {
        dump_options.exe = dump_exe;
    }

    context.dump = try collectObjdump(program_elf_path, io, init.gpa, regions.items, dump_options);
    defer context.dump.deinit(init.gpa);

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
            .continue_processing => dt.processFileReaderData(&trace_file_reader) catch |err| switch (err) {
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

    context.writer.flush() catch {};
    try opencsd.checkError(ret);
}
