const std = @import("std");
const opencsd = @import("opencsd.zig");
const capstone = @import("capstone");
const c = opencsd.c;
const elf = std.elf;
const Io = std.Io;

const ElfContext = @This();

pub const Region = opencsd.file_mem_region_t;

header: elf.Header,
mapped_mem: []align(std.heap.page_size_min) const u8,
regions: []const Region,
csh: capstone.csh = undefined,

pub const OpenOptions = struct {};

pub fn open(elf_file_path: []const u8, io: Io, gpa: std.mem.Allocator, options: OpenOptions) !ElfContext {
    _ = options;
    const elf_file = try Io.Dir.openFile(.cwd(), io, elf_file_path, .{
        .mode = .read_only,
        .allow_directory = false,
    });
    // once we've mapped the file, we no longer need it open
    defer elf_file.close(io);
    const mapped_mem = mapped: {
        const file_len = std.math.cast(
            usize,
            elf_file.length(io) catch |err| switch (err) {
                error.PermissionDenied => unreachable, // not asking for PROT_EXEC
                else => |e| return e,
            },
        ) orelse return error.Overflow;

        break :mapped std.posix.mmap(
            null,
            file_len,
            .{ .READ = true },
            .{ .TYPE = .SHARED },
            elf_file.handle,
            0,
        ) catch |err| switch (err) {
            error.MappingAlreadyExists => unreachable, // not using FIXED_NOREPLACE
            error.PermissionDenied => unreachable, // not asking for PROT_EXEC
            else => |e| return e,
        };
    };
    errdefer std.posix.munmap(mapped_mem);

    var regions: std.ArrayList(Region) = .empty;
    defer regions.deinit(gpa);

    var elf_reader: Io.Reader = .fixed(mapped_mem);
    const header: elf.Header = try .read(&elf_reader);

    switch (header.machine) {
        .ARM, .AARCH64 => {},
        else => return error.UnsupportedArchitecture,
    }

    // TODO: validate header.type

    var phdr_it = header.iterateProgramHeadersBuffer(mapped_mem);
    while (try phdr_it.next()) |phdr_raw| {
        const phdr: std.elf.Elf64.Phdr = @bitCast(phdr_raw);
        // Collect all LOAD program headers with execution perms
        // TODO: should we use section headers instead?
        if (phdr.flags.X and phdr.type == .LOAD and phdr.memsz > 0 and phdr.memsz == phdr.filesz) {
            try regions.append(gpa, .{
                .file_offset = @intCast(phdr.offset),
                .region_size = @intCast(phdr.memsz),
                .start_address = @intCast(phdr.vaddr),
            });
        }
    }

    // Sort regions by virtual address for eventual searching purposes
    std.mem.sort(opencsd.file_mem_region_t, regions.items, {}, struct {
        fn call(_: void, lhs: opencsd.file_mem_region_t, rhs: opencsd.file_mem_region_t) bool {
            return lhs.start_address < rhs.start_address;
        }
    }.call);

    if (header.machine == .ARM) {
        try armParseBuildAttributes(&header, mapped_mem);
    }
}

/// "Tag_CPU_arch_profile states that the attributed entity requires the noted
/// architecture profile. [...] Starting with architecture versions v8-A, v8-R and v8-M,
/// the profile is represented by Tag_CPU_arch. For these architecture versions and any
/// later versions, a value of 0 should be used for Tag_CPU_arch_profile."
const AebiCpuArchProfile = enum(u8) {
    na_or_implied_by_cpu_arch = 0,
    /// Application profile
    A = 'A',
    /// Real-time profile
    R = 'R',
    /// Microcontroller profile
    M = 'M',
    /// Application or real-time profile
    S = 'S',
    _,
};

pub const AeabiCpuArch = enum(u8) {
    pre_v4 = 0,
    arm_v4 = 1,
    arm_v4T = 2,
    arm_v5T = 3,
    arm_v5TE = 4,
    arm_v5TEJ = 5,
    arm_v6 = 6,
    arm_v6KZ = 7,
    arm_v6T2 = 8,
    arm_v6K = 9,
    arm_v7 = 10,
    arm_v6_M = 11,
    arm_v6S_M = 12,
    arm_v7E_M = 13,
    arm_v8_A = 14,
    arm_v8_R = 15,
    arm_v8_M_baseline = 16,
    arm_v8_M_mainline = 17,
    arm_v8_1_A = 18,
    arm_v8_2_A = 19,
    arm_v8_3_A = 20,
    arm_v8_1_M_mainline = 21,
    arm_v9_A = 22,
    _,
};

const ArmAttributes = struct {
    cpu_name: ?[:0]const u8 = null,
    cpu_raw_name: ?[:0]const u8 = null,
    cpu_arch: ?AeabiCpuArch = null,
    cpu_arch_profile: ?AebiCpuArchProfile = null,
    // this can be deduced from cpu_arch and/or cpu_name, right?
    use_thumb: ?bool = null,
    // this can be deduced from cpu_arch and/or cpu_name, right?
    use_arm: ?bool = null,
};

/// https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#id30
const SHT_ARM_ATTRIBUTES: elf.SHT = @enumFromInt(0x70000003);

/// https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#5362top-level-structure-tags
/// https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#id50
/// https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#35attributes-summary-and-history
const AeabiAttributeTag = enum(u64) {
    file = 1,
    section = 2,
    symbol = 3,
    CPU_raw_name = 4,
    CPU_name = 5,
    CPU_arch = 6,
    CPU_arch_profile = 7,
    ARM_ISA_use = 8,
    THUMB_ISA_use = 9,
    FP_arch = 10,
    VFP_arch = 10,
    WMMX_arch = 11,
    Advanced_SIMD_arch = 12,
    PCS_config = 13,
    ABI_PCS_R9_use = 14,
    ABI_PCS_RW_data = 15,
    ABI_PCS_RO_data = 16,
    ABI_PCS_GOT_use = 17,
    ABI_PCS_wchar_t = 18,
    ABI_FP_rounding = 19,
    ABI_FP_denormal = 20,
    ABI_FP_exceptions = 21,
    ABI_FP_user_exceptions = 22,
    ABI_FP_number_model = 23,
    ABI_align_needed = 24,
    ABI_align8_needed = 24,
    ABI_align_preserved = 25,
    ABI_align8_preserved = 25,
    ABI_enum_size = 26,
    ABI_HardFP_use = 27,
    ABI_VFP_args = 28,
    ABI_WMMX_args = 29,
    ABI_optimization_goals = 30,
    ABI_FP_optimization_goals = 31,
    compatibility = 32,

    _,

    pub fn valueEncoding(tag: AeabiAttributeTag) ValueEncoding {
        const tagint = @intFromEnum(tag);
        if (tagint > 32) {
            // https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#id49
            const is_even = tagint & 1 == 0;
            return if (is_even) .uleb128 else .ntbs;
        } else return switch (tag) {
            .file, .section, .symbol => .scope_len,
            .CPU_raw_name, .CPU_name, .TAG_compatibility => .ntbs,
            else => .uleb128,
        };
    }

    pub const ValueEncoding = enum {
        uleb128,
        /// Nul-terminated byte string
        ntbs,
        scope_len,
    };
};

// https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#id34
// https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#addendum-build-attributes
fn armParseBuildAttributes(ehdr: *const elf.Header, mapped_mem: []align(std.heap.page_size_min) const u8) !void {
    std.debug.assert(ehdr.machine == .ARM);
    const shstrtab = shstrtab: {
        const offs = try std.math.mul(u64, ehdr.shstrndx, ehdr.shentsize);
        const shstrtab_shdr_offs = try std.math.add(u64, ehdr.shoff, offs);
        var r: Io.Reader = .fixed(mapped_mem);
        r.seek = std.math.cast(usize, shstrtab_shdr_offs) orelse return error.Overflow;
        const shdr = try elf.takeSectionHeader(&r, ehdr.is_64, ehdr.endian);
        break :shstrtab mapped_mem[@intCast(shdr.sh_offset)..][0..@intCast(shdr.sh_size)];
    };

    var shdr_it = ehdr.iterateSectionHeadersBuffer(mapped_mem);
    while (try shdr_it.next()) |shdr_raw| {
        const shdr: elf.Elf64.Shdr = @bitCast(shdr_raw);
        if (shdr.type != SHT_ARM_ATTRIBUTES) continue;
        if (shdr.sh_name > shstrtab.len) return error.InvalidElfFile;
        const name = std.mem.sliceTo(shstrtab[@intCast(shdr.sh_name)..], 0);
        if (!std.mem.eql(u8, name, ".ARM.attributes")) return error.InvalidElfFile;
        if ((shdr.sh_flags & elf.SHF_COMPRESSED) != 0) return error.Unsupported;
        if (shdr.sh_offset + shdr.sh_size > mapped_mem.len) return error.InvalidElfFile;
        const section_data = mapped_mem[@intCast(shdr.sh_offset)..][0..@intCast(shdr.sh_size)];

        var r: Io.Reader = .fixed(section_data);
        const format_version = try r.takeByte();
        if (format_version != 'A') {
            return error.Unsupported;
        }

        while (r.bufferedLen() > 0) {
            const start_pos = r.seek;
            const sectlen = try r.takeInt(u32, ehdr.endian);
            // length includes length-field, and is followed by a null-terminated string
            if (sectlen < 1 + @sizeOf(u32) or start_pos + sectlen > r.end) {
                return error.InvalidElfFile;
            }
            const next_pos = start_pos + sectlen;
            const vendor_name = try r.takeSentinel(0);
            if (!std.mem.eql(u8, vendor_name, "aeabi")) {
                r.seek = next_pos;
                return;
            }

            var subreader: Io.Reader = .fixed(r.seek[start_pos..next_pos]);
            try parseBuildAttributesSubSectionData(&subreader, ehdr);
        }
    }
}

fn parseBuildAttributesSubSectionData(
    r: *Io.Reader,
    ehdr: *const elf.Header,
    // mapped_mem: []align(std.heap.page_size_min) const u8
) !void {
    while (r.bufferedLen() > 0) {
        const subsub_start = r.seek;
        const scope_tag: AeabiAttributeTag = @enumFromInt(try r.takeByte());
        const subsub_len = try r.takeInt(u32, ehdr.endian);
        const next_subsubpos = subsub_start + subsub_len;
        if (next_subsubpos > r.end) return error.InvalidElfFile;
        switch (scope_tag) {
            .file => {},
            // TODO: section/symbol level attrs?
            //       - note that "Tag_nodefaults" will have to be taken into account if
            //         these are supported
            //       - note that these tags are deprecated by arm
            .section, .symbol => {
                r.seek = next_subsubpos;
                continue;
            },
            else => return error.InvalidElfFile,
        }
        while (r.seek < next_subsubpos) {
            const tag_int = try r.takeLeb128(@typeInfo(AeabiAttributeTag).@"enum".tag_type);
            const tag: AeabiAttributeTag = @enumFromInt(tag_int);
        }
    }
}
