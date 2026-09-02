const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const opencsd_linkage: std.builtin.LinkMode =
        b.option(std.builtin.LinkMode, "linkage", "OpenCSD library linkage") orelse .static;

    // TODO: figure out a non-nuked way to get this from ocsd_if_version.h,
    // or hand-sync and maybe add a comparison check step or smth
    const opencsd_version: ?std.SemanticVersion = .{
        .major = 0x1,
        .minor = 0x8,
        .patch = 0x3,
    };

    const opencsd = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = optimize,
        .link_libcpp = true,
    });
    opencsd.addCSourceFiles(.{
        .files = opencsd_sources,
        .language = .cpp,
        .flags = &.{
            "-Wall",
            "-Wno-switch",
            "-Wno-deprecated-declarations",
            "-Wno-unused-variable",
            "-Wno-reorder",
            "-Wno-invalid-token-paste",
            "-fexceptions",
            "-Wlogical-op",
        },
    });

    const opencsd_c_api = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    opencsd_c_api.addCSourceFiles(.{
        .files = opencsd_c_api_sources,
        .language = .cpp,
        .flags = &.{
            "-Wall",
            "-Wno-switch",
            "-Wno-deprecated-declarations",
            "-Wno-unused-variable",
            "-Wno-reorder",
            "-Wno-invalid-token-paste",
            "-fexceptions",
            "-Wlogical-op",
        },
    });

    for ([_]*Build.Module{ opencsd, opencsd_c_api }) |mod| {
        mod.addIncludePath(b.path("decoder/source"));
        mod.addIncludePath(b.path("decoder/include"));
    }

    // TODO: need to wrap my head around OpenCSD's CMAKE logic for this.
    // These variables are set on the `opencsd_c_api_obj_<shared|static>` target, to which
    // the main <shared|static> opencsd_c_api target links
    if (target.result.os.tag == .windows) {
        switch (opencsd_linkage) {
            .dynamic => opencsd_c_api.addCMacro("_OCSD_C_API_DLL_EXPORT", ""),
            .static => opencsd_c_api.addCMacro("OCSD_USE_STATIC_C_API", ""),
        }
    }

    const opencsd_static_lib = b.addLibrary(.{
        .name = "opencsd",
        .root_module = opencsd,
        .linkage = .static,
        .version = opencsd_version,
    });

    const opencsd_dynamic_lib = b.addLibrary(.{
        .name = "opencsd",
        .root_module = opencsd,
        .linkage = .dynamic,
        .version = opencsd_version,
    });

    if (target.result.os.tag == .windows) {
        // is this needed?
        opencsd_dynamic_lib.dll_export_fns = true;
    }

    const opencsd_c_api_lib = b.addLibrary(.{
        .name = "opencsd_c_api",
        .root_module = opencsd,
        .linkage = opencsd_linkage,
        .version = opencsd_version,
    });
    opencsd_c_api_lib.installHeadersDirectory(
        b.path("decoder/include/opencsd/c_api"),
        "opencsd/c_api",
        .{ .exclude_extensions = &.{ "cust_fact.h", "cust_impl.h" } },
    );

    for ([_]*Build.Step.Compile{ opencsd_static_lib, opencsd_dynamic_lib, opencsd_c_api_lib }) |lib| {
        // TODO: cmakelists does `if (!apple) set(OPENCSD_LINK_FLAGS -Wl,-z,defs)`
        if (target.result.os.tag.isDarwin()) {
            lib.linker_allow_shlib_undefined = true;
        } else {
            lib.link_z_defs = true;
        }
    }

    const desired_lib = switch (opencsd_linkage) {
        .static => opencsd_static_lib,
        .dynamic => opencsd_dynamic_lib,
    };

    if (target.result.os.tag == .windows) {
        // not sure if special casing for windows is actually required,
        // they do this in cmake but I'm wondering if its so that they don't
        // have to handle implib stuff, which linkLibrary does for dynlibs
        // on windows automagically afaik
        opencsd_c_api.linkLibrary(opencsd_static_lib);
    } else {
        opencsd_c_api.linkLibrary(desired_lib);
    }

    const install_opencsd = b.addInstallArtifact(desired_lib, .{
        // i think enabling this matches how cmakelists does it?
        .dylib_symlinks = if (opencsd_linkage == .dynamic) true else null,
    });

    const install_opencsd_c_api = b.addInstallArtifact(opencsd_c_api_lib, .{
        // i think enabling this matches how cmakelists does it?
        .dylib_symlinks = if (opencsd_linkage == .dynamic) true else null,
    });

    const install_opencsd_step = b.step("opencsd-lib", "Install OpenCSD CPP library");
    install_opencsd_step.dependOn(&install_opencsd.step);

    for (opencsd_install_headers) |ih| {
        const src = b.path(b.pathJoin(&.{ opencsd_headers_base, ih }));
        desired_lib.installHeader(src, ih);
    }

    const install_opencsd_c_api_step = b.step("opencsd-c-api-lib", "Install OpenCSD C library");
    install_opencsd_c_api_step.dependOn(&install_opencsd_c_api.step);

    b.getInstallStep().dependOn(install_opencsd_step);
    b.getInstallStep().dependOn(install_opencsd_c_api_step);
}

const opencsd_sources: []const []const u8 = &.{
    "decoder/source/cs_frame_mux_data.cpp",
    "decoder/source/ocsd_code_follower.cpp",
    "decoder/source/ocsd_dcd_tree.cpp",
    "decoder/source/ocsd_error.cpp",
    "decoder/source/ocsd_error_logger.cpp",
    "decoder/source/ocsd_gen_elem_list.cpp",
    "decoder/source/ocsd_gen_elem_stack.cpp",
    "decoder/source/ocsd_lib_dcd_register.cpp",
    "decoder/source/ocsd_msg_logger.cpp",
    "decoder/source/ocsd_version.cpp",
    "decoder/source/trc_component.cpp",
    "decoder/source/trc_core_arch_map.cpp",
    "decoder/source/trc_frame_deformatter.cpp",
    "decoder/source/trc_gen_elem.cpp",
    "decoder/source/trc_printable_elem.cpp",
    "decoder/source/trc_ret_stack.cpp",
    "decoder/source/ete/trc_cmp_cfg_ete.cpp",
    "decoder/source/etmv3/trc_cmp_cfg_etmv3.cpp",
    "decoder/source/etmv3/trc_pkt_decode_etmv3.cpp",
    "decoder/source/etmv3/trc_pkt_elem_etmv3.cpp",
    "decoder/source/etmv3/trc_pkt_proc_etmv3.cpp",
    "decoder/source/etmv3/trc_pkt_proc_etmv3_impl.cpp",
    "decoder/source/etmv4/trc_cmp_cfg_etmv4.cpp",
    "decoder/source/etmv4/trc_etmv4_stack_elem.cpp",
    "decoder/source/etmv4/trc_pkt_decode_etmv4i.cpp",
    "decoder/source/etmv4/trc_pkt_elem_etmv4i.cpp",
    "decoder/source/etmv4/trc_pkt_proc_etmv4i.cpp",
    "decoder/source/i_dec/trc_i_decode.cpp",
    "decoder/source/i_dec/trc_idec_arminst.cpp",
    "decoder/source/itm/trc_pkt_decode_itm.cpp",
    "decoder/source/itm/trc_pkt_elem_itm.cpp",
    "decoder/source/itm/trc_pkt_proc_itm.cpp",
    "decoder/source/mem_acc/trc_mem_acc_base.cpp",
    "decoder/source/mem_acc/trc_mem_acc_bufptr.cpp",
    "decoder/source/mem_acc/trc_mem_acc_cache.cpp",
    "decoder/source/mem_acc/trc_mem_acc_cb.cpp",
    "decoder/source/mem_acc/trc_mem_acc_file.cpp",
    "decoder/source/mem_acc/trc_mem_acc_mapper.cpp",
    "decoder/source/pkt_printers/gen_elem_printer.cpp",
    "decoder/source/pkt_printers/raw_frame_printer.cpp",
    "decoder/source/pkt_printers/trc_print_fact.cpp",
    "decoder/source/ptm/trc_cmp_cfg_ptm.cpp",
    "decoder/source/ptm/trc_pkt_decode_ptm.cpp",
    "decoder/source/ptm/trc_pkt_elem_ptm.cpp",
    "decoder/source/ptm/trc_pkt_proc_ptm.cpp",
    "decoder/source/stm/trc_pkt_decode_stm.cpp",
    "decoder/source/stm/trc_pkt_elem_stm.cpp",
    "decoder/source/stm/trc_pkt_proc_stm.cpp",
};

const opencsd_c_api_sources: []const []const u8 = &.{
    "decoder/source/c_api/ocsd_c_api.cpp",
    "decoder/source/c_api/ocsd_c_api_custom_obj.cpp",
};

const opencsd_headers_base = "decoder/include";

const opencsd_install_headers: []const []const u8 = &.{
    "opencsd/trc_gen_elem_types.h",
    "opencsd/ocsd_if_types.h",
    "opencsd/ocsd_if_version.h",
    "opencsd/trc_pkt_types.h",
    "opencsd/ptm/trc_pkt_types_ptm.h",
    "opencsd/stm/trc_pkt_types_stm.h",
    "opencsd/etmv3/trc_pkt_types_etmv3.h",
    "opencsd/etmv4/trc_pkt_types_etmv4.h",
    "opencsd/ete/trc_pkt_types_ete.h",
};
