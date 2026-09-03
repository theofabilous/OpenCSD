const std = @import("std");
pub const c = @import("opencsd-c");

pub const DecodeTree = extern struct {
    handle: *anyopaque,

    pub fn fromRaw(raw: c.dcd_tree_handle_t) ?DecodeTree {
        if (raw) |nonnull| {
            return .{ .handle = nonnull };
        } else {
            return null;
        }
    }

    pub fn create(src_type: SrcType, deformatter_flags: DeformatterFlags) error{DecodeTreeCreationFailed}!DecodeTree {
        const raw = create_dcd_tree(@intFromEnum(src_type), @bitCast(deformatter_flags));
        const dt = fromRaw(raw);
        return dt orelse error.DecodeTreeCreationFailed;
    }

    pub fn destroy(dt: DecodeTree) void {
        destroy_dcd_tree(dt.handle);
    }

    pub fn createDecoder(
        dt: DecodeTree,
        name: [:0]const u8,
        create_flags: c_int,
        config: *const anyopaque
    ) Error!u8 {
        var csid: u8 = 0;
        try checkError(dt_create_decoder(dt.handle, @ptrCast(name.ptr), create_flags, config, &csid));
        return csid;
    }

    pub fn removeDecoder(dt: DecodeTree, csid: u8) !void {
        return checkError(dt_remove_decoder(dt.handle, csid));
    }

    pub fn processData(dt: DecodeTree, op: ProcessData) ProcessData.Result {
        var result: ProcessData.Result = .{
            .response = undefined,
            .num_processed_bytes = 0,
        };
        const resp = switch (op) {
            .DATA => |trace_data| dt_process_data(dt.handle,
                @intFromEnum(op),
                trace_data.trace_index,
                @intCast(trace_data.slice.len),
                trace_data.slice.ptr,
                &result.num_processed_bytes
            ),
            .EOT, .FLUSH, .RESET => dt_process_data(dt.handle, @intFromEnum(op), 0, 0, null, null),
        };
        result.response = @enumFromInt(resp);
        return result;
    }

    /// Process a block of data using data buffered in `reader`. This should generally
    /// only be used with fixed readers. `trc_index` corresponds to the offset of the
    /// reader's *base* position within the trace data, i.e. `trc_index` indicates the
    /// trace byte position of `reader.buffer[0]`. The actual trace position passed to the
    /// decoder is `trc_index + reader.seek`.
    ///
    /// If the entirety of the trace data is held within a fixed reader, it can be
    /// processed in full by calling this function in a loop (handling datapath responses
    /// appropriately) with `trc_index` set to `0`.
    ///
    /// Advances the reader's seek position by the number of processed bytes.
    /// Asserts `reader` has buffered data.
    pub fn processReaderBufferedData(dt: DecodeTree, trc_index: trc_index_t, reader: *std.Io.Reader) DataPath.Response {
        std.debug.assert(reader.bufferedLen() > 0);
        const result = dt.processData(.traceData(.{
            .slice = reader.buffered(),
            .trace_index = trc_index + @as(trc_index_t, @intCast(reader.seek)),
        }));
        reader.toss(result.num_processed_bytes);
        return result.response;
    }

    /// Process some data sourced from the `file_reader`.
    ///
    /// Assumes the file reader's logical position follows the decoder's trace position, i.e.
    /// the trace byte position passed to the decoder is `file_reader.logicalPos()`.
    pub fn processFileReaderData(dt: DecodeTree, file_reader: *std.Io.File.Reader) !DataPath.Response {
        const reader = &file_reader.interface;
        if (reader.bufferedLen() == 0) try reader.fillMore();
        const result = dt.processData(.traceData(.{
            .slice = reader.buffered(),
            .trace_index = @intCast(file_reader.logicalPos()),
        }));
        reader.toss(result.num_processed_bytes);
        return result.response;
    }

    pub const ProcessData = union(DataPath.Op) {
        DATA: TraceData,
        EOT,
        FLUSH,
        RESET,

        pub inline fn traceData(trace_data: TraceData) ProcessData {
            return .{ .DATA = trace_data };
        }

        pub const TraceData = struct {
            trace_index: trc_index_t,
            slice: []const u8,
        };

        pub const Result = struct {
            response: DataPath.Response,
            num_processed_bytes: u32,
        };
    };

    pub const SrcType = enum(dcd_tree_src_t) {
        FRAME_FORMATTED = c.OCSD_TRC_SRC_FRAME_FORMATTED,
        SINGLE = c.OCSD_TRC_SRC_SINGLE,
    };

    pub const DeformatterFlags = packed struct (u32) {
        has_fsyncs: bool = false,
        has_hsyncs: bool = false,
        frame_mem_align: bool = false,
        packed_raw_out: bool = false,
        unpacked_raw_out: bool = false,
        reset_on_4x_sync: bool = false,
        _: u26 = 0,
    };
};

pub const DataPath = opaque {
    pub const Op = enum (datapath_op_t) {
        /// Standard index + data packet
        DATA = c.OCSD_OP_DATA,
        /// End of available trace data. No data packet.
        EOT = c.OCSD_OP_EOT,
        /// Flush existing data where possible, retain decode state. No data packet.
        FLUSH = c.OCSD_OP_FLUSH,
        /// Reset decode state - drop any existing partial data. No data packet.
        RESET = c.OCSD_OP_RESET,
    };

    pub const Response = enum (datapath_resp_t) {
        /// Continue processing
        CONT = c.OCSD_RESP_CONT,
        /// Continue processing  : a component logged a warning.
        WARN_CONT = c.OCSD_RESP_WARN_CONT,
        /// Continue processing  : a component logged an error.
        ERR_CONT = c.OCSD_RESP_ERR_CONT,
        /// Pause processing
        WAIT = c.OCSD_RESP_WAIT,
        /// Pause processing : a component logged a warning.
        WARN_WAIT = c.OCSD_RESP_WARN_WAIT,
        /// Pause processing : a component logged an error.
        ERR_WAIT = c.OCSD_RESP_ERR_WAIT,
        /// Processing Fatal Error :  component unintialised.
        FATAL_NOT_INIT = c.OCSD_RESP_FATAL_NOT_INIT,
        /// Processing Fatal Error :  invalid data path operation.
        FATAL_INVALID_OP = c.OCSD_RESP_FATAL_INVALID_OP,
        /// Processing Fatal Error :  invalid parameter in datapath call.
        FATAL_INVALID_PARAM = c.OCSD_RESP_FATAL_INVALID_PARAM,
        /// Processing Fatal Error :  invalid trace data
        FATAL_INVALID_DATA = c.OCSD_RESP_FATAL_INVALID_DATA,
        /// Processing Fatal Error :  internal system error.
        FATAL_SYS_ERR = c.OCSD_RESP_FATAL_SYS_ERR,

        pub const Class = enum {
            continue_processing,
            wait,
            fatal,
        };

        pub fn classify(resp: Response) Class {
            if (resp.isContinue()) {
                return .continue_processing;
            } else if (resp.isWait()) {
                return .wait;
            } else if (resp.isFatal()) {
                return .fatal;
            } else {
                unreachable;
            }
        }

        pub inline fn isContinue(resp: Response) bool {
            return c.OCSD_DATA_RESP_IS_CONT(@intFromEnum(resp));
        }

        pub inline fn isWait(resp: Response) bool {
            return c.OCSD_DATA_RESP_IS_WAIT(@intFromEnum(resp));
        }

        pub inline fn isFatal(resp: Response) bool {
            return c.OCSD_DATA_RESP_IS_FATAL(@intFromEnum(resp));
        }
    };
};


pub const Isa = enum (c.ocsd_isa) {
    arm = c.ocsd_isa_arm,             // V7 ARM 32, V8 AArch32
    thumb2 = c.ocsd_isa_thumb2,       // Thumb2 -> 16/32 bit instructions
    aarch64 = c.ocsd_isa_aarch64,     // V8 AArch64
    tee = c.ocsd_isa_tee,             // Thumb EE - unsupported
    jazelle = c.ocsd_isa_jazelle,     // Jazelle - unsupported in trace
    custom = c.ocsd_isa_custom,       // Instruction set - custom arch decoder
    unknown = c.ocsd_isa_unknown,     // ISA not yet known
};

pub const InstructionType = enum(c.ocsd_instr_type) {
    ///  Other instruction - not significant for waypoints.
    OTHER = c.OCSD_INSTR_OTHER,
    ///  Immediate Branch instruction
    BR = c.OCSD_INSTR_BR,
    ///  Indirect Branch instruction
    BR_INDIRECT = c.OCSD_INSTR_BR_INDIRECT,
    ///  Barrier : ISB instruction
    ISB = c.OCSD_INSTR_ISB,
    ///  Barrier : DSB or DMB instruction
    DSB_DMB = c.OCSD_INSTR_DSB_DMB,
    ///  WFI or WFE traced as direct branch
    WFI_WFE = c.OCSD_INSTR_WFI_WFE,
    ///  PE Arch feature FEAT_TME - TSTART instruction
    TSTART = c.OCSD_INSTR_TSTART,
};

pub const InstructionSubType = enum(c.ocsd_instr_subtype) {
    ///  no subtype set
    NONE = c.OCSD_S_INSTR_NONE,
    ///  branch with link
    BR_LINK = c.OCSD_S_INSTR_BR_LINK,
    ///  v8 ret instruction - subtype of BR_INDIRECT
    V8_RET = c.OCSD_S_INSTR_V8_RET,
    ///  v8 eret instruction - subtype of BR_INDIRECT
    V8_ERET = c.OCSD_S_INSTR_V8_ERET,
    ///  v7 instruction which could imply return e.g. MOV PC, LR; POP { ,pc}
    V7_IMPLIED_RET = c.OCSD_S_INSTR_V7_IMPLIED_RET,
};

pub const GenericTraceElement = extern struct {
    type: ElemType,
    isa: Isa,
    start_address: c.ocsd_vaddr_t,
    end_address: c.ocsd_vaddr_t,
    pe_context: PeContext,
    timestamp: u64,
    cycle_count: u32,
    last_instr_type: InstructionType,
    last_instr_subtype: InstructionSubType,
    flag_bits: FlagBits,
    payload: Payload,
    extended_data: ?*const anyopaque,

    pub const Payload = extern union {
        exception_number: u32,
        trace_event: c.trace_event_t,
        trace_on_reason: c.trace_on_reason_t,
        sw_trace_info: SwtInfo,
        num_instr_range: u32,
        unsync_eot_info: c.unsync_info_t,
        sync_marker: c.trace_marker_payload_t,
        mem_trans: c.trace_memtrans_t,
        sw_ite: c.trace_sw_ite_t,
        sw_itm: c.swt_itm_info,

        pub const SwtInfo = extern struct {
            swt_master_id: u16,
            swt_channel_id: u16,
            // TODO: add the packed struct def here
            swt_flag_bits: u32,
        };
    };

    // TODO: verify that this type is ABI-compatible with the corresponding field(s)
    // declared in the c-api.
    pub const FlagBits = packed struct (u32) {
        /// 1 if last instruction in range was executed;
        last_instr_exec: u1,
        /// size of last instruction in bytes (2/4)
        last_instr_sz: u3,
        /// 1 if this packet has a valid cycle count included (e.g. cycle count included as part of instruction range packet, always 1 for pure cycle count packet.
        has_cc: u1,
        /// 1 if this packet indicates a change in CPU frequency
        cpu_freq_change: u1,
        /// 1 if en_addr is the preferred exception return address on exception packet type
        excep_ret_addr: u1,
        /// 1 if the exception entry packet is a data push marker only, with no address information (used typically in v7M trace for marking data pushed onto stack)
        excep_data_marker: u1,
        /// 1 if the packet extended data pointer is valid. Allows packet extensions for custom decoders, or additional data payloads for data trace.
        extended_data: u1,
        /// 1 if the packet has an associated timestamp - e.g. SW/STM trace TS+Payload as a single packet, ITM - accumulated delta TS
        has_ts: u1,
        /// 1 if the last instruction was conditional
        last_instr_cond: u1,
        /// 1 if exception return address (en_addr) is also the target of a taken branch addr from the previous range.
        excep_ret_addr_br_tgt: u1,
        /// 1 if the exception is an M class exception with no pref ret address - tail chained or similar
        excep_M_tail_chain: u1,
        _: u19 = 0,
    };

    pub const PeContext = extern struct {
        security_level: c.ocsd_sec_level,
        exception_level: c.ocsd_ex_level,
        context_id: u32,
        vmid: u32,
        packed_info: Packed,

        // TODO: verify that this type is ABI-compatible with the corresponding field(s)
        // declared in the c-api.
        pub const Packed = packed struct (u32) {
            is_64: bool,
            context_id_valid: bool,
            vmid_valid: bool,
            exception_level_valid: bool,
            _: u28 = 0,
        };
    };

    pub const ElemType = enum(c.ocsd_gen_trc_elem_t) {
        /// Unknown trace element - default value or indicate error in stream to client
        UNKNOWN = c.OCSD_GEN_TRC_ELEM_UNKNOWN,

        /// Waiting for sync - either at start of decode, or after overflow / bad packet
        NO_SYNC = c.OCSD_GEN_TRC_ELEM_NO_SYNC,

        /// Start of trace - beginning of elements or restart after discontinuity (overflow, trace filtering).
        TRACE_ON = c.OCSD_GEN_TRC_ELEM_TRACE_ON,

        /// end of the available trace in the buffer.
        EO_TRACE = c.OCSD_GEN_TRC_ELEM_EO_TRACE,

        /// PE status update / change (arch, ctxtid, vmid etc).
        PE_CONTEXT = c.OCSD_GEN_TRC_ELEM_PE_CONTEXT,

        /// traced N consecutive instructions from addr (no intervening events or data elements), may have data assoc key
        INSTR_RANGE = c.OCSD_GEN_TRC_ELEM_INSTR_RANGE,

        /// traced N instructions in a range, but incomplete information as to program execution path from start to end of range
        I_RANGE_NOPATH = c.OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH,

        /// tracing in inaccessible memory area
        ADDR_NACC = c.OCSD_GEN_TRC_ELEM_ADDR_NACC,

        /// address currently unknown - need address packet update
        ADDR_UNKNOWN = c.OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN,

        /// exception - start address may be exception target, end address may be preferred ret addr.
        EXCEPTION = c.OCSD_GEN_TRC_ELEM_EXCEPTION,

        /// expection return
        EXCEPTION_RET = c.OCSD_GEN_TRC_ELEM_EXCEPTION_RET,

        /// Timestamp - preceding elements happeded before this time.
        TIMESTAMP = c.OCSD_GEN_TRC_ELEM_TIMESTAMP,

        /// Cycle count - cycles since last cycle count value - associated with a preceding instruction range.
        CYCLE_COUNT = c.OCSD_GEN_TRC_ELEM_CYCLE_COUNT,

        /// Event - trigger or numbered event
        EVENT = c.OCSD_GEN_TRC_ELEM_EVENT,

        /// Software trace packet - may contain data payload. STM hardware trace with channel protocol
        SWTRACE = c.OCSD_GEN_TRC_ELEM_SWTRACE,

        /// Synchronisation marker - marks position in stream of an element that is output later.
        SYNC_MARKER = c.OCSD_GEN_TRC_ELEM_SYNC_MARKER,

        /// Trace indication of transactional memory operations.
        MEMTRANS = c.OCSD_GEN_TRC_ELEM_MEMTRANS,

        /// PE instrumentation trace - PE generated SW trace, application dependent protocol.
        INSTRUMENTATION = c.OCSD_GEN_TRC_ELEM_INSTRUMENTATION,

        /// Software trace packet - ITM hardware trace protocol.
        ITMTRACE = c.OCSD_GEN_TRC_ELEM_ITMTRACE,

        /// Fully custom packet type - used by none-ARM architecture decoders
        CUSTOM = c.OCSD_GEN_TRC_ELEM_CUSTOM,
    };
};

pub const Error = error {
    FAIL,
    MEM,
    NOT_INIT,
    INVALID_ID,
    BAD_HANDLE,
    INVALID_PARAM_VAL,
    INVALID_PARAM_TYPE,
    FILE_ERROR,
    NO_PROTOCOL,
    ATTACH_TOO_MANY,
    ATTACH_INVALID_PARAM,
    ATTACH_COMP_NOT_FOUND,
    RDR_FILE_NOT_FOUND,
    RDR_INVALID_INIT,
    RDR_NO_DECODER,
    DATA_DECODE_FATAL,
    DFMTR_NOTCONTTRACE,
    DFMTR_BAD_FHSYNC,
    BAD_PACKET_SEQ,
    INVALID_PCKT_HDR,
    PKT_INTERP_FAIL,
    UNSUPPORTED_ISA,
    HW_CFG_UNSUPP,
    UNSUPP_DECODE_PKT,
    BAD_DECODE_PKT,
    COMMIT_PKT_OVERRUN,
    MEM_NACC,
    RET_STACK_OVERFLOW,
    DCDT_NO_FORMATTER,
    MEM_ACC_OVERLAP,
    MEM_ACC_FILE_NOT_FOUND,
    MEM_ACC_FILE_DIFF_RANGE,
    MEM_ACC_RANGE_INVALID,
    MEM_ACC_BAD_LEN,
    TEST_SNAPSHOT_PARSE,
    TEST_SNAPSHOT_PARSE_INFO,
    TEST_SNAPSHOT_READ,
    TEST_SS_TO_DECODER,
    DCDREG_NAME_REPEAT,
    DCDREG_NAME_UNKNOWN,
    DCDREG_TYPE_UNKNOWN,
    DCDREG_TOOMANY,
    DCD_INTERFACE_UNUSED,
    INVALID_OPCODE,
    I_RANGE_LIMIT_OVERRUN,
    BAD_DECODE_IMAGE,
};

pub fn checkError(ret: c.ocsd_err_t) Error!void {
    return switch (ret) {
        c.OCSD_OK => {},
        c.OCSD_ERR_FAIL => error.FAIL,
        c.OCSD_ERR_MEM => error.MEM,
        c.OCSD_ERR_NOT_INIT => error.NOT_INIT,
        c.OCSD_ERR_INVALID_ID => error.INVALID_ID,
        c.OCSD_ERR_BAD_HANDLE => error.BAD_HANDLE,
        c.OCSD_ERR_INVALID_PARAM_VAL => error.INVALID_PARAM_VAL,
        c.OCSD_ERR_INVALID_PARAM_TYPE => error.INVALID_PARAM_TYPE,
        c.OCSD_ERR_FILE_ERROR => error.FILE_ERROR,
        c.OCSD_ERR_NO_PROTOCOL => error.NO_PROTOCOL,
        c.OCSD_ERR_ATTACH_TOO_MANY => error.ATTACH_TOO_MANY,
        c.OCSD_ERR_ATTACH_INVALID_PARAM => error.ATTACH_INVALID_PARAM,
        c.OCSD_ERR_ATTACH_COMP_NOT_FOUND => error.ATTACH_COMP_NOT_FOUND,
        c.OCSD_ERR_RDR_FILE_NOT_FOUND => error.RDR_FILE_NOT_FOUND,
        c.OCSD_ERR_RDR_INVALID_INIT => error.RDR_INVALID_INIT,
        c.OCSD_ERR_RDR_NO_DECODER => error.RDR_NO_DECODER,
        c.OCSD_ERR_DATA_DECODE_FATAL => error.DATA_DECODE_FATAL,
        c.OCSD_ERR_DFMTR_NOTCONTTRACE => error.DFMTR_NOTCONTTRACE,
        c.OCSD_ERR_DFMTR_BAD_FHSYNC => error.DFMTR_BAD_FHSYNC,
        c.OCSD_ERR_BAD_PACKET_SEQ => error.BAD_PACKET_SEQ,
        c.OCSD_ERR_INVALID_PCKT_HDR => error.INVALID_PCKT_HDR,
        c.OCSD_ERR_PKT_INTERP_FAIL => error.PKT_INTERP_FAIL,
        c.OCSD_ERR_UNSUPPORTED_ISA => error.UNSUPPORTED_ISA,
        c.OCSD_ERR_HW_CFG_UNSUPP => error.HW_CFG_UNSUPP,
        c.OCSD_ERR_UNSUPP_DECODE_PKT => error.UNSUPP_DECODE_PKT,
        c.OCSD_ERR_BAD_DECODE_PKT => error.BAD_DECODE_PKT,
        c.OCSD_ERR_COMMIT_PKT_OVERRUN => error.COMMIT_PKT_OVERRUN,
        c.OCSD_ERR_MEM_NACC => error.MEM_NACC,
        c.OCSD_ERR_RET_STACK_OVERFLOW => error.RET_STACK_OVERFLOW,
        c.OCSD_ERR_DCDT_NO_FORMATTER => error.DCDT_NO_FORMATTER,
        c.OCSD_ERR_MEM_ACC_OVERLAP => error.MEM_ACC_OVERLAP,
        c.OCSD_ERR_MEM_ACC_FILE_NOT_FOUND => error.MEM_ACC_FILE_NOT_FOUND,
        c.OCSD_ERR_MEM_ACC_FILE_DIFF_RANGE => error.MEM_ACC_FILE_DIFF_RANGE,
        c.OCSD_ERR_MEM_ACC_RANGE_INVALID => error.MEM_ACC_RANGE_INVALID,
        c.OCSD_ERR_MEM_ACC_BAD_LEN => error.MEM_ACC_BAD_LEN,
        c.OCSD_ERR_TEST_SNAPSHOT_PARSE => error.TEST_SNAPSHOT_PARSE,
        c.OCSD_ERR_TEST_SNAPSHOT_PARSE_INFO => error.TEST_SNAPSHOT_PARSE_INFO,
        c.OCSD_ERR_TEST_SNAPSHOT_READ => error.TEST_SNAPSHOT_READ,
        c.OCSD_ERR_TEST_SS_TO_DECODER => error.TEST_SS_TO_DECODER,
        c.OCSD_ERR_DCDREG_NAME_REPEAT => error.DCDREG_NAME_REPEAT,
        c.OCSD_ERR_DCDREG_NAME_UNKNOWN => error.DCDREG_NAME_UNKNOWN,
        c.OCSD_ERR_DCDREG_TYPE_UNKNOWN => error.DCDREG_TYPE_UNKNOWN,
        c.OCSD_ERR_DCDREG_TOOMANY => error.DCDREG_TOOMANY,
        c.OCSD_ERR_DCD_INTERFACE_UNUSED => error.DCD_INTERFACE_UNUSED,
        c.OCSD_ERR_INVALID_OPCODE => error.INVALID_OPCODE,
        c.OCSD_ERR_I_RANGE_LIMIT_OVERRUN => error.I_RANGE_LIMIT_OVERRUN,
        c.OCSD_ERR_BAD_DECODE_IMAGE => error.BAD_DECODE_IMAGE,
        else => unreachable,
    };
}

// 1. Go to translate-c output file
// 2. %g!/\c^pub \%(const\|extern fn\) ocsd_/d
// 3. %s/\cpub \%(const\|extern fn\) \(ocsd_\)\(\w\+\)\W.*/pub const \2 = c.\1\2;
// 4. Yank everything
// 5. Profit
pub const trc_index_t = c.ocsd_trc_index_t;
pub const OK = c.OCSD_OK;
pub const ERR_FAIL = c.OCSD_ERR_FAIL;
pub const ERR_MEM = c.OCSD_ERR_MEM;
pub const ERR_NOT_INIT = c.OCSD_ERR_NOT_INIT;
pub const ERR_INVALID_ID = c.OCSD_ERR_INVALID_ID;
pub const ERR_BAD_HANDLE = c.OCSD_ERR_BAD_HANDLE;
pub const ERR_INVALID_PARAM_VAL = c.OCSD_ERR_INVALID_PARAM_VAL;
pub const ERR_INVALID_PARAM_TYPE = c.OCSD_ERR_INVALID_PARAM_TYPE;
pub const ERR_FILE_ERROR = c.OCSD_ERR_FILE_ERROR;
pub const ERR_NO_PROTOCOL = c.OCSD_ERR_NO_PROTOCOL;
pub const ERR_ATTACH_TOO_MANY = c.OCSD_ERR_ATTACH_TOO_MANY;
pub const ERR_ATTACH_INVALID_PARAM = c.OCSD_ERR_ATTACH_INVALID_PARAM;
pub const ERR_ATTACH_COMP_NOT_FOUND = c.OCSD_ERR_ATTACH_COMP_NOT_FOUND;
pub const ERR_RDR_FILE_NOT_FOUND = c.OCSD_ERR_RDR_FILE_NOT_FOUND;
pub const ERR_RDR_INVALID_INIT = c.OCSD_ERR_RDR_INVALID_INIT;
pub const ERR_RDR_NO_DECODER = c.OCSD_ERR_RDR_NO_DECODER;
pub const ERR_DATA_DECODE_FATAL = c.OCSD_ERR_DATA_DECODE_FATAL;
pub const ERR_DFMTR_NOTCONTTRACE = c.OCSD_ERR_DFMTR_NOTCONTTRACE;
pub const ERR_DFMTR_BAD_FHSYNC = c.OCSD_ERR_DFMTR_BAD_FHSYNC;
pub const ERR_BAD_PACKET_SEQ = c.OCSD_ERR_BAD_PACKET_SEQ;
pub const ERR_INVALID_PCKT_HDR = c.OCSD_ERR_INVALID_PCKT_HDR;
pub const ERR_PKT_INTERP_FAIL = c.OCSD_ERR_PKT_INTERP_FAIL;
pub const ERR_UNSUPPORTED_ISA = c.OCSD_ERR_UNSUPPORTED_ISA;
pub const ERR_HW_CFG_UNSUPP = c.OCSD_ERR_HW_CFG_UNSUPP;
pub const ERR_UNSUPP_DECODE_PKT = c.OCSD_ERR_UNSUPP_DECODE_PKT;
pub const ERR_BAD_DECODE_PKT = c.OCSD_ERR_BAD_DECODE_PKT;
pub const ERR_COMMIT_PKT_OVERRUN = c.OCSD_ERR_COMMIT_PKT_OVERRUN;
pub const ERR_MEM_NACC = c.OCSD_ERR_MEM_NACC;
pub const ERR_RET_STACK_OVERFLOW = c.OCSD_ERR_RET_STACK_OVERFLOW;
pub const ERR_DCDT_NO_FORMATTER = c.OCSD_ERR_DCDT_NO_FORMATTER;
pub const ERR_MEM_ACC_OVERLAP = c.OCSD_ERR_MEM_ACC_OVERLAP;
pub const ERR_MEM_ACC_FILE_NOT_FOUND = c.OCSD_ERR_MEM_ACC_FILE_NOT_FOUND;
pub const ERR_MEM_ACC_FILE_DIFF_RANGE = c.OCSD_ERR_MEM_ACC_FILE_DIFF_RANGE;
pub const ERR_MEM_ACC_RANGE_INVALID = c.OCSD_ERR_MEM_ACC_RANGE_INVALID;
pub const ERR_MEM_ACC_BAD_LEN = c.OCSD_ERR_MEM_ACC_BAD_LEN;
pub const ERR_TEST_SNAPSHOT_PARSE = c.OCSD_ERR_TEST_SNAPSHOT_PARSE;
pub const ERR_TEST_SNAPSHOT_PARSE_INFO = c.OCSD_ERR_TEST_SNAPSHOT_PARSE_INFO;
pub const ERR_TEST_SNAPSHOT_READ = c.OCSD_ERR_TEST_SNAPSHOT_READ;
pub const ERR_TEST_SS_TO_DECODER = c.OCSD_ERR_TEST_SS_TO_DECODER;
pub const ERR_DCDREG_NAME_REPEAT = c.OCSD_ERR_DCDREG_NAME_REPEAT;
pub const ERR_DCDREG_NAME_UNKNOWN = c.OCSD_ERR_DCDREG_NAME_UNKNOWN;
pub const ERR_DCDREG_TYPE_UNKNOWN = c.OCSD_ERR_DCDREG_TYPE_UNKNOWN;
pub const ERR_DCDREG_TOOMANY = c.OCSD_ERR_DCDREG_TOOMANY;
pub const ERR_DCD_INTERFACE_UNUSED = c.OCSD_ERR_DCD_INTERFACE_UNUSED;
pub const ERR_INVALID_OPCODE = c.OCSD_ERR_INVALID_OPCODE;
pub const ERR_I_RANGE_LIMIT_OVERRUN = c.OCSD_ERR_I_RANGE_LIMIT_OVERRUN;
pub const ERR_BAD_DECODE_IMAGE = c.OCSD_ERR_BAD_DECODE_IMAGE;
pub const ERR_LAST = c.OCSD_ERR_LAST;
pub const err_t = c.ocsd_err_t;
pub const hndl_rdr_t = c.ocsd_hndl_rdr_t;
pub const hndl_err_log_t = c.ocsd_hndl_err_log_t;
pub const ERR_SEV_NONE = c.OCSD_ERR_SEV_NONE;
pub const ERR_SEV_ERROR = c.OCSD_ERR_SEV_ERROR;
pub const ERR_SEV_WARN = c.OCSD_ERR_SEV_WARN;
pub const ERR_SEV_INFO = c.OCSD_ERR_SEV_INFO;
pub const err_severity_t = c.ocsd_err_severity_t;
pub const OP_DATA = c.OCSD_OP_DATA;
pub const OP_EOT = c.OCSD_OP_EOT;
pub const OP_FLUSH = c.OCSD_OP_FLUSH;
pub const OP_RESET = c.OCSD_OP_RESET;
pub const datapath_op_t = c.ocsd_datapath_op_t;
pub const RESP_CONT = c.OCSD_RESP_CONT;
pub const RESP_WARN_CONT = c.OCSD_RESP_WARN_CONT;
pub const RESP_ERR_CONT = c.OCSD_RESP_ERR_CONT;
pub const RESP_WAIT = c.OCSD_RESP_WAIT;
pub const RESP_WARN_WAIT = c.OCSD_RESP_WARN_WAIT;
pub const RESP_ERR_WAIT = c.OCSD_RESP_ERR_WAIT;
pub const RESP_FATAL_NOT_INIT = c.OCSD_RESP_FATAL_NOT_INIT;
pub const RESP_FATAL_INVALID_OP = c.OCSD_RESP_FATAL_INVALID_OP;
pub const RESP_FATAL_INVALID_PARAM = c.OCSD_RESP_FATAL_INVALID_PARAM;
pub const RESP_FATAL_INVALID_DATA = c.OCSD_RESP_FATAL_INVALID_DATA;
pub const RESP_FATAL_SYS_ERR = c.OCSD_RESP_FATAL_SYS_ERR;
pub const datapath_resp_t = c.ocsd_datapath_resp_t;
pub const FRM_NONE = c.OCSD_FRM_NONE;
pub const FRM_PACKED = c.OCSD_FRM_PACKED;
pub const FRM_HSYNC = c.OCSD_FRM_HSYNC;
pub const FRM_FSYNC = c.OCSD_FRM_FSYNC;
pub const FRM_ID_DATA = c.OCSD_FRM_ID_DATA;
pub const rawframe_elem_t = c.ocsd_rawframe_elem_t;
pub const TRC_SRC_FRAME_FORMATTED = c.OCSD_TRC_SRC_FRAME_FORMATTED;
pub const TRC_SRC_SINGLE = c.OCSD_TRC_SRC_SINGLE;
pub const dcd_tree_src_t = c.ocsd_dcd_tree_src_t;
pub const arch_version_t = c.ocsd_arch_version_t;
pub const core_profile_t = c.ocsd_core_profile_t;
pub const arch_profile_t = c.ocsd_arch_profile_t;
pub const vaddr_t = c.ocsd_vaddr_t;
pub const isa_arm = c.ocsd_isa_arm;
pub const isa_thumb2 = c.ocsd_isa_thumb2;
pub const isa_aarch64 = c.ocsd_isa_aarch64;
pub const isa_tee = c.ocsd_isa_tee;
pub const isa_jazelle = c.ocsd_isa_jazelle;
pub const isa_custom = c.ocsd_isa_custom;
pub const isa_unknown = c.ocsd_isa_unknown;
pub const isa = c.ocsd_isa;
pub const sec_secure = c.ocsd_sec_secure;
pub const sec_nonsecure = c.ocsd_sec_nonsecure;
pub const sec_root = c.ocsd_sec_root;
pub const sec_realm = c.ocsd_sec_realm;
pub const sec_level = c.ocsd_sec_level;
pub const EL_unknown = c.ocsd_EL_unknown;
pub const EL0 = c.ocsd_EL0;
pub const EL1 = c.ocsd_EL1;
pub const EL2 = c.ocsd_EL2;
pub const EL3 = c.ocsd_EL3;
pub const ex_level = c.ocsd_ex_level;
pub const INSTR_OTHER = c.OCSD_INSTR_OTHER;
pub const INSTR_BR = c.OCSD_INSTR_BR;
pub const INSTR_BR_INDIRECT = c.OCSD_INSTR_BR_INDIRECT;
pub const INSTR_ISB = c.OCSD_INSTR_ISB;
pub const INSTR_DSB_DMB = c.OCSD_INSTR_DSB_DMB;
pub const INSTR_WFI_WFE = c.OCSD_INSTR_WFI_WFE;
pub const INSTR_TSTART = c.OCSD_INSTR_TSTART;
pub const instr_type = c.ocsd_instr_type;
pub const S_INSTR_NONE = c.OCSD_S_INSTR_NONE;
pub const S_INSTR_BR_LINK = c.OCSD_S_INSTR_BR_LINK;
pub const S_INSTR_V8_RET = c.OCSD_S_INSTR_V8_RET;
pub const S_INSTR_V8_ERET = c.OCSD_S_INSTR_V8_ERET;
pub const S_INSTR_V7_IMPLIED_RET = c.OCSD_S_INSTR_V7_IMPLIED_RET;
pub const instr_subtype = c.ocsd_instr_subtype;
pub const instr_info = c.ocsd_instr_info;
pub const pe_context = c.ocsd_pe_context;
pub const MEM_SPACE_NONE = c.OCSD_MEM_SPACE_NONE;
pub const MEM_SPACE_EL1S = c.OCSD_MEM_SPACE_EL1S;
pub const MEM_SPACE_EL1N = c.OCSD_MEM_SPACE_EL1N;
pub const MEM_SPACE_EL2 = c.OCSD_MEM_SPACE_EL2;
pub const MEM_SPACE_EL3 = c.OCSD_MEM_SPACE_EL3;
pub const MEM_SPACE_EL2S = c.OCSD_MEM_SPACE_EL2S;
pub const MEM_SPACE_EL1R = c.OCSD_MEM_SPACE_EL1R;
pub const MEM_SPACE_EL2R = c.OCSD_MEM_SPACE_EL2R;
pub const MEM_SPACE_ROOT = c.OCSD_MEM_SPACE_ROOT;
pub const MEM_SPACE_S = c.OCSD_MEM_SPACE_S;
pub const MEM_SPACE_N = c.OCSD_MEM_SPACE_N;
pub const MEM_SPACE_R = c.OCSD_MEM_SPACE_R;
pub const MEM_SPACE_ANY = c.OCSD_MEM_SPACE_ANY;
pub const mem_space_acc_t = c.ocsd_mem_space_acc_t;
pub const file_mem_region_t = c.ocsd_file_mem_region_t;
pub const PROTOCOL_UNKNOWN = c.OCSD_PROTOCOL_UNKNOWN;
pub const PROTOCOL_ETMV3 = c.OCSD_PROTOCOL_ETMV3;
pub const PROTOCOL_ETMV4I = c.OCSD_PROTOCOL_ETMV4I;
pub const PROTOCOL_ETMV4D = c.OCSD_PROTOCOL_ETMV4D;
pub const PROTOCOL_PTM = c.OCSD_PROTOCOL_PTM;
pub const PROTOCOL_STM = c.OCSD_PROTOCOL_STM;
pub const PROTOCOL_ETE = c.OCSD_PROTOCOL_ETE;
pub const PROTOCOL_ITM = c.OCSD_PROTOCOL_ITM;
pub const PROTOCOL_BUILTIN_END = c.OCSD_PROTOCOL_BUILTIN_END;
pub const PROTOCOL_CUSTOM_0 = c.OCSD_PROTOCOL_CUSTOM_0;
pub const PROTOCOL_CUSTOM_1 = c.OCSD_PROTOCOL_CUSTOM_1;
pub const PROTOCOL_CUSTOM_2 = c.OCSD_PROTOCOL_CUSTOM_2;
pub const PROTOCOL_CUSTOM_3 = c.OCSD_PROTOCOL_CUSTOM_3;
pub const PROTOCOL_CUSTOM_4 = c.OCSD_PROTOCOL_CUSTOM_4;
pub const PROTOCOL_CUSTOM_5 = c.OCSD_PROTOCOL_CUSTOM_5;
pub const PROTOCOL_CUSTOM_6 = c.OCSD_PROTOCOL_CUSTOM_6;
pub const PROTOCOL_CUSTOM_7 = c.OCSD_PROTOCOL_CUSTOM_7;
pub const PROTOCOL_CUSTOM_8 = c.OCSD_PROTOCOL_CUSTOM_8;
pub const PROTOCOL_CUSTOM_9 = c.OCSD_PROTOCOL_CUSTOM_9;
pub const PROTOCOL_END = c.OCSD_PROTOCOL_END;
pub const trace_protocol_t = c.ocsd_trace_protocol_t;
pub const swt_info_t = c.ocsd_swt_info_t;
pub const demux_stats_t = c.ocsd_demux_stats_t;
pub const decode_stats_t = c.ocsd_decode_stats_t;
pub const GEN_TRC_ELEM_UNKNOWN = c.OCSD_GEN_TRC_ELEM_UNKNOWN;
pub const GEN_TRC_ELEM_NO_SYNC = c.OCSD_GEN_TRC_ELEM_NO_SYNC;
pub const GEN_TRC_ELEM_TRACE_ON = c.OCSD_GEN_TRC_ELEM_TRACE_ON;
pub const GEN_TRC_ELEM_EO_TRACE = c.OCSD_GEN_TRC_ELEM_EO_TRACE;
pub const GEN_TRC_ELEM_PE_CONTEXT = c.OCSD_GEN_TRC_ELEM_PE_CONTEXT;
pub const GEN_TRC_ELEM_INSTR_RANGE = c.OCSD_GEN_TRC_ELEM_INSTR_RANGE;
pub const GEN_TRC_ELEM_I_RANGE_NOPATH = c.OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH;
pub const GEN_TRC_ELEM_ADDR_NACC = c.OCSD_GEN_TRC_ELEM_ADDR_NACC;
pub const GEN_TRC_ELEM_ADDR_UNKNOWN = c.OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN;
pub const GEN_TRC_ELEM_EXCEPTION = c.OCSD_GEN_TRC_ELEM_EXCEPTION;
pub const GEN_TRC_ELEM_EXCEPTION_RET = c.OCSD_GEN_TRC_ELEM_EXCEPTION_RET;
pub const GEN_TRC_ELEM_TIMESTAMP = c.OCSD_GEN_TRC_ELEM_TIMESTAMP;
pub const GEN_TRC_ELEM_CYCLE_COUNT = c.OCSD_GEN_TRC_ELEM_CYCLE_COUNT;
pub const GEN_TRC_ELEM_EVENT = c.OCSD_GEN_TRC_ELEM_EVENT;
pub const GEN_TRC_ELEM_SWTRACE = c.OCSD_GEN_TRC_ELEM_SWTRACE;
pub const GEN_TRC_ELEM_SYNC_MARKER = c.OCSD_GEN_TRC_ELEM_SYNC_MARKER;
pub const GEN_TRC_ELEM_MEMTRANS = c.OCSD_GEN_TRC_ELEM_MEMTRANS;
pub const GEN_TRC_ELEM_INSTRUMENTATION = c.OCSD_GEN_TRC_ELEM_INSTRUMENTATION;
pub const GEN_TRC_ELEM_ITMTRACE = c.OCSD_GEN_TRC_ELEM_ITMTRACE;
pub const GEN_TRC_ELEM_CUSTOM = c.OCSD_GEN_TRC_ELEM_CUSTOM;
pub const gen_trc_elem_t = c.ocsd_gen_trc_elem_t;
pub const MEM_TRANS_TRACE_INIT = c.OCSD_MEM_TRANS_TRACE_INIT;
pub const MEM_TRANS_START = c.OCSD_MEM_TRANS_START;
pub const MEM_TRANS_COMMIT = c.OCSD_MEM_TRANS_COMMIT;
pub const MEM_TRANS_FAIL = c.OCSD_MEM_TRANS_FAIL;
pub const generic_trace_elem = c.ocsd_generic_trace_elem;
pub const pkt_va_size = c.ocsd_pkt_va_size;
pub const pkt_vaddr = c.ocsd_pkt_vaddr;
pub const pkt_byte_sz_val = c.ocsd_pkt_byte_sz_val;
pub const pkt_atm_type = c.ocsd_pkt_atm_type;
pub const atm_val = c.ocsd_atm_val;
pub const pkt_atom = c.ocsd_pkt_atom;
pub const iSync_reason = c.ocsd_iSync_reason;
pub const armv7_exception = c.ocsd_armv7_exception;
pub const etmv3_pkt_type = c.ocsd_etmv3_pkt_type;
pub const etmv3_excep = c.ocsd_etmv3_excep;
pub const etmv3_pkt = c.ocsd_etmv3_pkt;
pub const etmv3_cfg = c.ocsd_etmv3_cfg;
pub const etmv4_i_pkt_type = c.ocsd_etmv4_i_pkt_type;
pub const etmv4_i_pkt = c.ocsd_etmv4_i_pkt;
pub const etmv4_d_pkt_type = c.ocsd_etmv4_d_pkt_type;
pub const etmv4_d_pkt = c.ocsd_etmv4_d_pkt;
pub const etmv4_cfg = c.ocsd_etmv4_cfg;
pub const ptm_pkt_type = c.ocsd_ptm_pkt_type;
pub const ptm_excep = c.ocsd_ptm_excep;
pub const ptm_pkt = c.ocsd_ptm_pkt;
pub const ptm_cfg = c.ocsd_ptm_cfg;
pub const stm_pkt_type = c.ocsd_stm_pkt_type;
pub const stm_ts_type = c.ocsd_stm_ts_type;
pub const stm_pkt = c.ocsd_stm_pkt;
pub const stm_cfg = c.ocsd_stm_cfg;
pub const ete_cfg = c.ocsd_ete_cfg;
pub const C_API_CB_PKT_SINK = c.OCSD_C_API_CB_PKT_SINK;
pub const C_API_CB_PKT_MON = c.OCSD_C_API_CB_PKT_MON;
pub const c_api_cb_types = c.ocsd_c_api_cb_types;
pub const extern_dcd_inst_t = c.ocsd_extern_dcd_inst_t;
pub const extern_dcd_cb_fns = c.ocsd_extern_dcd_cb_fns;
pub const extern_dcd_fact_t = c.ocsd_extern_dcd_fact_t;
pub const get_version = c.ocsd_get_version;
pub const get_version_str = c.ocsd_get_version_str;
pub const create_dcd_tree = c.ocsd_create_dcd_tree;
pub const destroy_dcd_tree = c.ocsd_destroy_dcd_tree;
pub const dt_process_data = c.ocsd_dt_process_data;
pub const dt_set_gen_elem_outfn = c.ocsd_dt_set_gen_elem_outfn;
pub const dt_create_decoder = c.ocsd_dt_create_decoder;
pub const dt_remove_decoder = c.ocsd_dt_remove_decoder;
pub const dt_attach_packet_callback = c.ocsd_dt_attach_packet_callback;
pub const dt_get_decode_stats = c.ocsd_dt_get_decode_stats;
pub const dt_reset_decode_stats = c.ocsd_dt_reset_decode_stats;
pub const dt_add_binfile_mem_acc = c.ocsd_dt_add_binfile_mem_acc;
pub const dt_add_binfile_region_mem_acc = c.ocsd_dt_add_binfile_region_mem_acc;
pub const dt_add_buffer_mem_acc = c.ocsd_dt_add_buffer_mem_acc;
pub const dt_add_callback_mem_acc = c.ocsd_dt_add_callback_mem_acc;
pub const dt_add_callback_trcid_mem_acc = c.ocsd_dt_add_callback_trcid_mem_acc;
pub const dt_remove_mem_acc = c.ocsd_dt_remove_mem_acc;
pub const tl_log_mapped_mem_ranges = c.ocsd_tl_log_mapped_mem_ranges;
pub const dt_set_mem_acc_cacheing = c.ocsd_dt_set_mem_acc_cacheing;
pub const def_errlog_init = c.ocsd_def_errlog_init;
pub const def_errlog_config_output = c.ocsd_def_errlog_config_output;
pub const def_errlog_set_strprint_cb = c.ocsd_def_errlog_set_strprint_cb;
pub const def_errlog_msgout = c.ocsd_def_errlog_msgout;
pub const err_str = c.ocsd_err_str;
pub const get_last_err = c.ocsd_get_last_err;
pub const pkt_str = c.ocsd_pkt_str;
pub const gen_elem_str = c.ocsd_gen_elem_str;
pub const gen_elem_init = c.ocsd_gen_elem_init;
pub const dt_set_raw_frame_printer = c.ocsd_dt_set_raw_frame_printer;
pub const dt_set_gen_elem_printer = c.ocsd_dt_set_gen_elem_printer;
pub const dt_set_pkt_protocol_printer = c.ocsd_dt_set_pkt_protocol_printer;
pub const register_custom_decoder = c.ocsd_register_custom_decoder;
pub const deregister_decoders = c.ocsd_deregister_decoders;
pub const cust_protocol_to_str = c.ocsd_cust_protocol_to_str;
pub const C_API = c.OCSD_C_API;
pub const TRC_IDX_STR = c.OCSD_TRC_IDX_STR;
pub const BAD_TRC_INDEX = c.OCSD_BAD_TRC_INDEX;
pub const BAD_CS_SRC_ID = c.OCSD_BAD_CS_SRC_ID;
pub const IS_RESERVED_CS_SRC_ID = c.OCSD_IS_RESERVED_CS_SRC_ID;
pub const INVALID_HANDLE = c.OCSD_INVALID_HANDLE;
pub const DFRMTR_HAS_FSYNCS = c.OCSD_DFRMTR_HAS_FSYNCS;
pub const DFRMTR_HAS_HSYNCS = c.OCSD_DFRMTR_HAS_HSYNCS;
pub const DFRMTR_FRAME_MEM_ALIGN = c.OCSD_DFRMTR_FRAME_MEM_ALIGN;
pub const DFRMTR_PACKED_RAW_OUT = c.OCSD_DFRMTR_PACKED_RAW_OUT;
pub const DFRMTR_UNPACKED_RAW_OUT = c.OCSD_DFRMTR_UNPACKED_RAW_OUT;
pub const DFRMTR_RESET_ON_4X_FSYNC = c.OCSD_DFRMTR_RESET_ON_4X_FSYNC;
pub const DFRMTR_VALID_MASK = c.OCSD_DFRMTR_VALID_MASK;
pub const DFRMTR_FRAME_SIZE = c.OCSD_DFRMTR_FRAME_SIZE;
pub const CMPNAME_PREFIX_SOURCE_READER = c.OCSD_CMPNAME_PREFIX_SOURCE_READER;
pub const CMPNAME_PREFIX_FRAMEDEFORMATTER = c.OCSD_CMPNAME_PREFIX_FRAMEDEFORMATTER;
pub const CMPNAME_PREFIX_PKTPROC = c.OCSD_CMPNAME_PREFIX_PKTPROC;
pub const CMPNAME_PREFIX_PKTDEC = c.OCSD_CMPNAME_PREFIX_PKTDEC;
pub const MAX_VA_BITSIZE = c.OCSD_MAX_VA_BITSIZE;
pub const VA_MASK = c.OCSD_VA_MASK;
pub const OPFLG_PKTPROC_NOFWD_BAD_PKTS = c.OCSD_OPFLG_PKTPROC_NOFWD_BAD_PKTS;
pub const OPFLG_PKTPROC_NOMON_BAD_PKTS = c.OCSD_OPFLG_PKTPROC_NOMON_BAD_PKTS;
pub const OPFLG_PKTPROC_ERR_BAD_PKTS = c.OCSD_OPFLG_PKTPROC_ERR_BAD_PKTS;
pub const OPFLG_PKTPROC_UNSYNC_ON_BAD_PKTS = c.OCSD_OPFLG_PKTPROC_UNSYNC_ON_BAD_PKTS;
pub const OPFLG_PKTPROC_COMMON = c.OCSD_OPFLG_PKTPROC_COMMON;
pub const OPFLG_COMP_MODE_MASK = c.OCSD_OPFLG_COMP_MODE_MASK;
pub const OPFLG_PKTDEC_ERROR_BAD_PKTS = c.OCSD_OPFLG_PKTDEC_ERROR_BAD_PKTS;
pub const OPFLG_PKTDEC_HALT_BAD_PKTS = c.OCSD_OPFLG_PKTDEC_HALT_BAD_PKTS;
pub const OPFLG_N_UNCOND_DIR_BR_CHK = c.OCSD_OPFLG_N_UNCOND_DIR_BR_CHK;
pub const OPFLG_STRICT_N_UNCOND_BR_CHK = c.OCSD_OPFLG_STRICT_N_UNCOND_BR_CHK;
pub const OPFLG_CHK_RANGE_CONTINUE = c.OCSD_OPFLG_CHK_RANGE_CONTINUE;
pub const OPFLG_N_UNCOND_CHK_NO_THUMB = c.OCSD_OPFLG_N_UNCOND_CHK_NO_THUMB;
pub const OPFLG_PKTDEC_COMMON = c.OCSD_OPFLG_PKTDEC_COMMON;
pub const CREATE_FLG_PACKET_PROC = c.OCSD_CREATE_FLG_PACKET_PROC;
pub const CREATE_FLG_FULL_DECODER = c.OCSD_CREATE_FLG_FULL_DECODER;
pub const CREATE_FLG_INST_ID = c.OCSD_CREATE_FLG_INST_ID;
pub const BUILTIN_DCD_STM = c.OCSD_BUILTIN_DCD_STM;
pub const BUILTIN_DCD_ETMV3 = c.OCSD_BUILTIN_DCD_ETMV3;
pub const BUILTIN_DCD_ETMV4I = c.OCSD_BUILTIN_DCD_ETMV4I;
pub const BUILTIN_DCD_ETMV4D = c.OCSD_BUILTIN_DCD_ETMV4D;
pub const BUILTIN_DCD_PTM = c.OCSD_BUILTIN_DCD_PTM;
pub const BUILTIN_DCD_ETE = c.OCSD_BUILTIN_DCD_ETE;
pub const BUILTIN_DCD_ITM = c.OCSD_BUILTIN_DCD_ITM;
pub const STATS_REVISION = c.OCSD_STATS_REVISION;
pub const VER_MAJOR = c.OCSD_VER_MAJOR;
pub const VER_MINOR = c.OCSD_VER_MINOR;
pub const VER_PATCH = c.OCSD_VER_PATCH;
pub const VER_NUM = c.OCSD_VER_NUM;
pub const VER_STRING = c.OCSD_VER_STRING;
pub const LIB_NAME = c.OCSD_LIB_NAME;
pub const LIB_SHORT_NAME = c.OCSD_LIB_SHORT_NAME;
pub const CUST_DCD_PKT_CB_USE_MON = c.OCSD_CUST_DCD_PKT_CB_USE_MON;
pub const CUST_DCD_PKT_CB_USE_SINK = c.OCSD_CUST_DCD_PKT_CB_USE_SINK;
