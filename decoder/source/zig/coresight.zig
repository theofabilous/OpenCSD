const std = @import("std");
const opencsd = @import("opencsd.zig");
const Io = std.Io;
const assert = std.debug.assert;

pub const TraceId = enum (u7) {
    /// NULL trace source ID. Data associated with this ID should be ignored
    null = NULL,
    /// Indicates a flush response.
    /// See CoreSight v3.0 Architecture Specification D.4.2.4
    /// NOTE: might also be allowed as a general ATB ID?
    flush = FLUSH,
    /// Indicates a trigger within the trace stream.
    /// See CoreSight v3.0 Architecture Specification D.4.2.4
    /// NOTE: might also be allowed as a general ATB ID? AMBA ATB mentions the ATID of
    ///       0x7D for trace triggers specifically, with semantics that seem to match
    ///       those discussed in the coresight manual, so idk
    trigger = TRIGGER,
    invalid_sync_packet_collision = INVALID_SYNC_PACKET_COLLISION,
    _,

    pub fn initATID(id_int: u7) error{Reserved}!TraceId {
        const id: TraceId = @enumFromInt(id_int);
        if (id.isValidGeneralPurposeATID()) {
            return id;
        } else {
            return error.Reserved;
        }
    }

    // TODO: see notes for `flush` and `trigger`, those may technically be valid
    // general purpose ATIDs in some cases? maybe?
    pub fn isValidGeneralPurposeATID(id: TraceId) bool {
        return switch (@intFromEnum(id)) {
            NULL, 0x70...INVALID_SYNC_PACKET_COLLISION => false,
            else => true,
        };
    }

    pub fn isReserved(id: TraceId) bool {
        return switch (@intFromEnum(id)) {
            0x70...0x7A, 0x7C, 0x7E, INVALID_SYNC_PACKET_COLLISION => true,
            else => false,
        };
    }

    const NULL: u7 = 0x00;
    const FLUSH: u7 = 0x7B;
    const TRIGGER: u7 = 0x7D;
    const INVALID_SYNC_PACKET_COLLISION: u7 = 0x7F;
};

pub const FormatterFrame = extern struct {
    chunks: [8]Chunk,

    pub fn auxBit(ff: *const FormatterFrame, index: Chunk.Index) u1 {
        const aux_bits = ff.chunks[Chunk.max_index].data;
        return @truncate(aux_bits >> index);
    }

    pub const AuxIdBit = enum(u1) {
        next_byte_for_old_id = 0,
        next_byte_for_new_id = 1,
    };

    pub const Chunk = extern struct {
        id_or_data: IdOrData,
        data: u8,

        pub const IdOrData = packed struct (u8) {
            id: bool,
            rest: u7,
        };

        pub const Index = u3;
        const max_index = std.math.maxInt(Index);
    };

    pub const DataIterator = struct {
        curr_id: u7,
        frame: *const FormatterFrame,
        index: u8,

        pub const Item = struct {
            id: u7,
            data: []const u8,
        };

        pub fn init(id: u7, frame: *const FormatterFrame) DataIterator {
            return .{
                .curr_id = id,
                .frame = frame,
                .index = 0,
            };
        }

        pub fn next(it: *DataIterator, buffer: *[2]u8) ?Item {
            if (it.index > Chunk.max_index) return null;
            defer it.index += 1;
            const chunk_index: Chunk.Index = @truncate(it.index);
            const chunk = it.frame.chunks[chunk_index];
            const aux_bit = it.frame.auxBit(chunk_index);
            const one_if_last = @intFromBool(chunk_index == Chunk.max_index);
            // Always write the full 2-byte chunk, then adjust the returned item's slice
            // length as needed
            buffer[0..2].* = @as([2]u8, @bitCast(chunk));
            if (chunk.id_or_data.id) {
                const new_id = chunk.id_or_data.rest;
                defer it.curr_id = new_id;
                const aux_id: AuxIdBit = @enumFromInt(aux_bit);
                return .{
                    // For the last chunk, this has no meaning since the the data buffer
                    // is empty
                    .id = switch (aux_id) {
                        .next_byte_for_old_id => it.curr_id,
                        .next_byte_for_new_id => new_id,
                    },
                    .data = buffer[0..1-one_if_last],
                };
            } else {
                // For data bytes, the aux bit corresponds to bit 0 of the data. The bit
                // at that position must be 0, due to it being the id/data discriminator,
                // and 0 indicates data, so the `or` here is fine.
                buffer[0] |= aux_bit;
                return .{
                    .id = it.curr_id,
                    .data = buffer[0..2-one_if_last],
                };
            }
        }
    };
};

pub const Deformatter = struct {
    reader: *Io.Reader,
    flags: Flags,
    logical_position: usize,

    const min_buffer_capacity = 32;

    pub const hsync: u16 = 0x7F_FF;
    pub const fsync: u32 = 0x7F_FF_FF_FF;
    pub const hsync_bytes = std.mem.toBytes(hsync);
    pub const fsync_bytes = std.mem.toBytes(fsync);

    pub fn synchronize(df: *Deformatter) !void {
        const r = df.reader;
        assert(r.buffer.len >= min_buffer_capacity);
        const min_size = switch (df.flags.sync) {
            .aligned => unreachable,
            .hsync_fsync => hsync_bytes.len,
            .fsync => fsync_bytes.len,
        };
        if (r.bufferedLen() < min_size) try r.fillMore();
        while (true) {
            const buffered = r.buffered();
            if (std.mem.find(u8, buffered, hsync_bytes)) |pos| {
                _ = pos;
            } else {
                // As it stands, both unaligned modes (fsync and hsync+fsync) accept fsyncs,
                // however the hsync+fsync mode allows shorter buffer lengths. hsync+fsync mode
                // is such that the minimum buffer size can both be valid AND hold a potential
                // fsync prefix.
                //
                // Keep a potential FSYNC/HSYNC byte prefix buffered before refilling the
                // buffer if we didn't find any sync points.
                //
                // The `-1` on the `buffered.len` operand is used so that we can guarantee that
                // the preserved byte sequence length is strictly less than the buffered length. Without
                // this, we risk keeping an FSYNC prefix candidate buffered in a way that would prevent
                // us from ever moving forward if HSYNC frames are enabled (0xFF_FF is a candidate, but
                // also long enough to inhibit a buffer refill due to it being 2-bytes long). This
                // is still correct though,
                const trail_size = @min(buffered.len-1, fsync_bytes.len-1);
                // TODO: ensure we don't risk looping forever if HSYNCs are enabled...
                // i feel like theres a chance that if we have 0xFFFF at the end of our
                // buffer, we'll keep those bytes, thereby satisfying the `min_size` requirement
                // and bypassing the call to fillMore(). In that case we'll fail to find any sync
                // bytes, and then land back here, keep the bytes buffered, and spin forever...
                //
                // Probably could be mitigated by reorganizing when/where the buffer is refilled
                const keep = for (0..trail_size) |i| {
                    if (buffered[buffered.len - (i+1)] != 0xFF) break i;
                } else trail_size;
            }
        }
    }

    pub const Flags = packed struct {
        sync: SyncMode,

        // TODO: split this into two separate fields if it is possible for FSYNCs to
        // present without HSYNCs (and if it useful to make a distinction, if the scenario
        // is possible)
        pub const SyncMode = enum(u2) {
            aligned,
            fsync,
            hsync_fsync,
        };
    };
};
