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

    const SyncFrame = enum(u8) {
        hsync = hsync_bytes.len,
        fsync = fsync_bytes.len,

        pub inline fn byteLength(sf: SyncFrame) usize {
            return @intFromEnum(sf);
        }
    };

    pub fn synchronize(df: *Deformatter) !SyncFrame {
        const r = df.reader;
        assert(r.buffer.len >= min_buffer_capacity);
        const min_size = switch (df.flags.sync) {
            .aligned => unreachable,
            .hsync_fsync => hsync_bytes.len,
            .fsync => fsync_bytes.len,
        };
        while (true) {
            if (r.bufferedLen() < min_size) try r.fillMore();
            const buffered = r.buffered();
            if (std.mem.find(u8, buffered, hsync_bytes)) |pos| {
                if (pos > 2 and buffered[pos-2] == 0xFF and buffered[pos-1] == 0xFF) {
                    // akshually, its an fsync!
                    const n = pos - 2;
                    r.seek += n;
                    df.logical_position += n;
                    return .fsync;
                } else {
                    // hsync
                    r.seek += pos;
                    df.logical_position += pos;
                    // TODO: I think there is a chance that the presence of an hsync byte
                    // sequence when they are not enabled is indicative of invalid data?
                    if (df.flags.sync != .hsync_fsync) continue;
                    return .hsync;
                }
            } else {
                // Keep a potential FSYNC/HSYNC byte prefix buffered before refilling the
                // buffer if we didn't find any sync points. The prefix size is at most
                // len(FSYNC)-1, and of course bounded by the current buffer size.
                const trail_size = @min(buffered.len, fsync_bytes.len-1);
                const keep = for (0..trail_size) |i| {
                    if (buffered[buffered.len - (i+1)] != 0xFF) break i;
                } else trail_size;

                // Without this, we risk keeping an FSYNC prefix candidate buffered in a
                // way that would prevent us from ever moving forward if HSYNC frames are
                // enabled (0xFF_FF and 0xFF_FF_FF are candidates, but also long enough to
                // inhibit a buffer refill due to them being >= 2 bytes long).
                //
                // Note that it is incorrect to mitigate this condition by capping the
                // `trail_size` to `buffered.len-1` instead. Although it would guarantee
                // that we move forward, it risks ignoring an FSYNC. Consider the
                // following scenario:
                //
                // <-[...]---------------- underlying stream ----[...]->
                //           <--- buffered --->
                //           |                |
                //   ... ... [ 0xFF 0xFF 0xFF ] 0x7F |... ...
                //           |                       |
                //           <-------- FSYNC -------->
                //
                // (Note that this also holds if only `[0xFF 0xFF]` is buffered)
                //
                // In this situation, the correct action is to *not* move forward, but to
                // try to fill the buffer up some more. If that fails and/or nothing was
                // added to the buffer, we *correctly* return with an error of some sort
                // to indicate that we failed to synchronize (this function is only called
                // when we are not synchronized). If it succeeds, we were at worst
                // microscopically pessimistic about the reader's available refill
                // capacity.
                if (keep == buffered.len) {
                    @branchHint(.unlikely);
                    try r.fillMore();
                    if (r.bufferedLen() == buffered.len) {
                        return error.EndOfStream;
                    }
                } else {
                    const n = buffered.len - keep;
                    r.seek += n;
                    df.logical_position += n;
                }
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
