const std = @import("std");
const opencsd = @import("opencsd.zig");

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
