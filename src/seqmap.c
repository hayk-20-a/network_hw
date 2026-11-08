#include "seqmap.h"

#include <string.h>

/*
 * TCP sequence numbers wrap around.
 * This comparison works when distances are less than 2^31.
 */
static int seq_after_or_equal(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) >= 0;
}

void seqmap_init(SeqMap *map)
{
    if (map == NULL) {
        return;
    }

    memset(map, 0, sizeof(*map));
}

int seqmap_add_segment(
    SeqMap *map,
    uint32_t original_seq,
    uint32_t original_len,
    uint32_t wire_len
)
{
    if (map == NULL || map->count >= SEQMAP_MAX_ENTRIES) {
        return -1;
    }

    if (wire_len < original_len) {
        return -1;
    }

    if (original_len == 0 && wire_len == 0) {
        return 0;
    }

    SeqMapEntry *entry = &map->entries[map->count];

    entry->original_seq = original_seq;
    entry->original_len = original_len;
    entry->wire_len = wire_len;
    entry->added_len = wire_len - original_len;

    map->count++;

    return 0;
}

uint32_t seqmap_translate_seq(
    const SeqMap *map,
    uint32_t original_seq
)
{
    if (map == NULL) {
        return original_seq;
    }

    uint32_t offset = 0;

    for (size_t i = 0; i < map->count; i++) {
        const SeqMapEntry *entry = &map->entries[i];

        uint32_t original_end =
            entry->original_seq + entry->original_len;

        if (seq_after_or_equal(original_seq, original_end)) {
            offset += entry->added_len;
        } else {
            break;
        }
    }

    return original_seq + offset;
}

uint32_t seqmap_translate_ack(
    const SeqMap *map,
    uint32_t wire_ack
)
{
    if (map == NULL) {
        return wire_ack;
    }

    uint32_t offset = 0;

    for (size_t i = 0; i < map->count; i++) {
        const SeqMapEntry *entry = &map->entries[i];

        uint32_t wire_start =
            entry->original_seq + offset;

        uint32_t wire_end =
            wire_start + entry->wire_len;

        uint32_t original_end =
            entry->original_seq + entry->original_len;

        /*
         * ACK has passed the expanded segment.
         * Remove the expansion from the sequence space.
         */
        if (seq_after_or_equal(wire_ack, wire_end)) {
            offset += entry->added_len;
            continue;
        }

        /*
         * ACK is inside the inserted authentication-tag region.
         * Map it to the end of the original payload.
         */
        uint32_t original_payload_end_in_wire =
            wire_start + entry->original_len;

        if (seq_after_or_equal(
                wire_ack,
                original_payload_end_in_wire)) {
            return original_end;
        }

        /*
         * ACK is before this segment's tag insertion.
         */
        break;
    }

    return wire_ack - offset;
}