#ifndef SEQMAP_H
#define SEQMAP_H

#include <stddef.h>
#include <stdint.h>

#define SEQMAP_MAX_ENTRIES 256

typedef struct {
    uint32_t original_seq;
    uint32_t original_len;
    uint32_t wire_len;
    uint32_t added_len;
} SeqMapEntry;

typedef struct {
    SeqMapEntry entries[SEQMAP_MAX_ENTRIES];
    size_t count;
} SeqMap;

void seqmap_init(SeqMap *map);

int seqmap_add_segment(
    SeqMap *map,
    uint32_t original_seq,
    uint32_t original_len,
    uint32_t wire_len
);

uint32_t seqmap_translate_seq(
    const SeqMap *map,
    uint32_t original_seq
);

uint32_t seqmap_translate_ack(
    const SeqMap *map,
    uint32_t wire_ack
);

#endif