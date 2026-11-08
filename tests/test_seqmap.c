#include "seqmap.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    SeqMap map;
    seqmap_init(&map);

    /* Original TCP payload of 100 bytes becomes 116 bytes. */
    assert(seqmap_add_segment(&map, 1000, 100, 116) == 0);

    /* Sequence number before the insertion is unchanged. */
    assert(seqmap_translate_seq(&map, 999) == 999);

    /* The next sequence position includes the 16-byte tag. */
    assert(seqmap_translate_seq(&map, 1100) == 1116);

    /* Later sequence numbers carry the accumulated offset. */
    assert(seqmap_translate_seq(&map, 1200) == 1216);

    /* ACK beyond the expanded segment maps back correctly. */
    assert(seqmap_translate_ack(&map, 1116) == 1100);
    assert(seqmap_translate_ack(&map, 1216) == 1200);

    /* ACK within the tag region maps to original payload end. */
    assert(seqmap_translate_ack(&map, 1110) == 1100);

    /* A second segment adds another expansion. */
    assert(seqmap_add_segment(&map, 1100, 50, 66) == 0);

    assert(seqmap_translate_seq(&map, 1150) == 1182);
    assert(seqmap_translate_seq(&map, 1200) == 1232);

    puts("[PASS] TCP sequence/ACK mapping tests");

    return 0;
}