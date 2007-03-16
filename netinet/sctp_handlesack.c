#include <sys/types.h>
#include <stdio.h>
#include "sctp_sack.h"
#include <netinet/sctp.h>

int verbose = 0;

#define SCTP_IS_TSN_PRESENT(arry, gap) ((arry[(gap >> 3)] >> (gap & 0x07)) & 0x01)
#define SCTP_SET_TSN_PRESENT(arry, gap) (arry[(gap >> 3)] |= (0x01 << ((gap & 0x07))))
#define SCTP_UNSET_TSN_PRESENT(arry, gap) (arry[(gap >> 3)] &= ((~(0x01 << ((gap & 0x07)))) & 0xff))
#define MAX_TSN 0xfffffff

struct sctp_sack {
	uint32_t cum_tsn_ack;	/* cumulative TSN Ack */
	uint32_t a_rwnd;	/* updated a_rwnd of sender */
	uint16_t num_gap_ack_blks;	/* number of Gap Ack blocks */
	uint16_t num_dup_tsns;	/* number of duplicate TSNs */
	/* struct sctp_gap_ack_block's follow */
	/* uint32_t duplicate_tsn's follow */
};

struct sctp_sack_chunk {
	struct sctp_chunkhdr ch;
	struct sctp_sack sack;
};

/*
 * 1  2  3  4  5  6  7  8 0  01 03 07 0f 1f 3f 7f ff 1  02 06 0e 1e 3e 7e fe
 * -- 2  04 0c 1c 3c 7c fc -- -- 3  08 18 38 78 f8 -- -- -- 4  10 30 70 f0 --
 * -- -- -- 5  20 60 e0 -- -- -- -- -- 6  40 c0 -- -- -- -- -- -- 7  80 -- --
 * -- -- -- -- --
 *
 */

uint8_t map_table[8][8] = {
	 /* row 0 */ 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff,
	 /* row 1 */ 0x02, 0x06, 0x0e, 0x1e, 0x3e, 0x7e, 0xfe, 0x00,
	 /* row 2 */ 0x04, 0x0c, 0x1c, 0x3c, 0x7c, 0xfc, 0x00, 0x00,
	 /* row 3 */ 0x08, 0x18, 0x38, 0x78, 0xf8, 0x00, 0x00, 0x00,
	 /* row 4 */ 0x10, 0x30, 0x70, 0xf0, 0x00, 0x00, 0x00, 0x00,
	 /* row 5 */ 0x20, 0x60, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	 /* row 6 */ 0x40, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 /* row 7 */ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void
process_a_sack(uint8_t * mapping_array, uint32_t mapping_array_base_tsn, struct sctp_sack_chunk *ch)
{
	int i, nblks, indx, bit;
	struct sctp_gap_ack_block *blk;
	uint32_t pos, cumack;
	int32_t bit_pos_start;
	int32_t bit_run_length, bit_run;
	uint16_t start, end;

	blk = (struct sctp_gap_ack_block *)((caddr_t)ch + sizeof(struct sctp_sack_chunk));
	nblks = (ch->sack.num_gap_ack_blks);
	cumack = (ch->sack.cum_tsn_ack);

	for (i = 0; i < nblks; i++) {
		/* get relevant info */
		start = (blk->start);
		end = (blk->end);
		blk++;
do_some_more:
		pos = cumack + start;
		if (pos > mapping_array_base_tsn) {
			bit_pos_start = pos - mapping_array_base_tsn;
		} else {
			bit_pos_start = (MAX_TSN - mapping_array_base_tsn) + pos + 1;
		}
		bit_run_length = (end - start) + 1;
		indx = bit_pos_start / 8;
		bit = bit_pos_start % 8;
again:
		if ((bit_run_length + bit) > 8) {
			/* spans byte boundary */
			bit_run = 8 - bit;
			/* now get one part */
			mapping_array[indx] |= map_table[bit][(bit_run - 1)];
			bit_run_length -= bit_run;
			bit_pos_start += bit_run;
			indx = bit_pos_start / 8;
			bit = bit_pos_start % 8;
			goto again;
		} else {
			bit_run = bit_run_length;
		}
		mapping_array[indx] |= map_table[bit][(bit_run - 1)];
		if (bit_run < bit_run_length) {
			start += bit_run;
			goto do_some_more;
		}
	}
}

void
process_a_sack2(uint8_t * mapping_array, uint32_t mapping_array_base_tsn, struct sctp_sack_chunk *ch)
{
	int i, nblks, gap, j;
	struct sctp_gap_ack_block *blk;
	uint32_t pos, cumack;
	int32_t bit_pos_start;
	int32_t bit_run_length;
	uint16_t start, end;

	blk = (struct sctp_gap_ack_block *)((caddr_t)ch + sizeof(struct sctp_sack_chunk));
	nblks = (ch->sack.num_gap_ack_blks);
	cumack = ch->sack.cum_tsn_ack;
	for (i = 0; i < nblks; i++) {
		start = (blk->start);
		end = (blk->end);
		pos = cumack + start;
		blk++;
		if (pos > mapping_array_base_tsn) {
			bit_pos_start = pos - mapping_array_base_tsn;
		} else {
			bit_pos_start = (MAX_TSN - mapping_array_base_tsn) + pos + 1;
		}
		bit_run_length = (end - start) + 1;
		for (j = 0; j < bit_run_length; j++) {
			SCTP_SET_TSN_PRESENT(mapping_array, (bit_pos_start + j));
		}
	}
}

struct sack_block {
	struct sctp_chunkhdr ch;
	struct sctp_sack sack;
	struct sctp_gap_ack_block blocks[20];
}          sack;

int
main(int argc, char **argv)
{
	int blks, cumack, gap, numgaps;
	int start, end;
	uint32_t mapping_array_base_tsn;
	uint8_t mapping_array1[512];
	uint8_t mapping_array2[512];
	struct sctp_sack_chunk *ch;

	sack.ch.chunk_type = SCTP_SELECTIVE_ACK;
	sack.ch.chunk_flags = 0;
	sack.ch.chunk_length = 0;
	sack.sack.a_rwnd = 200000;
	sack.sack.num_gap_ack_blks = 0;
	sack.sack.num_dup_tsns = 0;
	mapping_array_base_tsn = 1;
	for (cumack = 0; cumack < 2000; cumack++) {
		sack.sack.cum_tsn_ack = cumack;
		for (gap = 1; gap < 10; gap++) {
			for (numgaps = 1; numgaps < 20; numgaps++) {
				/* how many gaps? */
				sack.sack.num_gap_ack_blks = numgaps;
				start = 2;
				end = start + gap;
				for (blks = 0; blks < numgaps; blks++) {
					sack.blocks[blks].start = (start + (blks * start) + blks);
					sack.blocks[blks].end = (end + (blks * start) + blks);
				}
				memset(mapping_array1, 0, sizeof(mapping_array1));
				memset(mapping_array2, 0, sizeof(mapping_array1));
				process_a_sack(mapping_array1,
				    mapping_array_base_tsn,
				    (struct sctp_sack_chunk *)&sack);
				process_a_sack2(mapping_array2,
				    mapping_array_base_tsn,
				    (struct sctp_sack_chunk *)&sack);
				if (memcmp(mapping_array1, mapping_array2, sizeof(mapping_array1))) {
					printf("Did not match\n");
				}
			}
		}
	}

}
