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


int
sctp_generate_sack(uint8_t * mapping_array,
    uint32_t highest_tsn_inside_map,
    uint32_t mapping_array_base_tsn,
    uint32_t cumulative_tsn,
    struct sctp_sack_chunk *sack)
{
	struct sctp_gap_ack_block *gap_descriptor;
	int num_gap_discriptor = 0;
	int seeing_ones, i;
	int start, maxi, m_size;

	start = maxi = 0;
	gap_descriptor = (struct sctp_gap_ack_block *)((caddr_t)sack + sizeof(struct sctp_sack_chunk));
	seeing_ones = 0;

	if (highest_tsn_inside_map >= mapping_array_base_tsn) {
		maxi = (highest_tsn_inside_map - mapping_array_base_tsn);
	} else {
		maxi = (highest_tsn_inside_map + (MAX_TSN - mapping_array_base_tsn) + 1);
	}
	if (cumulative_tsn >= mapping_array_base_tsn) {
		start = (cumulative_tsn - mapping_array_base_tsn);
	} else {
		/* Set it so we start at 0 */
		start = -1;
	}
	start++;

	for (i = start; i <= maxi; i++) {
		if (seeing_ones) {
			/*
			 * while seeing Ones I must transition back to 0
			 * before finding the next gap
			 */
			if (SCTP_IS_TSN_PRESENT(mapping_array, i) == 0) {
				num_gap_discriptor++;
				seeing_ones = 0;
			}
		} else {
			if (SCTP_IS_TSN_PRESENT(mapping_array, i)) {
				seeing_ones = 1;
			}
		}
	}

	num_gap_discriptor = 0;
	seeing_ones = 0;

	for (i = start; i <= maxi; i++) {
		if (seeing_ones) {
			/*
			 * while seeing Ones I must transition back to 0
			 * before finding the next gap
			 */
			if (SCTP_IS_TSN_PRESENT(mapping_array, i) == 0) {
				gap_descriptor->end = htons(((uint16_t) (i - start)));
				num_gap_discriptor++;
				gap_descriptor++;
				seeing_ones = 0;
			}
		} else {
			if (SCTP_IS_TSN_PRESENT(mapping_array, i)) {
				gap_descriptor->start = htons(((uint16_t) (i + 1 - start)));
				/* advance struct to next pointer */
				seeing_ones = 1;
			}
		}
	}
	if ((SCTP_IS_TSN_PRESENT(mapping_array, maxi)) &&
	    (seeing_ones)) {
		/*
		 * special case where the array is all 1's to the end of the
		 * array
		 */
		gap_descriptor->end = htons(((uint16_t) ((i - start))));
		gap_descriptor++;
		num_gap_discriptor++;
	}
	return (num_gap_discriptor);
}


int
sctp_generate_sack_new(uint8_t * mapping_array,
    uint32_t highest_tsn_inside_map,
    uint32_t mapping_array_base_tsn,
    uint32_t cumulative_tsn,
    struct sctp_sack_chunk *sack)
{
	struct sctp_gap_ack_block *gap_descriptor;
	int num_gap_discriptor = 0;
	struct sack_track *selector;
	int siz, offset, i, j, jstart;
	int mergeable = 0, need_incr = 0;

	gap_descriptor = (struct sctp_gap_ack_block *)((caddr_t)sack + sizeof(struct sctp_sack_chunk));
	/* calculate the number of bufs to work on */
	siz = (((highest_tsn_inside_map - mapping_array_base_tsn) + 1) + 7) / 8;
	if (verbose)
		printf("Highest:%d mapping_array_base:%d cum_ack:%d siz:%d\n",
		    highest_tsn_inside_map, mapping_array_base_tsn,
		    cumulative_tsn, siz);

	if (cumulative_tsn < mapping_array_base_tsn) {
		offset = 1;
		/*
		 * cum-ack behind the mapping array, so we start and use all
		 * entries.
		 */
		jstart = 0;
	} else {
		offset = mapping_array_base_tsn - cumulative_tsn;
		/*
		 * we skip the first one when the cum-ack is at or above the
		 * mapping array base.
		 */
		jstart = 1;
	}
	for (i = 0; i < siz; i++) {
		selector = &sack_array[mapping_array[i]];
		if (mergeable && selector->right_edge) {
			/*
			 * Backup, left and right edges were ok to merge.
			 */
			num_gap_discriptor--;
			gap_descriptor--;
		}
		if (selector->num_entries == 0)
			mergeable = 0;
		else {
			for (j = jstart; j < selector->num_entries; j++) {
				if (mergeable && selector->right_edge) {
					/*
					 * do a merge by NOT setting the
					 * left side
					 */
					mergeable = 0;
				} else {
					/* no merge, set the left side */
					mergeable = 0;
					gap_descriptor->start = htons((selector->gaps[j].start + offset));
				}
				gap_descriptor->end = htons((selector->gaps[j].end + offset));
				num_gap_discriptor++;
				gap_descriptor++;

			}
			if (selector->left_edge) {
				mergeable = 1;
			}
		}
		jstart = 0;
		offset += 8;
	}
	return (num_gap_discriptor);
}

void
dump_out_sack(struct sctp_sack_chunk *sack)
{
	int i;
	struct sctp_gap_ack_block *gap;

	if (sack == NULL)
		return;
	printf("Number of gaps:%d\n",
	    sack->sack.num_gap_ack_blks);
	gap = (struct sctp_gap_ack_block *)((caddr_t)sack + sizeof(struct sctp_sack_chunk));
	for (i = 0; i < sack->sack.num_gap_ack_blks; i++) {
		printf("Start:%d End:%d\n",
		    ntohs(gap->start), ntohs(gap->end));
		gap++;
	}
}

extern void *optarg;

int
main(int argc, char **argv)
{
	uint8_t sack1_buf[2048];
	uint8_t sack2_buf[2048];
	struct sctp_sack_chunk *sack1, *sack2;
	int j, i;
	uint32_t num_skip = 0, num_compared = 0, num_diff = 0, max, startat;
	uint8_t mapping_array[32];
	uint32_t counter, *point;
	uint32_t highest_tsn_inside_map, mapping_array_base_tsn, cumulative_tsn;

	startat = 1;
	max = 0xffffffff;

	while ((i = getopt(argc, argv, "s:e:v")) != EOF) {
		switch (i) {
		case 's':
			startat = strtoul(optarg, NULL, 0);
			break;
		case 'e':
			max = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			printf("Use %s [-s num -e num -v]\n", argv[0]);
			return (0);
		};
	}
	sack1 = (struct sctp_sack_chunk *)sack1_buf;
	sack2 = (struct sctp_sack_chunk *)sack2_buf;
	point = (uint32_t *) mapping_array;
	mapping_array_base_tsn = 0x100;
	for (i = startat; i <= max; i++) {
		memset(sack1_buf, 0, sizeof(sack1_buf));
		memset(sack2_buf, 0, sizeof(sack2_buf));

		/* setup the bit map */
		*point = i;
		/* now figure out where cum-ack is */
		if (SCTP_IS_TSN_PRESENT(mapping_array, 0)) {
			/* figure out where cum-ack is then */
			cumulative_tsn = mapping_array_base_tsn;
			for (j = 0; j < 32; j++) {
				if (SCTP_IS_TSN_PRESENT(mapping_array, j)) {
					cumulative_tsn = mapping_array_base_tsn + j;
				} else {
					break;
				}
			}
		} else {
			cumulative_tsn = mapping_array_base_tsn - 1;
		}
		/* Now where is the highest TSN present */
		for (j = 0; j < 32; j++) {
			/* we only have up to 32 bits used */
			if (SCTP_IS_TSN_PRESENT(mapping_array, j)) {
				/* this one is here */
				highest_tsn_inside_map = mapping_array_base_tsn + j;
			}
		}
		if (highest_tsn_inside_map == cumulative_tsn) {
			/* no gap ack blocks, skip this one */

			num_skip++;
			continue;
		}
		num_compared++;
		/* generate gap ack blocks */
		sack1->sack.num_gap_ack_blks = sctp_generate_sack(mapping_array,
		    highest_tsn_inside_map,
		    mapping_array_base_tsn,
		    cumulative_tsn,
		    sack1);

		sack2->sack.num_gap_ack_blks = sctp_generate_sack_new(mapping_array,
		    highest_tsn_inside_map,
		    mapping_array_base_tsn,
		    cumulative_tsn,
		    sack2);
		if (verbose) {
			printf("Value %x\n", i);
			printf("Sack1 (old method)\n");
			dump_out_sack(sack1);
			printf("Sack2 (new method)\n");
			dump_out_sack(sack2);
		}
		if (sack1->sack.num_gap_ack_blks != sack2->sack.num_gap_ack_blks) {
			printf("had a difference with count:%x sack1->num:%d sack2->num:%d\n",
			    i,
			    sack1->sack.num_gap_ack_blks, sack2->sack.num_gap_ack_blks);
			num_diff++;
		} else {
			int cmp_size = ((sack1->sack.num_gap_ack_blks * sizeof(struct sctp_gap_ack_block)) +
			    sizeof(struct sctp_sack_chunk));

			if (memcmp(sack1, sack2, cmp_size)) {
				printf("Value %x came up with different blocks\n", i);
				num_diff++;
			}
		}
		if (i && ((i % 10000000) == 0)) {
			printf("At %d compared:%d total skipped %d total diffs %d\n",
			    i,
			    num_compared,
			    num_skip,
			    num_diff);
		}
	}
	printf("Total compared:%d total skipped %d total diffs %d\n",
	    num_compared,
	    num_skip,
	    num_diff);
}
