#include "murmur3.h"
#include <string.h>
#include <stdlib.h>

uint32_t murmur3_x86_32(const char *buf, int len, uint32_t seed)
{
	uint32_t hash = seed;
	const int32_t qlen = len >> 2;
	uint32_t k;
	const uint8_t *cbuf = (const uint8_t *)buf;
	const uint32_t vector1 = 0xcc9e2d51;
	const uint32_t vector2 = 0x1b873593;
	int i;

	const uint32_t *mbuf = (const uint32_t *)(cbuf + (qlen * 4));

	for (i = -qlen; i; i++) {
		k = mbuf[i];
		k *= vector1;
		k = __ROL_X86__(k, 15);
		k *= vector2;
		hash ^= k;
		hash = __ROL_X86__(hash, 13);
		hash = (hash * 5) + 0xe6546b64;
	}

	const uint8_t *rem = (const uint8_t *)(cbuf + (qlen * 4));

	k = 0;

	switch (len & 3) {
	case 3: k ^= (uint8_t)rem[2] << 16;
	case 2: k ^= (uint8_t)rem[1] <<  8;
	case 1: k ^= (uint8_t)rem[0] <<  0;
		k *= vector1; k = __ROL_X86__(k, 15); k *= vector2; hash ^= k;
	}

	hash ^= len;

	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;
}

uint32_t *murmur3_x86_128(const char *buf, int len, uint32_t seed)
{
	uint32_t hash1 = seed;
	uint32_t hash2 = seed;
	uint32_t hash3 = seed;
	uint32_t hash4 = seed;
	const uint32_t qlen = len >> 4;
	const uint8_t *cbuf = (const uint8_t *)buf;
	const uint32_t vector1 = 0x239b961b;
	const uint32_t vector2 = 0xab0e9789;
	const uint32_t vector3 = 0x38b34ae5;
	const uint32_t vector4 = 0xa1e38b93;
	uint32_t k1, k2, k3, k4;
	uint32_t *chashptr;
	int i;

	// append padding
	const uint32_t *mbuf = (const uint32_t *)(cbuf + (qlen * 16));

	for (i = -qlen; i; i++) {
		k1 = mbuf[i * 4 + 0];
		k2 = mbuf[i * 4 + 1];
		k3 = mbuf[i * 4 + 2];
		k4 = mbuf[i * 4 + 3];

		// process first block
		k1 *= vector1;
		k1 = __ROL_X86__(k1, 15);
		k1 *= vector2;
		hash1 ^= k1;
		hash1 = __ROL_X86__(hash1, 19);
		hash1 += hash2;
		hash1 = (hash1 * 5) + 0x561ccd1b;

		// process second block
		k2 *= vector2;
		k2 = __ROL_X86__(k2, 16);
		k2 *= vector3;
		hash2 ^= k2;
		hash2 = __ROL_X86__(hash2, 17);
		hash2 += hash3;
		hash2 = (hash2 * 5) + 0x0bcaa747;

		// process third block
		k3 *= vector3;
		k3 = __ROL_X86__(k3, 17);
		k3 *= vector4;
		hash3 ^= k3;
		hash3 = __ROL_X86__(hash3, 15);
		hash3 += hash4;
		hash3 = (hash3 * 5) + 0x96cd1c35;

		// process fourth block
		k4 *= vector4;
		k4 = __ROL_X86__(k4, 18);
		k4 *= vector1;
		hash4 ^= k4;
		hash4 = __ROL_X86__(hash4, 13);
		hash4 += hash1;
		hash4 = (hash4 * 5) + 0x32ac3b17;
	}

	// append padding
	const uint8_t *rem = (const uint8_t *)(cbuf + (qlen * 16));
	k1 = 0; k2 = 0; k3 = 0; k4 = 0;

	switch (len & 15) {
	// processing last block
	case 15: k4 ^= rem[14] << 16;
	case 14: k4 ^= rem[13] <<  8;
	case 13: k4 ^= rem[12] <<  0;
		 k4 *= vector4; k4 = __ROL_X86__(k4, 18); k4 *= vector1; hash1 ^= k4;

	// processing third block
	case 12: k3 ^= rem[11] << 24;
	case 11: k3 ^= rem[10] << 16;
	case 10: k3 ^= rem[ 9] <<  8;
	case  9: k3 ^= rem[ 8] <<  0;
		 k3 *= vector3; k3 = __ROL_X86__(k3, 17); k3 *= vector4; hash3 ^= k3;

	// processing second block
	case  8: k2 ^= rem[ 7] << 24;
	case  7: k2 ^= rem[ 6] << 16;
	case  6: k2 ^= rem[ 5] <<  8;
	case  5: k2 ^= rem[ 4] <<  0;
		 k2 *= vector2; k2 = __ROL_X86__(k2, 16); k2 *= vector3; hash2 ^= k2;

	// processing first block
	case  4: k1 ^= rem[ 3] << 24;
	case  3: k1 ^= rem[ 2] << 16;
	case  2: k1 ^= rem[ 1] <<  8;
	case  1: k1 ^= rem[ 0] <<  0;
		 k1 *= vector1; k1 = __ROL_X86__(k1, 15); k1 *= vector2; hash1 ^= k1;
	}

	hash1 ^= len; hash2 ^= len; hash3 ^= len; hash4 ^= len;

	// add each hash block in odd-formed pair
	hash1 += hash2; hash1 += hash3; hash1 += hash4;
	hash2 += hash1; hash3 += hash1; hash4 += hash1;

	// finalization (first hash block)
	hash1 ^= hash1 >> 16;
	hash1 *= 0x85ebca6b;
	hash1 ^= hash1 >> 13;
	hash1 *= 0xc2b2ae35;
	hash1 ^= hash1 >> 16;

	// finalization (second hash block)
	hash2 ^= hash2 >> 16;
	hash2 *= 0x85ebca6b;
	hash2 ^= hash2 >> 13;
	hash2 *= 0xc2b2ae35;
	hash2 ^= hash2 >> 16;

	// finalization (third hash block)
	hash3 ^= hash3 >> 16;
	hash3 *= 0x85ebca6b;
	hash3 ^= hash3 >> 13;
	hash3 *= 0xc2b2ae35;
	hash3 ^= hash3 >> 16;

	// finalization (fourth hash block)
	hash4 ^= hash4 >> 16;
	hash4 *= 0x85ebca6b;
	hash4 ^= hash4 >> 13;
	hash4 *= 0xc2b2ae35;
	hash4 ^= hash4 >> 16;

	// add each hash block in odd-formed pair
	hash1 += hash2; hash1 += hash3; hash1 += hash4;
	hash2 += hash1; hash3 += hash1; hash4 += hash1;

	chashptr = malloc(4 * sizeof(uint32_t));

	((uint32_t *)(chashptr))[0] = hash1;
	((uint32_t *)(chashptr))[1] = hash2;
	((uint32_t *)(chashptr))[2] = hash3;
	((uint32_t *)(chashptr))[3] = hash4;

	return chashptr;
}

uint64_t *murmur3_x64_128(const char *buf, int64_t len, uint64_t seed)
{
	uint64_t hash1 = seed;
	uint64_t hash2 = seed;
	const uint8_t *cbuf = (const uint8_t *)buf;
	const int64_t qlen = len >> 4;
	uint64_t vector1 = LL_POSTFIX(0x87c37b91114253d5);
	uint64_t vector2 = LL_POSTFIX(0x4cf5ad432745937f);
	uint64_t k1 = 0, k2 = 0;
	uint64_t *chashptr_quad;
	int64_t i;

	// append padding
	const uint64_t *mbuf = (const uint64_t *)(cbuf);

	for (i = 0; i < qlen; i++) {
		k1 = mbuf[i * 2 + 0];
		k2 = mbuf[i * 2 + 1];

		// process first quad block
		k1 *= vector1;
		k1 = __ROL_X64__(k1, 31);
		k1 *= vector2;
		hash1 ^= k1;
		hash1 = __ROL_X64__(hash1, 27);
		hash1 += hash2;
		hash1 = (hash1 * 5) + 0x52dce729;

		// process second quad block
		k2 *= vector2;
		k2 = __ROL_X64__(k2, 33);
		k2 *= vector1;
		hash2 ^= k2;
		hash2 = __ROL_X64__(hash2, 31);
		hash2 += hash1;
		hash2 = (hash2 * 5) + 0x38495ab5;
	}

	const uint8_t *rem = (const uint8_t *)(cbuf + (qlen * 16));

	k1 = 0; k2 = 0;

	switch (len & 15) {
	case 15: k2 ^= (uint64_t)(rem[14]) << 48;
	case 14: k2 ^= (uint64_t)(rem[13]) << 40;
	case 13: k2 ^= (uint64_t)(rem[12]) << 32;
	case 12: k2 ^= (uint64_t)(rem[11]) << 24;
	case 11: k2 ^= (uint64_t)(rem[10]) << 16;
	case 10: k2 ^= (uint64_t)(rem[ 9]) <<  8;
	case  9: k2 ^= (uint64_t)(rem[ 8]) <<  0;
		 k2 *= vector2; k2 = __ROL_X64__(k2, 33); k2 *= vector1; hash2 ^= k2;

	case  8: k1 ^= (uint64_t)(rem[ 7]) << 56;
	case  7: k1 ^= (uint64_t)(rem[ 6]) << 48;
	case  6: k1 ^= (uint64_t)(rem[ 5]) << 40;
	case  5: k1 ^= (uint64_t)(rem[ 4]) << 32;
	case  4: k1 ^= (uint64_t)(rem[ 3]) << 24;
	case  3: k1 ^= (uint64_t)(rem[ 2]) << 16;
	case  2: k1 ^= (uint64_t)(rem[ 1]) <<  8;
	case  1: k1 ^= (uint64_t)(rem[ 0]) <<  0;
		 k1 *= vector1; k1 = __ROL_X64__(k1, 31); k1 *= vector2; hash1 ^= k1;
	}

	hash1 ^= len; hash2 ^= len;

	// add quad-formed hash block to each other
	hash1 += hash2; hash2 += hash1;

	// finalization (first quad hash block)
	hash1 ^= hash1 >> 33;
	hash1 *= LL_POSTFIX(0xff51afd7ed558ccd);
	hash1 ^= hash1 >> 33;
	hash1 *= LL_POSTFIX(0xc4ceb9fe1a85ec53);
	hash1 ^= hash1 >> 33;

	// finalization (second quad hash block)
	hash2 ^= hash2 >> 33;
	hash2 *= LL_POSTFIX(0xff51afd7ed558ccd);
	hash2 ^= hash2 >> 33;
	hash2 *= LL_POSTFIX(0xc4ceb9fe1a85ec53);
	hash2 ^= hash2 >> 33;

	// add quad-formed hash block to each other
	hash1 += hash2; hash2 += hash1;

	chashptr_quad = malloc(2 * sizeof(uint64_t));

	((uint64_t *)(chashptr_quad))[0] = (uint64_t)(hash1);
	((uint64_t *)(chashptr_quad))[1] = (uint64_t)(hash2);

	return chashptr_quad;
}

void murmur3_destruct_rethash(void *q)
{
	if (q != NULL)
		free(q);
}
