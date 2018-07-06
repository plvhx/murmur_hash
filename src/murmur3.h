#ifndef _MURMUR3_H_
#define _MURMUR3_H_

#include <stdint.h>

#if __WORDSIZE == 64
#define NBITS	64
#define UINT_PLATFORM_DEP	uint64_t
#else
#define NBITS	32
#define UINT_PLATFORM_DEP	uint32_t
#endif

#define __ROL_X86__(x, b)	(((x) << (b)) | ((x) >> (32 - (b))))
#define __ROL_X64__(x, b)	(((x) << (b)) | ((x) >> (64 - (b))))

#define __ROL__(x, b)	(((x) << (b)) | ((x) >> (NBITS - (b))))
#define LL_POSTFIX(x)	(x##LLU)

uint32_t murmur3_x86_32(const char *buf, int len, uint32_t seed);
uint32_t *murmur3_x86_128(const char *buf, int len, uint32_t seed);
uint64_t *murmur3_x64_128(const char *buf, int64_t len, uint64_t seed);
void murmur3_destruct_rethash(void *q);

#endif	/* _MURMUR3_H_ */
