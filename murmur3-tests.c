#include <stdio.h>
#include <string.h>
#include "./src/murmur3.h"

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	char *buf = "This is a shitty text.";
	uint32_t hash_x86_32;
	uint32_t *hash_x86_128;
	uint64_t *hash_x64_128;

	hash_x86_32 = murmur3_x86_32(buf, strlen(buf), 42);
	hash_x86_128 = murmur3_x86_128(buf, strlen(buf), 42);
	hash_x64_128 = murmur3_x64_128(buf, strlen(buf), 42);

	MSG_OUT("hash_x86_32(\"%s\"): %08x\n", buf, hash_x86_32);

	MSG_OUT("hash_x86_128(\"%s\"): %08x %08x %08x %08x\n",
		buf,
		hash_x86_128[0],
		hash_x86_128[1],
		hash_x86_128[2],
		hash_x86_128[3]
	);

	MSG_OUT("hash_x64_128(\"%s\"): %16lx %16lx\n",
		buf,
		hash_x64_128[0],
		hash_x64_128[1]
	);

	murmur3_destruct_rethash(hash_x86_128);
	murmur3_destruct_rethash(hash_x64_128);

	return 0;
}
