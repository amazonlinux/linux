// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Kernel Cryptographic Module
 * HMAC generation tool for integrity verification
 */

#include <elf.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HMAC_KEY "The quick brown fox jumps over the lazy dog"
#define DIGEST_SIZE 32 /* SHA-256 */

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s <module.ko>\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	const char *module_path;
	int fd;
	struct stat st;
	void *map;
	unsigned char digest[DIGEST_SIZE];
	unsigned int digest_len = DIGEST_SIZE;
	int i;

	if (argc != 2)
		usage(argv[0]);

	module_path = argv[1];
	fd = open(module_path, O_RDWR);
	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		close(fd);
		return EXIT_FAILURE;
	}

	map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return EXIT_FAILURE;
	}

	/* 
	 * This is a simplified version. The actual implementation would:
	 * 1. Parse the ELF file to find the .text and .rodata sections
	 * 2. Calculate the HMAC over these sections
	 * 3. Find the location of the fips140_integ_hmac_digest variable
	 * 4. Write the HMAC digest to that location
	 */

	/* For now, just print a placeholder message */
	printf("FIPS 140 HMAC generation tool\n");
	printf("This tool would calculate the HMAC of the .text and .rodata sections\n");
	printf("and write it to the fips140_integ_hmac_digest variable in the module.\n");

	/* Generate a dummy HMAC for demonstration */
	if (!HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), 
		 (unsigned char *)map, st.st_size, digest, &digest_len)) {
		fprintf(stderr, "HMAC calculation failed\n");
		munmap(map, st.st_size);
		close(fd);
		return EXIT_FAILURE;
	}

	printf("Generated HMAC digest: ");
	for (i = 0; i < DIGEST_SIZE; i++)
		printf("%02x", digest[i]);
	printf("\n");

	munmap(map, st.st_size);
	close(fd);
	return EXIT_SUCCESS;
}
