#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>

void usage_error() {
	dprintf(STDERR_FILENO, "usage: ./woody_woodpacker filename\n");
	exit(1);
}

typedef struct ELFHeader {
	uint8_t e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} ELFHeader;

void print_elf_header(ELFHeader *h) {
	printf("e_ident:     ");
	for (int i = 0; i < 16; ++i) {
		printf("%02x", h->e_ident[i]);
		if (i != 15) printf(" ");
		if (i == 7) printf(" ");
	}
	printf("\n");
	printf("e_type:      0x%x\n", h->e_type);
	printf("e_machine:   0x%x\n", h->e_machine);
	printf("e_version:   0x%x\n", h->e_version);
	printf("e_entry:     0x%lx\n", h->e_entry);
	printf("e_phoff:     0x%lx\n", h->e_phoff);
	printf("e_shoff:     0x%lx\n", h->e_shoff);
	printf("e_flags:     0x%x\n", h->e_flags);
	printf("e_ehsize:    0x%x\n", h->e_ehsize);
	printf("e_phentsize: 0x%x\n", h->e_phentsize);
	printf("e_phnum:     0x%x\n", h->e_phnum);
	printf("e_shentsize: 0x%x\n", h->e_shentsize);
	printf("e_shnum:     0x%x\n", h->e_shnum);
	printf("e_shstrndx:  0x%x\n", h->e_shstrndx);
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		usage_error();
	}
	printf("sizeof(ELFHeader): %lu\n", sizeof(ELFHeader));
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	char buf[1024];
	int rc = read(fd, buf, sizeof(ELFHeader));
	printf("rc = %d\n", rc);
	ELFHeader *h = (ELFHeader *)buf;
	print_elf_header(h);
	close(fd);
	return 0;
}
