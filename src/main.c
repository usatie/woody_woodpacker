#include "ft_printf.h"
#include "libft.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>  // perror, strerror, STDERR_FILENO
#include <stdlib.h> // exit
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEBUG 1
#if DEBUG
#include "debug.h"
#endif

// These variables are declared as global to make it easier for checking
// boundary
static struct stat st;
static void *map;

// Boundary check macros
#define CHECK_OFFSET_SIZE(offset, size, msg)                                   \
  if ((__off_t)(offset + size) > st.st_size) {                                 \
    ft_dprintf(STDERR_FILENO, "%s\n", msg);                                    \
    exit(1);                                                                   \
  }

#define CHECK_SIZE(size, msg)                                                  \
  if ((__off_t)(size) > st.st_size) {                                          \
    ft_dprintf(STDERR_FILENO, "%s\n", msg);                                    \
    exit(1);                                                                   \
  }

#define CHECK_BOUNDARY(ptr, index, entsize)                                    \
  if ((__off_t)(((void *)ptr - (void *)map) + (index + 1) * entsize) >         \
      st.st_size) {                                                            \
    ft_dprintf(STDERR_FILENO, "CHECK_BOUNDARY failed: %s %s %s\n", #ptr,       \
               #index, #entsize);                                              \
    exit(1);                                                                   \
  }

#define CHECK_CSTRING_BOUNDARY(str)                                            \
  {                                                                            \
    const char *tmp = str;                                                     \
    while (*tmp && (__off_t)((void *)tmp - (void *)map) < st.st_size) {        \
      ++tmp;                                                                   \
    }                                                                          \
    if ((__off_t)(void *)((void *)tmp - (void *)map) >= st.st_size) {          \
      ft_dprintf(STDERR_FILENO, "CHECK_CSTRING_BOUNDARY failed: %s\n", #str);  \
      exit(1);                                                                 \
    }                                                                          \
  }

void usage_error() {
  ft_dprintf(STDERR_FILENO, "usage: ./woody_woodpacker filename\n");
  exit(1);
}

bool is_elf(const unsigned char *e_ident) {
  if (e_ident[EI_MAG0] != 0x7f)
    return false;
  if (e_ident[EI_MAG1] != 'E')
    return false;
  if (e_ident[EI_MAG2] != 'L')
    return false;
  if (e_ident[EI_MAG3] != 'F')
    return false;
  return true;
}

char get_symbol_type_64(const Elf64_Sym *sym, const Elf64_Shdr *shdrs,
                        int num_sections) {
  unsigned char bind = ELF64_ST_BIND(sym->st_info);
  unsigned char type = ELF64_ST_TYPE(sym->st_info);
  // Weak symbol
  if (bind == STB_WEAK) {
    if (type == STT_OBJECT) {
      return (sym->st_shndx != SHN_UNDEF) ? 'V' : 'v';
    }
    return (sym->st_shndx != SHN_UNDEF) ? 'W' : 'w';
  }
  if (sym->st_shndx == SHN_UNDEF)
    return 'U';
  if (sym->st_shndx == SHN_ABS)
    return 'A';
  if (sym->st_shndx == SHN_COMMON)
    return 'C';
  if (sym->st_shndx >= SHN_LORESERVE)
    return '?'; // TODO: Unknown type for now

  // Check if section index is within bounds
  if (sym->st_shndx >= num_sections) {
    ft_dprintf(STDERR_FILENO, "Invalid section index: %u\n", sym->st_shndx);
    return '?'; // Return unknown type if out of bounds
  }

  const Elf64_Shdr *sec = &shdrs[sym->st_shndx];
  // Text section
  if (sec->sh_flags & SHF_EXECINSTR) {
    return (bind == STB_LOCAL) ? 't' : 'T';
  }

  // BSS
  if ((sec->sh_type == SHT_NOBITS) && (sec->sh_flags & SHF_ALLOC) &&
      (sec->sh_flags & SHF_WRITE)) {
    return (bind == STB_LOCAL) ? 'b' : 'B';
  }

  // Data sections (flags: Writable and Allocated, but not Executable)
  //               (type: not NOBITS)
  if ((sec->sh_type != SHT_NOBITS) && (sec->sh_flags & SHF_ALLOC) &&
      (sec->sh_flags & SHF_WRITE)) {
    return (bind == STB_LOCAL) ? 'd' : 'D';
  }
  // Read-only data sections (flags: Allocated, but not Writable nor Executable)
  if ((sec->sh_type == SHT_PROGBITS || sec->sh_type == SHT_NOTE) &&
      (sec->sh_flags & SHF_ALLOC)) {
    return (bind == STB_LOCAL) ? 'r' : 'R';
  }

  return '?'; // Unknown type
}

void do_pack_64bit() {
  CHECK_SIZE(sizeof(Elf64_Ehdr), "File too small for ELF header");
  Elf64_Ehdr *h = (Elf64_Ehdr *)map;
#if DEBUG
  // print ELF header
  print_elf_header(h);
#endif
  // print section headers
  if (sizeof(Elf64_Shdr) != h->e_shentsize) {
    ft_dprintf(STDERR_FILENO, "Invalid section header size\n");
    exit(1);
  }
  // Check if section header table is within bounds
  CHECK_OFFSET_SIZE(h->e_shoff, h->e_shnum * h->e_shentsize,
                    "Section header table extends beyond file");
  Elf64_Shdr *sht = (Elf64_Shdr *)(map + h->e_shoff);
  CHECK_BOUNDARY(sht, h->e_shstrndx, h->e_shentsize);
  Elf64_Shdr *shstrtab_header = &sht[h->e_shstrndx];
  // Check if section string table is within bounds
  CHECK_OFFSET_SIZE(shstrtab_header->sh_offset, shstrtab_header->sh_size,
                    "Section string table extends beyond file");
  char *shstrtab = (char *)(map + shstrtab_header->sh_offset);
  Elf64_Shdr *symtab_header = NULL;
  for (int i = 0; i < h->e_shnum; ++i) {
    CHECK_BOUNDARY(sht, i, h->e_shentsize);
    Elf64_Shdr *current_shdr = &sht[i];
#if DEBUG
    print_section_header(sht, shstrtab, i);
#endif
    if (current_shdr->sh_type == SHT_SYMTAB) {
      symtab_header = current_shdr;
      // Check if symbol table is within bounds
      CHECK_OFFSET_SIZE(symtab_header->sh_offset, symtab_header->sh_size,
                        "Symbol table extends beyond file");
    }
  }
}

int do_pack(const char *filename) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", filename, strerror(errno));
    goto error_exit_do_pack_fd;
  }
  if (fstat(fd, &st) < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", filename, strerror(errno));
    goto error_exit_do_pack_fd;
  }
  if (st.st_size == 0) { // Empty file is valid
    goto error_exit_do_pack_fd;
  }
  if (st.st_size < (__off_t)EI_NIDENT) {
    ft_dprintf(STDERR_FILENO, "File too small to be an ELF file\n");
    goto error_exit_do_pack_fd;
  }
  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) {
    perror("mmap");
    goto error_exit_do_pack_fd;
  }
  // Check if we can safely read the ELF header
  const unsigned char *e_ident = (unsigned char *)map;
  if (!is_elf(e_ident)) {
    ft_dprintf(STDERR_FILENO, "Not an ELF file\n");
    goto error_exit_do_pack_mmap;
  }
  // Determine the ELF class
  unsigned char elf_class = e_ident[EI_CLASS];
  if (elf_class == ELFCLASS64) {
    do_pack_64bit();
  } else if (elf_class == ELFCLASS32) {
    ft_dprintf(STDERR_FILENO, "File architecture not suported. x86_64 only\n");
    goto error_exit_do_pack_mmap;
  } else {
    ft_dprintf(STDERR_FILENO, "Invalid ELF class value.\n");
    goto error_exit_do_pack_mmap;
  }

  // Copy the file to a buffer
  size_t packed_size = st.st_size;
  unsigned char *packed = malloc(packed_size);
  if (packed == NULL) {
    ft_dprintf(STDERR_FILENO, "malloc failed.\n");
    goto error_exit_do_pack_mmap;
  }
  ft_memcpy(packed, map, st.st_size);

  // TODO: pack the file

  // Write to new file
  const char *new_filename = ft_strjoin(filename, ".packed");
  int ofd = open(new_filename, O_CREAT | O_WRONLY | O_TRUNC, 0744);
  if (ofd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", new_filename, strerror(errno));
    goto error_exit_do_pack_ofd;
  }
  write(ofd, packed, packed_size); // TODO: handle partial write
  close(ofd);
  close(fd);
  munmap(map, st.st_size);
  return 0;
error_exit_do_pack_ofd:
  close(ofd);
error_exit_do_pack_mmap:
  munmap(map, st.st_size);
error_exit_do_pack_fd:
  close(fd);
  return -1;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage_error();
  }
  int is_error = do_pack(argv[1]);
  if (is_error) {
    return 1;
  } else {
    return 0;
  }
}
