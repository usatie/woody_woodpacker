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
static void *elf;

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
  if ((__off_t)(((void *)ptr - (void *)elf) + (index + 1) * entsize) >         \
      st.st_size) {                                                            \
    ft_dprintf(STDERR_FILENO, "CHECK_BOUNDARY failed: %s %s %s\n", #ptr,       \
               #index, #entsize);                                              \
    exit(1);                                                                   \
  }

#define CHECK_CSTRING_BOUNDARY(str)                                            \
  {                                                                            \
    const char *tmp = str;                                                     \
    while (*tmp && (__off_t)((void *)tmp - (void *)elf) < st.st_size) {        \
      ++tmp;                                                                   \
    }                                                                          \
    if ((__off_t)(void *)((void *)tmp - (void *)elf) >= st.st_size) {          \
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

const char *get_c_string(char *elf, size_t offset) {
  CHECK_SIZE(offset, "Invalid offset for c string");
  char *str = (char *)(elf + offset);
  CHECK_CSTRING_BOUNDARY(str);
  return str;
}

void encrypt(uint8_t key, uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    data[i] ^= key;
  }
}

int do_pack(const char *filename) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", filename,
               strerror(errno));
    goto error_exit_do_pack_fd;
  }
  if (fstat(fd, &st) < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", filename,
               strerror(errno));
    goto error_exit_do_pack_fd;
  }
  if (st.st_size == 0) { // Empty file is valid
    goto error_exit_do_pack_fd;
  }
  if (st.st_size < (__off_t)EI_NIDENT) {
    ft_dprintf(STDERR_FILENO, "File too small to be an ELF file\n");
    goto error_exit_do_pack_fd;
  }
  elf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (elf == MAP_FAILED) {
    perror("mmap");
    goto error_exit_do_pack_fd;
  }
  close(fd); // Close the file descriptor as we have mmaped the file
  // Check if we can safely read the ELF header
  const unsigned char *e_ident = (unsigned char *)elf;
  if (!is_elf(e_ident)) {
    ft_dprintf(STDERR_FILENO, "Not an ELF file\n");
    goto error_exit_do_pack_mmap;
  }
  // Determine the ELF class
  unsigned char elf_class = e_ident[EI_CLASS];
  if (elf_class == ELFCLASS64) {
    ; // continue
  } else if (elf_class == ELFCLASS32) {
    ft_dprintf(STDERR_FILENO, "File architecture not suported. x86_64 only\n");
    goto error_exit_do_pack_mmap;
  } else {
    ft_dprintf(STDERR_FILENO, "Invalid ELF class value.\n");
    goto error_exit_do_pack_mmap;
  }

  // Copy the file to a buffer
  ft_printf("size: 0x%x\n", st.st_size);
  size_t packed_size = st.st_size + 1024 + sizeof(Elf64_Shdr);
  unsigned char *packed = malloc(packed_size);
  if (packed == NULL) {
    ft_dprintf(STDERR_FILENO, "malloc failed.\n");
    goto error_exit_do_pack_mmap;
  }
  ft_memcpy(packed, elf, st.st_size);

  // TODO: pack the file
  // 1. Parse the ELF file
  /*
   * For adding .packed section, we need to do add/modify the following:
   *   1. Modify ELF header
   *   2. (Optional) Modify the program header table
   *   2. Add the .packed section header
   *   3. Add the .packed section
   *   4. Add the .packed section name to the section header string table
   * */
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdrs = (Elf64_Shdr *)(elf + ehdr->e_shoff); // need to add
  Elf64_Shdr *shstrtab = &shdrs[ehdr->e_shstrndx];         // need to add
  for (int i = 0; i < ehdr->e_shnum; ++i) {
    Elf64_Shdr *shdr = &shdrs[i];
    const char *name = get_c_string(elf, shstrtab->sh_offset + shdr->sh_name);
    ft_printf("Section %d: %s (0x%x-0x%x) (addr:0x%x)\n", i, name,
              shdr->sh_offset, shdr->sh_offset + shdr->sh_size - 1,
              shdr->sh_addr);
  }
  // 2. Write the loader program to the packed file
  /*
   * ELF File Structure:
   *  ELF Header
   *  Program Header Table
   *  [Sections]
   *  Section Header Table
   */
  Elf64_Ehdr *new_ehdr = (Elf64_Ehdr *)packed;
  size_t ehdr_offset = 0;
  size_t phdr_offset = ehdr_offset + sizeof(Elf64_Ehdr);
  Elf64_Phdr *new_phdrs = (Elf64_Phdr *)(packed + phdr_offset);
  size_t section_start_offset =
      phdr_offset + ehdr->e_phnum * sizeof(Elf64_Phdr);
  size_t next_executable_offset = 0;
  size_t next_executable_vaddr = 0;
  int text_segment_index = -1;
  // Loop through the program headers to find the executable segment
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    Elf64_Phdr *phdr = &new_phdrs[i];
    if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
      if (text_segment_index != -1) {
        ft_dprintf(STDERR_FILENO, "Multiple executable segments found\n");
        goto error_exit_do_pack_mmap;
      }
      text_segment_index = i;
      encrypt(0xa5, packed + phdr->p_offset + 0x60, phdr->p_filesz - 0x60);
    }
  }
  if (text_segment_index == -1) {
    ft_dprintf(STDERR_FILENO, "No executable segment found\n");
    goto error_exit_do_pack_mmap;
  }
  // TODO: Sort the sections by offset
  // Loop through the sections to find the next executable section
  for (int i = 0; i < ehdr->e_shnum + 1; ++i) {
    Elf64_Shdr *shdr = &shdrs[i];
    if (shdr->sh_type == SHT_PROGBITS && (shdr->sh_flags & SHF_EXECINSTR)) {
      if (shdr->sh_offset > next_executable_offset) {
        // Found the next executable section
        next_executable_offset = shdr->sh_offset + shdr->sh_size;
      }
      if (shdr->sh_addr > next_executable_vaddr) {
        next_executable_vaddr = shdr->sh_addr + shdr->sh_size;
      }
    }
  }
  if (next_executable_offset % 16 != 0) {
    next_executable_offset += 16 - (next_executable_offset % 16);
  }
  if (next_executable_vaddr % 16 != 0) {
    next_executable_vaddr += 16 - (next_executable_vaddr % 16);
  }
  ft_printf("next_executable_offset: 0x%x\n", next_executable_offset);
  ft_printf("next_executable_vaddr: 0x%x\n", next_executable_vaddr);
  Elf64_Shdr packed_shdr = {
      .sh_name = 0, // TODO: shstrtab->sh_size + 1, and update shstrtab
      .sh_type = SHT_PROGBITS,
      .sh_flags = SHF_EXECINSTR | SHF_ALLOC,
      .sh_addr = next_executable_vaddr,
      .sh_offset = next_executable_offset,
      .sh_size = 1024,
      .sh_link = 0,
      .sh_info = 0,
      .sh_addralign = 16,
      .sh_entsize = 0};
  new_ehdr->e_shnum += 1;
  new_ehdr->e_entry = next_executable_vaddr;

  // 1. Read the Loader program to the memory
  unsigned char packed_text[1024] = {};
  int lfd = open("src/loader", O_RDONLY);
  if (lfd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", "loader",
               strerror(errno));
    goto error_exit_do_pack_lfd;
  }
  ssize_t n =
      read(lfd, packed_text,
           sizeof(packed_text)); // TODO: handle partial read or use mmap
  packed_shdr.sh_size = n;
  new_phdrs[text_segment_index].p_filesz =
      packed_shdr.sh_offset - new_phdrs[text_segment_index].p_offset + n;
  new_phdrs[text_segment_index].p_memsz =
      new_phdrs[text_segment_index].p_filesz;
  // Write to the packed region
  ft_memcpy(packed + ehdr->e_shoff + (ehdr->e_shnum) * sizeof(Elf64_Shdr),
            &packed_shdr, sizeof(Elf64_Shdr));
  ft_memcpy(packed + next_executable_offset, packed_text, n);
  // Write to new file
  const char *new_filename = ft_strjoin(filename, ".packed");
  int ofd = open(new_filename, O_CREAT | O_WRONLY | O_TRUNC, 0755);
  if (ofd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", new_filename,
               strerror(errno));
    goto error_exit_do_pack_ofd;
  }
  write(ofd, packed, packed_size); // TODO: handle partial write or use mmap
  close(ofd);
  close(lfd);
  munmap(elf, st.st_size);
  return 0;
error_exit_do_pack_ofd:
  close(ofd);
error_exit_do_pack_lfd:
  close(lfd);
error_exit_do_pack_mmap:
  munmap(elf, st.st_size);
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
