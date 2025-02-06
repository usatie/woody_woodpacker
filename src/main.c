#include "ft_printf.h"
#include "libft.h"
#include "loader_data.h"
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

const char *get_c_string(char *elf, size_t offset) {
  CHECK_SIZE(offset, "Invalid offset for c string");
  char *str = (char *)(elf + offset);
  CHECK_CSTRING_BOUNDARY(str);
  return str;
}

void encrypt(uint64_t key, uint8_t *data, size_t size_in_bytes) {
  for (size_t i = 0; i < ((size_in_bytes + 8 - 1) / 8); ++i) {
    *((uint64_t *)(data + i * sizeof(uint64_t))) ^= key;
  }
}

void *ft_memmem(const void *haystack, size_t haystacklen, const void *needle,
                size_t needlelen);

// Inefficient implementation of memmem, but it works
void *ft_memmem(const void *haystack, size_t haystacklen, const void *needle,
                size_t needlelen) {
  size_t i = 0;
  while (i + needlelen <= haystacklen) {
    if (memcmp(haystack + i, needle, needlelen) == 0) {
      return (void *)(haystack + i);
    }
    ++i;
  }
  return NULL;
}

int generate_key(void *key, size_t size) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror("open");
    return -1;
  }
  ssize_t n = read(fd, key, size);
  if (n != (ssize_t)size) {
    perror("read");
    return -1;
  }
  close(fd);
  return 0;
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
  // Elf64_Shdr *shstrtab = &shdrs[ehdr->e_shstrndx];         // need to add
  //  2. Write the loader program to the packed file
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
  size_t next_executable_offset = 0;
  size_t next_executable_vaddr = 0;
  int text_segment_index = -1;
  uint64_t encryption_key;
  if (generate_key(&encryption_key, sizeof(encryption_key)) < 0) {
    perror("generate_key");
    goto error_exit_do_pack_mmap;
  }
  // Loop through the program headers to find the executable segment
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    Elf64_Phdr *phdr = &new_phdrs[i];
    if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
      if (text_segment_index != -1) {
        ft_dprintf(STDERR_FILENO, "Multiple executable segments found\n");
        goto error_exit_do_pack_mmap;
      }
      text_segment_index = i;
      encrypt(encryption_key, packed + phdr->p_offset, phdr->p_filesz);
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
      if (shdr->sh_offset + shdr->sh_size > next_executable_offset) {
        // Found the next executable section
        next_executable_offset = shdr->sh_offset + shdr->sh_size;
      }
      if (shdr->sh_addr + shdr->sh_size > next_executable_vaddr) {
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
  packed_shdr.sh_size = sizeof(src_loader);
  new_phdrs[text_segment_index].p_filesz =
      packed_shdr.sh_offset - new_phdrs[text_segment_index].p_offset +
      sizeof(src_loader);
  new_phdrs[text_segment_index].p_memsz =
      new_phdrs[text_segment_index].p_filesz;
  // Update the dummy values in the packed text
  // 1. Patch the address in the loader
  {
    uint32_t placeholder = 0x11111111;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(
          STDERR_FILENO,
          "mprotect addr placeholder (0x11111111) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    while (found) {
      size_t rip_offset = (void *)found - (void *)src_loader +
                          packed_shdr.sh_offset + sizeof(uint32_t);
      int32_t addr = new_phdrs[text_segment_index].p_offset - rip_offset;
      ft_memcpy(found, &addr, sizeof(addr));
      found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                        sizeof(placeholder));
    }
  }
  // 2. Patch the len in the loader
  {
    uint32_t placeholder = 0x22222222;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(STDERR_FILENO,
                 "mprotect len placeholder (0x22222222) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    while (found) {
      Elf64_Phdr *text_phdr = &new_phdrs[text_segment_index];
      uint32_t len = (text_phdr->p_filesz + text_phdr->p_align - 1) /
                     text_phdr->p_align * text_phdr->p_align;
      ft_memcpy(found, &len, sizeof(len));
      found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                        sizeof(placeholder));
    }
  }
  // 3. Patch dst in the loader
  {
    uint32_t placeholder = 0x33333333;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(STDERR_FILENO,
                 "dst placeholder (0x33333333) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    size_t rip_offset = (void *)found - (void *)src_loader +
                        packed_shdr.sh_offset + sizeof(uint32_t);
    int32_t dst = new_phdrs[text_segment_index].p_offset - rip_offset;
    ft_memcpy(found, &dst, sizeof(dst));
  }
  // 4. Patch size in the loader
  {
    uint32_t placeholder = 0x44444444;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(STDERR_FILENO,
                 "size placeholder (0x44444444) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    uint32_t size = phdrs[text_segment_index].p_filesz;
    size = (size + 8 - 1) / 8;
    ft_memcpy(found, &size, sizeof(size));
  }
  // 5. Patch key in the loader
  {
    uint64_t placeholder = 0x5555555555555555;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(STDERR_FILENO,
                 "key placeholder (0x5555555555555555) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    ft_memcpy(found, &encryption_key, sizeof(encryption_key));
  }
  // 6. Patch orig_ep_offset in the loader
  {
    uint32_t placeholder = 0x66666666;
    void *found = ft_memmem(src_loader, sizeof(src_loader), &placeholder,
                            sizeof(placeholder));
    if (found == NULL) {
      ft_dprintf(
          STDERR_FILENO,
          "orig_ep_offset placeholder (0x66666666) not found in loader\n");
      goto error_exit_do_pack_mmap;
    }
    size_t rip_offset = (void *)found - (void *)src_loader +
                        packed_shdr.sh_offset + sizeof(uint32_t);
    uint32_t orig_ep_offset = ehdr->e_entry - rip_offset;
    ft_memcpy(found, &orig_ep_offset, sizeof(orig_ep_offset));
  }
  // Write to the packed region
  ft_memcpy(packed + ehdr->e_shoff + (ehdr->e_shnum) * sizeof(Elf64_Shdr),
            &packed_shdr, sizeof(Elf64_Shdr));
  ft_memcpy(packed + next_executable_offset, src_loader, sizeof(src_loader));
  // Write to new file
  const char *new_filename = ft_strjoin(filename, ".packed");
  int ofd = open(new_filename, O_CREAT | O_WRONLY | O_TRUNC, 0755);
  if (ofd < 0) {
    ft_dprintf(STDERR_FILENO, "woody_woodpacker: '%s': %s\n", new_filename,
               strerror(errno));
    goto error_exit_do_pack_ofd;
  }
  write(ofd, packed, packed_size); // TODO: handle partial write or use mmap
  ft_printf("key_value: %lX\n", encryption_key);
  close(ofd);
  munmap(elf, st.st_size);
  return 0;
error_exit_do_pack_ofd:
  close(ofd);
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
