#include "ft_printf.h"
#include <elf.h>

char *string_of_e_type(uint16_t e_type) {
  switch (e_type) {
  case ET_NONE:
    return "ET_NONE";
  case ET_REL:
    return "ET_REL";
  case ET_EXEC:
    return "ET_EXEC";
  case ET_DYN:
    return "ET_DYN";
  case ET_CORE:
    return "ET_CORE";
  case ET_LOOS:
    return "ET_LOOS";
  case ET_HIOS:
    return "ET_HIOS";
  case ET_LOPROC:
    return "ET_LOPROC";
  case ET_HIPROC:
    return "ET_HIPROC";
  default:
    return "Unknown";
  }
}

char *string_of_sh_type(uint32_t sh_type) {
  switch (sh_type) {
  case 0x00:
    return "SHT_NULL";
  case 0x01:
    return "SHT_PROGBITS";
  case 0x02:
    return "SHT_SYMTAB";
  case 0x03:
    return "SHT_STRTAB";
  case 0x04:
    return "SHT_RELA";
  case 0x05:
    return "SHT_HASH";
  case 0x06:
    return "SHT_DYNAMIC";
  case 0x07:
    return "SHT_NOTE";
  case 0x08:
    return "SHT_NOBITS";
  case 0x09:
    return "SHT_REL";
  case 0x0a:
    return "SHT_SHLIB";
  case 0x0b:
    return "SHT_DYNSYM";
  case 0x0e:
    return "SHT_INIT_ARRAY";
  case 0x0f:
    return "SHT_FINI_ARRAY";
  case 0x10:
    return "SHT_PREINIT_ARRAY";
  case 0x11:
    return "SHT_GROUP";
  case 0x12:
    return "SHT_SYMTAB_SHNDX";
  case 0x13:
    return "SHT_NUM";
  default:
    return "Unknown";
  }
}

void print_elf_header(Elf64_Ehdr *h) {
  ft_printf("e_ident:     ");
  for (int i = 0; i < 16; ++i) {
    ft_printf("%02x", h->e_ident[i]);
    if (i != 15)
      ft_printf(" ");
    if (i == 7)
      ft_printf(" ");
  }
  ft_printf("\n");
  ft_printf("e_type:      0x%x (%s)\n", h->e_type, string_of_e_type(h->e_type));
  ft_printf("e_machine:   0x%x\n", h->e_machine);
  ft_printf("e_version:   0x%x\n", h->e_version);
  ft_printf("e_entry:     0x%lx\n", h->e_entry);
  ft_printf("e_phoff:     0x%lx\n", h->e_phoff);
  ft_printf("e_shoff:     0x%lx\n", h->e_shoff);
  ft_printf("e_flags:     0x%x\n", h->e_flags);
  ft_printf("e_ehsize:    0x%x\n", h->e_ehsize);
  ft_printf("e_phentsize: 0x%x\n", h->e_phentsize);
  ft_printf("e_phnum:     0x%x\n", h->e_phnum);
  ft_printf("e_shentsize: 0x%x\n", h->e_shentsize);
  ft_printf("e_shnum:     0x%x\n", h->e_shnum);
  ft_printf("e_shstrndx:  0x%x\n", h->e_shstrndx);
}

void print_section_header(const Elf64_Shdr *sht, const char *shstrtab, int i) {
  const char *name = shstrtab + sht[i].sh_name;
  ft_printf("Section %d (%s)\n", i, name);
  ft_printf("\tsh_name:      0x%x\n", sht[i].sh_name);
  ft_printf("\tsh_type:      0x%x (%s)\n", sht[i].sh_type,
            string_of_sh_type(sht[i].sh_type));
  ft_printf("\tsh_flags:     0x%lx\n", sht[i].sh_flags);
  ft_printf("\tsh_addr:      0x%lx\n", sht[i].sh_addr);
  ft_printf("\tsh_offset:    0x%lx\n", sht[i].sh_offset);
  ft_printf("\tsh_size:      0x%lx\n", sht[i].sh_size);
  ft_printf("\tsh_link:      0x%x\n", sht[i].sh_link);
  ft_printf("\tsh_info:      0x%x\n", sht[i].sh_info);
  ft_printf("\tsh_addralign: 0x%lx\n", sht[i].sh_addralign);
  ft_printf("\tsh_entsize:   0x%lx\n", sht[i].sh_entsize);
  ft_printf("\n");
}

char *string_of_symbol_type(uint8_t st_info) {
  switch (ELF64_ST_TYPE(st_info)) {
  case 0:
    return "NOTYPE";
  case 1:
    return "OBJECT";
  case 2:
    return "FUNC";
  case 3:
    return "SECTION";
  case 4:
    return "FILE";
  case 13:
    return "LOPROC";
  case 15:
    return "HIPROC";
  default:
    return "Unknown";
  }
}

char *string_of_symbol_binding(uint8_t st_info) {
  switch (ELF64_ST_BIND(st_info)) {
  case 0:
    return "LOCAL";
  case 1:
    return "GLOBAL";
  case 2:
    return "WEAK";
  case 13:
    return "LOPROC";
  case 15:
    return "HIPROC";
  default:
    return "Unknown";
  }
}

void print_symbols(Elf64_Sym *symtab, char *strtab, int num_symbols) {
  for (int i = 0; i < num_symbols; ++i) {
    ft_printf("Symbol %d\n", i);
    ft_printf("\tst_name: 0x%x (%s)\n", symtab[i].st_name,
              strtab + symtab[i].st_name);
    ft_printf("\tst_info: 0x%x\n", symtab[i].st_info);
    ft_printf("\tst_other: 0x%x\n", symtab[i].st_other);
    ft_printf("\tst_shndx: 0x%x\n", symtab[i].st_shndx);
    ft_printf("\tst_value: 0x%lx\n", symtab[i].st_value);
    ft_printf("\tst_size: 0x%lx\n", symtab[i].st_size);
    ft_printf("\n");
  }
}
