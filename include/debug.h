#ifndef DEBUG_H
#define DEBUG_H

#include <stdint.h>
char *string_of_sh_type(uint32_t sh_type);
char *string_of_e_type(uint16_t e_type);
void print_elf_header(Elf64_Ehdr *h);
void print_section_header(Elf64_Shdr *sht, char *shstrtab, int i);
char *string_of_symbol_type(uint8_t st_info);
char *string_of_symbol_binding(uint8_t st_info);
char *string_of_symbol_visibility(uint8_t st_other);
void print_symbols(Elf64_Sym *symtab, char *strtab, int num_symbols);

#endif
