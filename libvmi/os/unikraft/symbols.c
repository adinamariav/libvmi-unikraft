/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include "os/unikraft/unikraft.h"

#define EI_NIDENT 16
#define STR_SIZE 50

struct elf64_ehdr {
    unsigned char e_ident[EI_NIDENT];
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
} __attribute__ ((packed));

struct elf64_shdr
{
  uint32_t	sh_name;		/* Section name (string tbl index) */
  uint32_t	sh_type;		/* Section type */
  uint64_t	sh_flags;		/* Section flags */
  uint64_t	sh_addr;		/* Section virtual addr at execution */
  uint64_t	sh_offset;		/* Section file offset */
  uint64_t	sh_size;		/* Section size in bytes */
  uint32_t	sh_link;		/* Link to another section */
  uint32_t	sh_info;		/* Additional section information */
  uint64_t	sh_addralign;		/* Section alignment */
  uint64_t	sh_entsize;		/* Entry size if section holds table */
} __attribute__ ((packed));

struct elf64_sym {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} __attribute__ ((packed));

#define SHT_SYMTAB	  2
#define SHT_DYNAMIC	  6

status_t read_section_header_table(FILE* f, struct elf64_ehdr elf_header, struct elf64_shdr sh_table[]) {
     if (fseek(f, (off_t)elf_header.e_shoff, SEEK_SET) != 0) {
        errprint("Error seeking for sht\n");
        return VMI_FAILURE;
     }

    for (uint32_t i = 0; i < elf_header.e_shnum; i++) {
        size_t n = fread((void *)&sh_table[i], 1, elf_header.e_shentsize, f);

        if (n != elf_header.e_shentsize) {
            errprint("Error reading sht\n");
            return VMI_FAILURE;
        }
    }

    return VMI_SUCCESS;
}

char* read_section(FILE* f, struct elf64_shdr sh) {
    char* section = g_try_malloc0(sh.sh_size);
    if (section == NULL) {
        errprint("Memory allocation failed for 'sym_tbl'\n");
        return NULL;
    }

   if (fseek(f, (off_t)sh.sh_offset, SEEK_SET) != 0) {
        errprint("Error seeking symbol section\n");
        return NULL;
    }

    size_t len = fread((void *)section, 1, sh.sh_size, f);
    if (len != sh.sh_size) {
        errprint("Error reading symbol section'\n");
        return NULL;
    }

    return section;
}

char* addr2symbol_lookup(FILE *f, struct elf64_ehdr elf_header, struct elf64_shdr sh_table[], addr_t address) {
    char *str_tbl = NULL;
    char *symbol = NULL;
    struct elf64_sym *sym_tbl = NULL;
    uint32_t symbol_count = 0;

    for (uint32_t i = 0; i < elf_header.e_shnum; i++) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            sym_tbl = (struct elf64_sym *)read_section(f, sh_table[i]);
            if (!sym_tbl) {
                errprint("Failed to read symbol table section\n");
                goto done;
            }

            uint32_t str_tbl_ndx = sh_table[i].sh_link;
            str_tbl = read_section(f, sh_table[str_tbl_ndx]);
            if (!str_tbl) {
                errprint("Failed to read string table section\n");
                goto done;
            }

            symbol_count = sh_table[i].sh_size / sizeof(struct elf64_sym);

            uint64_t lower = 0;

            char symbol_lower[STR_SIZE + 1], curr_symbol[STR_SIZE + 1];

            for (uint32_t j = 0; j < symbol_count; j++) {
                strncpy(curr_symbol, str_tbl + sym_tbl[j].st_name, STR_SIZE);
                curr_symbol[STR_SIZE] = '\0';

                if (sym_tbl[j].st_value == address) {
                    symbol = g_try_malloc0(strlen(curr_symbol) + 1);
                    if (!symbol) {
                        errprint("Memory allocation failed for 'symbol'\n");
                        goto done;
                    }

                    strcpy(symbol, curr_symbol);
                    goto done;
                }

                if (sym_tbl[j].st_value < address) {
                    if (lower < sym_tbl[j].st_value) {
                        lower = sym_tbl[j].st_value;
                        strncpy(symbol_lower, curr_symbol, STR_SIZE);
                        symbol_lower[STR_SIZE] = '\0';
                    }
                }
            }

            symbol = g_try_malloc0(strlen(symbol_lower) + 1);
            if (!symbol) {
                errprint("Memory allocation failed for 'symbol'\n");
                goto done;
            }

            strcpy(symbol, symbol_lower);
            goto done;
        }
    }

done:
    if (str_tbl) 
        free(str_tbl);
    if (sym_tbl) 
        free(sym_tbl);
    return symbol;
}               

status_t symbol2addr_lookup(FILE *f, struct elf64_ehdr elf_header, struct elf64_shdr sh_table[], const char* symbol, addr_t* address) {
    char *str_tbl = NULL;
    struct elf64_sym *sym_tbl = NULL;
    uint32_t symbol_count = 0;

    for (uint32_t i = 0; i < elf_header.e_shnum; i++) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            sym_tbl = (struct elf64_sym *)read_section(f, sh_table[i]);
            if (!sym_tbl) {
                errprint("Failed to read symbol table section\n");
                goto done;
            }

            uint32_t str_tbl_ndx = sh_table[i].sh_link;
            str_tbl = read_section(f, sh_table[str_tbl_ndx]);
            if (!str_tbl) {
                errprint("Failed to read string table section\n");
                goto done;
            }

            symbol_count = sh_table[i].sh_size / sizeof(struct elf64_sym);

            char curr_symbol[STR_SIZE + 1];

            for (uint32_t j = 0; j < symbol_count; j++) {
                strncpy(curr_symbol, str_tbl + sym_tbl[j].st_name, STR_SIZE);
                curr_symbol[STR_SIZE] = '\0';

                if (strcmp(curr_symbol, symbol) == 0) {
                    *address = sym_tbl[j].st_value;
                    goto done;
                }
            }
        }
    }

done:
    if (str_tbl) 
        free(str_tbl);
    if (sym_tbl) 
        free(sym_tbl);
    return VMI_SUCCESS;
}   

char* unikraft_system_map_address_to_symbol(
    vmi_instance_t vmi,
    addr_t address,
    const access_context_t *ctx)
{
    FILE* f;
    struct elf64_ehdr elf_header;
    struct elf64_shdr* sh_tbl;

    unikraft_instance_t unikraft_instance = vmi->os_data;

#ifdef ENABLE_SAFETY_CHECKS
    if (!unikraft_instance) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        goto done;
    }
#endif

    if ((NULL == unikraft_instance->kernel) || (strlen(unikraft_instance->kernel) == 0)) {
        errprint("VMI_WARNING: No unikraft kernel configured\n");
        goto done;
    }

    f = fopen(unikraft_instance->kernel, "r");
    if (f == NULL) {
        fprintf(stderr,
                "ERROR: could not find kernel file after checking:\n");
        fprintf(stderr, "\t%s\n", unikraft_instance->kernel);
        fprintf(stderr,
                "To fix this problem, add the correct kernel entry to /etc/libvmi.conf\n");
        goto done;
    }

    size_t ret = fread(&elf_header, sizeof(struct elf64_ehdr), 1, f);

    if (ret == 0) {
        errprint("Error reading ELF header\n");
        goto done;
    }

    sh_tbl = g_try_malloc0(elf_header.e_shentsize * elf_header.e_shnum);
    if (sh_tbl == NULL) {
        errprint("Memory allocation failed for 'sh_tbl'\n");
        goto done;
    }

    if (read_section_header_table(f, elf_header, sh_tbl) == VMI_FAILURE) {
        errprint("Error reading 'sh_tbl'\n");
        goto done;
    }

    char* symbol = addr2symbol_lookup(f, elf_header, sh_tbl, address);

    if (symbol == NULL) {
        errprint("Error performing symbol lookup\n");
        goto done;
    }
    
done:
    if (sh_tbl)
        free(sh_tbl);
    if (f)
        fclose(f);
    return symbol;

    errprint("VMI_WARNING: Lookup is implemented for kernel symbols only\n");
    if (symbol)
        free(symbol);
    return NULL;
}

status_t unikraft_system_map_symbol_to_address(vmi_instance_t vmi,
    const char *symbol,
    addr_t* UNUSED(__unused),
    addr_t* address)
{
    FILE* f;
    struct elf64_ehdr elf_header;
    struct elf64_shdr* sh_tbl;

    unikraft_instance_t unikraft_instance = vmi->os_data;

#ifdef ENABLE_SAFETY_CHECKS
    if (!unikraft_instance) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        goto done;
    }
#endif

    if ((NULL == unikraft_instance->kernel) || (strlen(unikraft_instance->kernel) == 0)) {
        errprint("VMI_WARNING: No unikraft kernel configured\n");
        goto done;
    }

    f = fopen(unikraft_instance->kernel, "r");

    if (f == NULL) {
        fprintf(stderr,
                "ERROR: could not find kernel file after checking:\n");
        fprintf(stderr, "\t%s\n", unikraft_instance->kernel);
        fprintf(stderr,
                "To fix this problem, add the correct kernel entry to /etc/libvmi.conf\n");
        goto done;
    }

    int ret = fread(&elf_header, sizeof(struct elf64_ehdr), 1, f);

    if (ret == 0) {
        errprint("Error reading ELF header\n");
        goto done;
    }

    sh_tbl = g_try_malloc0(elf_header.e_shentsize * elf_header.e_shnum);
    if (sh_tbl == NULL) {
        errprint("Memory allocation failed for 'sh_tbl'\n");
        goto done;
    }

    if (read_section_header_table(f, elf_header, sh_tbl) == VMI_FAILURE) {
        errprint("Error reading 'sh_tbl'\n");
        goto done;
    }

    status_t status = symbol2addr_lookup(f, elf_header, sh_tbl, symbol, address);

    if (status == VMI_FAILURE) {
        errprint("Error performing symbol lookup\n");
        goto done;
    }
    
done:
    if (sh_tbl)
        free(sh_tbl);
    if (f)
        fclose(f);
    return VMI_SUCCESS;

    errprint("VMI_WARNING: Lookup is implemented for kernel symbols only\n");
    return VMI_FAILURE;
}