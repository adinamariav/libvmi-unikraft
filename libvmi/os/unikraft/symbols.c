#include "private.h"
#define _GNU_SOURCE
#include "os/unikraft/unikraft.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

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
} __attribute__((packed));

struct elf64_shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} __attribute__((packed));

struct elf64_sym {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} __attribute__((packed));

#define SHT_SYMTAB 2
#define SHT_DYNAMIC 6

status_t
read_section_header_table(FILE * f, const struct elf64_ehdr *elf_header,
                          struct elf64_shdr *sh_table)
{
    if (fseek(f, (off_t) elf_header->e_shoff, SEEK_SET) != 0) {
        errprint("Error seeking section header table\n");
        return VMI_FAILURE;
    }

    for (uint32_t i = 0; i < elf_header->e_shnum; i++) {
        size_t n = fread(&sh_table[i], elf_header->e_shentsize, 1, f);

        if (n != 1) {
            errprint("Error reading section header table\n");
            return VMI_FAILURE;
        }
    }

    return VMI_SUCCESS;
}

char *
read_section(FILE * f, const struct elf64_shdr *sh)
{
    char *section = g_try_malloc0(sh->sh_size);
    if (!section) {
        errprint("Memory allocation failed for section\n");
        return NULL;
    }

    if (fseek(f, (off_t) sh->sh_offset, SEEK_SET) != 0) {
        errprint("Error seeking section\n");
        g_free(section);
        return NULL;
    }

    size_t len = fread(section, 1, sh->sh_size, f);
    if (len != sh->sh_size) {
        errprint("Error reading section\n");
        g_free(section);
        return NULL;
    }

    return section;
}

char *
addr2symbol_lookup(FILE * f, const struct elf64_ehdr *elf_header,
                   const struct elf64_shdr *sh_table, addr_t address)
{
    char *str_tbl = NULL, *symbol = NULL;
    struct elf64_sym *sym_tbl = NULL;
    uint32_t symbol_count = 0;

    for (uint32_t i = 0; i < elf_header->e_shnum; i++) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            sym_tbl = (struct elf64_sym *) read_section(f, &sh_table[i]);
            if (!sym_tbl) {
                errprint("Failed to read symbol table section\n");
                goto cleanup;
            }

            uint32_t str_tbl_ndx = sh_table[i].sh_link;
            str_tbl = read_section(f, &sh_table[str_tbl_ndx]);
            if (!str_tbl) {
                errprint("Failed to read string table section\n");
                goto cleanup;
            }

            symbol_count = sh_table[i].sh_size / sizeof(struct elf64_sym);
            char symbol_lower[STR_SIZE + 1] = { 0 };
            uint64_t lower = 0;

            for (uint32_t j = 0; j < symbol_count; j++) {
                char curr_symbol[STR_SIZE + 1] = { 0 };
                strncpy(curr_symbol, str_tbl + sym_tbl[j].st_name, STR_SIZE);

                if (sym_tbl[j].st_value == address) {
                    symbol = g_try_malloc0(strlen(curr_symbol) + 1);
                    if (!symbol) {
                        errprint("Memory allocation failed for symbol\n");
                        goto cleanup;
                    }
                    strcpy(symbol, curr_symbol);
                    goto cleanup;
                }

                if (sym_tbl[j].st_value < address &&
                    sym_tbl[j].st_value > lower) {
                    lower = sym_tbl[j].st_value;
                    strncpy(symbol_lower, curr_symbol, STR_SIZE);
                }
            }

            if (lower != 0) {
                symbol = g_try_malloc0(strlen(symbol_lower) + 1);
                if (!symbol) {
                    errprint("Memory allocation failed for symbol\n");
                    goto cleanup;
                }
                strcpy(symbol, symbol_lower);
            }

            goto cleanup;
        }
    }

cleanup:
    if (str_tbl)
        g_free(str_tbl);
    if (sym_tbl)
        g_free(sym_tbl);
    return symbol;
}

status_t
symbol2addr_lookup(FILE * f, const struct elf64_ehdr *elf_header,
                   const struct elf64_shdr *sh_table,
                   const char *symbol, addr_t *address)
{
    char *str_tbl = NULL;
    struct elf64_sym *sym_tbl = NULL;
    uint32_t symbol_count = 0;
    status_t status = VMI_FAILURE;

    for (uint32_t i = 0; i < elf_header->e_shnum; i++) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            sym_tbl = (struct elf64_sym *) read_section(f, &sh_table[i]);
            if (!sym_tbl) {
                errprint("Failed to read symbol table section\n");
                goto cleanup;
            }

            uint32_t str_tbl_ndx = sh_table[i].sh_link;
            str_tbl = read_section(f, &sh_table[str_tbl_ndx]);
            if (!str_tbl) {
                errprint("Failed to read string table section\n");
                goto cleanup;
            }

            symbol_count = sh_table[i].sh_size / sizeof(struct elf64_sym);
            char curr_symbol[STR_SIZE + 1] = { 0 };

            for (uint32_t j = 0; j < symbol_count; j++) {
                strncpy(curr_symbol, str_tbl + sym_tbl[j].st_name, STR_SIZE);

                if (strcmp(curr_symbol, symbol) == 0) {
                    *address = sym_tbl[j].st_value;
                    status = VMI_SUCCESS;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    if (str_tbl)
        g_free(str_tbl);
    if (sym_tbl)
        g_free(sym_tbl);
    return status;
}

char *
unikraft_system_map_address_to_symbol(vmi_instance_t vmi, addr_t address,
                                      const access_context_t * UNUSED(ctx))
{
    FILE *f = NULL;
    char *symbol = NULL;
    struct elf64_ehdr elf_header = { 0 };
    struct elf64_shdr *sh_tbl = NULL;

    unikraft_instance_t unikraft_instance = vmi->os_data;

#ifdef ENABLE_SAFETY_CHECKS
    if (!unikraft_instance) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return NULL;
    }
#endif

    if (!unikraft_instance->kernel || strlen(unikraft_instance->kernel) == 0) {
        errprint("VMI_WARNING: No unikraft kernel configured\n");
        return NULL;
    }

    f = fopen(unikraft_instance->kernel, "r");
    if (!f) {
        errprint("ERROR: Could not open kernel file: %s\n",
                 unikraft_instance->kernel);
        return NULL;
    }

    if (fread(&elf_header, sizeof(elf_header), 1, f) != 1) {
        errprint("Error reading ELF header\n");
        goto cleanup;
    }

    sh_tbl = g_try_malloc0(elf_header.e_shentsize * elf_header.e_shnum);
    if (!sh_tbl) {
        errprint("Memory allocation failed for section header table\n");
        goto cleanup;
    }

    if (read_section_header_table(f, &elf_header, sh_tbl) != VMI_SUCCESS) {
        errprint("Error reading section header table\n");
        goto cleanup;
    }

    symbol = addr2symbol_lookup(f, &elf_header, sh_tbl, address);

cleanup:
    if (sh_tbl)
        g_free(sh_tbl);
    if (f)
        fclose(f);
    return symbol;
}

status_t
unikraft_system_map_symbol_to_address(vmi_instance_t vmi,
                                      const char *symbol,
                                      addr_t *UNUSED(__unused),
                                      addr_t *address)
{
    FILE *f = NULL;
    status_t status = VMI_FAILURE;
    struct elf64_ehdr elf_header = { 0 };
    struct elf64_shdr *sh_tbl = NULL;

    unikraft_instance_t unikraft_instance = vmi->os_data;

#ifdef ENABLE_SAFETY_CHECKS
    if (!unikraft_instance) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return VMI_FAILURE;
    }
#endif

    if (!unikraft_instance->kernel || strlen(unikraft_instance->kernel) == 0) {
        errprint("VMI_WARNING: No unikraft kernel configured\n");
        return VMI_FAILURE;
    }

    f = fopen(unikraft_instance->kernel, "r");
    if (!f) {
        errprint("ERROR: Could not open kernel file: %s\n",
                 unikraft_instance->kernel);
        return VMI_FAILURE;
    }

    if (fread(&elf_header, sizeof(elf_header), 1, f) != 1) {
        errprint("Error reading ELF header\n");
        goto cleanup;
    }

    sh_tbl = g_try_malloc0(elf_header.e_shentsize * elf_header.e_shnum);
    if (!sh_tbl) {
        errprint("Memory allocation failed for section header table\n");
        goto cleanup;
    }

    if (read_section_header_table(f, &elf_header, sh_tbl) != VMI_SUCCESS) {
        errprint("Error reading section header table\n");
        goto cleanup;
    }

    status = symbol2addr_lookup(f, &elf_header, sh_tbl, symbol, address);

cleanup:
    if (sh_tbl)
        g_free(sh_tbl);
    if (f)
        fclose(f);
    return status;
}
