/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
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
#include <string.h>

#define PAGE_LEVEL 0
#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000UL
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define PT_LEVELS 4

#define X86_PT_LEVEL_SHIFT 9
#define X86_PT_PTES_PER_LEVEL (1UL << X86_PT_LEVEL_SHIFT)

#define X86_PTE_PADDR_BITS 52
#define X86_PTE_PADDR_MASK ((1UL << X86_PTE_PADDR_BITS) - 1)

#define X86_PT_L0_SHIFT 12
#define X86_PT_Lx_SHIFT(lvl) (X86_PT_L0_SHIFT + (X86_PT_LEVEL_SHIFT * (lvl)))
#define X86_PT_SHIFT_Lx(shift) (((shift)-X86_PT_L0_SHIFT) / X86_PT_LEVEL_SHIFT)

#define PT_Lx_IDX(vaddr, lvl)                                                  \
  (((vaddr) >> X86_PT_Lx_SHIFT(lvl)) & (X86_PT_PTES_PER_LEVEL - 1))

#define PT_Lx_PTES(lvl) X86_PT_PTES_PER_LEVEL

#define PAGE_Lx_SHIFT(lvl) X86_PT_Lx_SHIFT(lvl)
#define PAGE_SHIFT_Lx(shift) X86_PT_SHIFT_Lx(shift)

#define X86_PTE_PRESENT 0x001UL
#define X86_PTE_RW 0x002UL
#define X86_PTE_US 0x004UL
#define X86_PTE_PWT 0x008UL
#define X86_PTE_PCD 0x010UL
#define X86_PTE_ACCESSED 0x020UL
#define X86_PTE_DIRTY 0x040UL
#define X86_PTE_PAT(lvl) ((lvl) > PAGE_LEVEL ? 0x1000 : 0x80)
#define X86_PTE_PSE 0x080UL
#define X86_PTE_GLOBAL 0x100UL
#define X86_PTE_USER1_MASK 0xE00UL
#define X86_PTE_USER2_MASK (0x7FUL << 52)
#define X86_PTE_MPK_MASK (0xFUL << 59)
#define X86_PTE_NX (1UL << 63)

#define PAGE_Lx_IS(pte, lvl) (((lvl) == PAGE_LEVEL) || ((pte)&X86_PTE_PSE))

#define PT_Lx_PTE_PRESENT(pte, lvl) ((pte)&X86_PTE_PRESENT)
#define PT_Lx_PTE_CLEAR_PRESENT(pte, lvl) ((pte) & ~X86_PTE_PRESENT)

#define PT_Lx_PTE_PADDR(pte) (((__paddr_t)(pte)&X86_PTE_PADDR_MASK) & PAGE_MASK)

#define PT_Lx_PTE_SET_PADDR(pte, lvl, paddr)                                   \
  (((pte) & ~(X86_PTE_PADDR_MASK & PAGE_MASK)) |                               \
   (__pte_t)((paddr)&X86_PTE_PADDR_MASK))

#define PT_Lx_PTE_INVALID(lvl) 0x0UL

#define DIRECTMAP_AREA_START 0xffffff8000000000
#define DIRECTMAP_AREA_END 0xffffffffffffffff
#define DIRECTMAP_AREA_OFFSET 0x0000000fffffffff
#define DIRECTMAP_AREA_SIZE (DIRECTMAP_AREA_END - DIRECTMAP_AREA_START + 1)

#define X86_PT_L0_SHIFT 12
#define X86_PT_LEVEL_SHIFT 9

#define X86_PT_Lx_SHIFT(lvl) (X86_PT_L0_SHIFT + (X86_PT_LEVEL_SHIFT * (lvl)))

#define PAGE_Lx_SHIFT(lvl) X86_PT_Lx_SHIFT(lvl)
#define PAGE_Lx_SIZE(lvl) (1UL << PAGE_Lx_SHIFT(lvl))

#define ALIGN_DOWN(v, a) ((v) & ~((a)-1))
#define PAGE_Lx_ALIGN_DOWN(addr, lvl) ALIGN_DOWN(addr, PAGE_Lx_SIZE(lvl))
#define PAGE_ALIGN_DOWN(addr) PAGE_Lx_ALIGN_DOWN(addr, PAGE_LEVEL)

typedef unsigned long __u64;
typedef __u64 __paddr_t;
typedef __u64 __uptr;
typedef __uptr __vaddr_t;
typedef __u64 __pte_t;

struct uk_falloc;
struct ukarch_pagetable {
    /* nothing */
};

struct uk_pagetable {
    __vaddr_t pt_vbase;
    __paddr_t pt_pbase;

    struct uk_falloc *fa;
    struct ukarch_pagetable arch;
};

__vaddr_t
x86_directmap_paddr_to_vaddr(__paddr_t paddr)
{
    return (__vaddr_t) paddr + DIRECTMAP_AREA_START;
}

static inline __vaddr_t
pgarch_pt_pte_to_vaddr(__pte_t pte)
{
    return x86_directmap_paddr_to_vaddr(PT_Lx_PTE_PADDR(pte));
}

int
ukarch_pte_read(vmi_instance_t vmi, __vaddr_t pt_vaddr, unsigned int lvl,
                unsigned int idx, __pte_t * pte)
{
    (void) lvl;
    uint64_t value;

    __pte_t *pte_ptr = (__pte_t *) pt_vaddr + idx;

    unsigned long long pte_val = (unsigned long long) pte_ptr;
    pte_val &= DIRECTMAP_AREA_OFFSET;

    vmi_read_64_pa(vmi, pte_val, &value);
    *pte = value;

    return 0;
}

int
pg_pt_walk(vmi_instance_t vmi, __vaddr_t * pt_vaddr, __vaddr_t vaddr,
           unsigned int *level, unsigned int to_level, __pte_t * pte)
{
    unsigned int lvl = *level;
    __pte_t lpte;
    int rc;

    while (lvl > to_level) {
        rc = ukarch_pte_read(vmi, *pt_vaddr, lvl, PT_Lx_IDX(vaddr, lvl),
                             &lpte);

        *pt_vaddr = pgarch_pt_pte_to_vaddr(lpte);
        lvl--;
    }

    rc = ukarch_pte_read(vmi, *pt_vaddr, lvl, PT_Lx_IDX(vaddr, to_level),
                         &lpte);

    *level = lvl;
    *pte = lpte;

    return rc;
}

int
ukplat_pt_walk(vmi_instance_t vmi, struct uk_pagetable *pt, __vaddr_t vaddr,
               unsigned int *level, __vaddr_t * pt_vaddr, __pte_t * pte)
{
    unsigned int lvl = PT_LEVELS - 1;
    unsigned int to_lvl = (level) ? *level : PAGE_LEVEL;
    __vaddr_t tmp_pt_vaddr = pt->pt_vbase;
    __pte_t tmp_pte;
    int rc;

    rc = pg_pt_walk(vmi, &tmp_pt_vaddr, vaddr, &lvl, to_lvl, &tmp_pte);

    if (pt_vaddr)
        *pt_vaddr = tmp_pt_vaddr;
    if (level)
        *level = lvl;
    if (pte)
        *pte = tmp_pte;

    return rc;
}

status_t
unikraft_virt_to_phys(vmi_instance_t vmi, addr_t va, addr_t *pa)
{
    addr_t uk_pt_offset;
    struct uk_pagetable pt;

    vmi_get_offset(vmi, "uk_pt", &uk_pt_offset);

    addr_t active_vas;
    vmi_translate_ksym2v(vmi, "vmem_active_vas", &active_vas);

    addr_t uk_vas_addr;
    vmi_read_addr_pa(vmi, active_vas, &uk_vas_addr);

    addr_t uk_pt_addr;
    vmi_read_addr_pa(vmi, uk_vas_addr + uk_pt_offset, &uk_pt_addr);

    vmi_read_addr_pa(vmi, uk_pt_addr, &pt.pt_vbase);
    vmi_read_addr_pa(vmi, uk_pt_addr + sizeof(addr_t), &pt.pt_pbase);

    __vaddr_t vaddr = (__vaddr_t) va;
    __pte_t pte;
    unsigned int level = PAGE_LEVEL;
    unsigned long offset;

    ukplat_pt_walk(vmi, &pt, PAGE_ALIGN_DOWN(vaddr), &level, 0, &pte);
    offset = vaddr - PAGE_Lx_ALIGN_DOWN(vaddr, level);

    *pa = PT_Lx_PTE_PADDR(pte) + offset;

    return VMI_SUCCESS;
}
