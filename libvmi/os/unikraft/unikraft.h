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
 #ifndef OS_UNIKRAFT_H_
 #define OS_UNIKRAFT_H_

 #include "private.h"

 struct unikraft_instance {
    char *kernel;                      /* kernel .dbg file path */
    addr_t thread_list_offset;         /* uk_sched_head->thread_list */
    addr_t queue_last_addr_offset;     /* uk_thread_list->tqh_last */
    addr_t thread_name_offset;         /* uk_thread->name */
    addr_t thread_next_offset;         /* uk_thread->next */
    addr_t pt_offset;                  /* uk_vas->pt */
 };

 typedef struct unikraft_instance *unikraft_instance_t;

 status_t unikraft_init(vmi_instance_t instance, GHashTable *config);

 status_t unikraft_get_offset(vmi_instance_t vmi, const char* offset_name, addr_t *offset);

 char* unikraft_system_map_address_to_symbol(vmi_instance_t vmi,
        addr_t address, const access_context_t *ctx);

status_t unikraft_system_map_symbol_to_address(vmi_instance_t vmi,
    const char *symbol,
    addr_t *__unused,
    addr_t* address);

 status_t unikraft_teardown(vmi_instance_t vmi);

 #endif /* OS_UNIKRAFT_H_ */