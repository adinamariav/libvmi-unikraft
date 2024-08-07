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

#include "config/config_parser.h"
#include "driver/driver_wrapper.h"
#include "os/unikraft/unikraft.h"
#include "private.h"

void unikraft_read_config_ghashtable_entries(char *key, gpointer value,
                                             vmi_instance_t vmi);

status_t
unikraft_init(vmi_instance_t vmi, GHashTable * config)
{
    status_t status = VMI_FAILURE;
    os_interface_t os_interface = NULL;

    if (vmi->os_data != NULL) {
        errprint("os data already initialized, reinitializing\n");
        unikraft_teardown(vmi);
    }

    vmi->os_data = g_try_malloc0(sizeof(struct unikraft_instance));
    if (!vmi->os_data) {
        errprint("Failed to allocate memory for unikraft_instance\n");
        goto _exit;
    }

    g_hash_table_foreach(config,
                         (GHFunc) unikraft_read_config_ghashtable_entries,
                         vmi);

#if defined(I386) || defined(X86_64)
    status = driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0);
    if (status != VMI_SUCCESS) {
        errprint("Failed to get vcpu register\n");
        goto _exit;
    }
#endif

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16" PRIx64 ").\n",
            vmi->kpgd);

    os_interface = g_try_malloc0(sizeof(struct os_interface));
    if (!os_interface) {
        errprint("Failed to allocate memory for os_interface\n");
        goto _exit;
    }

    os_interface->os_get_offset = unikraft_get_offset;
    os_interface->os_v2ksym = unikraft_system_map_address_to_symbol;
    os_interface->os_ksym2v = unikraft_system_map_symbol_to_address;

    vmi->os_interface = os_interface;

    return VMI_SUCCESS;

_exit:
    unikraft_teardown(vmi);
    return VMI_FAILURE;
}

void
unikraft_read_config_ghashtable_entries(char *key, gpointer value,
                                        vmi_instance_t vmi)
{
    unikraft_instance_t unikraft_instance = vmi->os_data;

    if (!key || !value) {
        errprint("VMI_ERROR: key or value point to NULL\n");
        return;
    }

    if (strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->kernel = strdup((char *) value);
        if (!unikraft_instance->kernel) {
            errprint("Failed to duplicate kernel sysmap value\n");
        }
    } else if (strncmp(key, "uk_thread_list", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->thread_list_offset = *(addr_t *) value;
    } else if (strncmp(key, "uk_thread_list_last", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->queue_last_addr_offset = *(addr_t *) value;
    } else if (strncmp(key, "uk_thread_name", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->thread_name_offset = *(addr_t *) value;
    } else if (strncmp(key, "uk_thread_next", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->thread_next_offset = *(addr_t *) value;
    } else if (strncmp(key, "uk_pt", CONFIG_STR_LENGTH) == 0) {
        unikraft_instance->pt_offset = *(addr_t *) value;
    }
}

status_t
unikraft_get_offset(vmi_instance_t vmi, const char *offset_name,
                    addr_t *offset)
{
    const size_t max_length = 100;
    unikraft_instance_t uk_instance = vmi->os_data;

    if (!uk_instance) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return VMI_FAILURE;
    }

    if (!offset_name || !offset) {
        errprint("VMI_ERROR: offset_name or offset point to NULL\n");
        return VMI_FAILURE;
    }

    if (strncmp(offset_name, "uk_thread_list", max_length) == 0) {
        *offset = uk_instance->thread_list_offset;
    } else if (strncmp(offset_name, "uk_thread_list_last", max_length) == 0) {
        *offset = uk_instance->queue_last_addr_offset;
    } else if (strncmp(offset_name, "uk_thread_name", max_length) == 0) {
        *offset = uk_instance->thread_name_offset;
    } else if (strncmp(offset_name, "uk_thread_next", max_length) == 0) {
        *offset = uk_instance->thread_next_offset;
    } else if (strncmp(offset_name, "uk_pt", max_length) == 0) {
        *offset = uk_instance->pt_offset;
    } else {
        warnprint("Invalid offset name in unikraft_get_offset (%s).\n",
                  offset_name);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

status_t
unikraft_teardown(vmi_instance_t vmi)
{
    unikraft_instance_t unikraft_instance = vmi->os_data;

    if (!unikraft_instance) {
        return VMI_SUCCESS;
    }

    if (unikraft_instance->kernel) {
        free(unikraft_instance->kernel);
    }
    g_free(unikraft_instance);

    vmi->os_data = NULL;

    return VMI_SUCCESS;
}
