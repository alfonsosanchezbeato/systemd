/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <efi.h>
#include <efilib.h>
#include <libfdt.h>

#include "linux.h"
#include "linux-aarch64.h"
#include "missing_efi.h"

/* Create new fdt, either empty or with the content of old_fdt if not null */
static void *create_new_fdt(void *old_fdt, UINTN fdt_sz) {
        EFI_STATUS err;
	/* Max physical address allowed for the allocation (no limit in this case) */
        void *fdt = (void *) UINT64_MAX;
        int r;

        err = uefi_call_wrapper(BS->AllocatePages, 4,
                                AllocateMaxAddress,
                                EfiACPIReclaimMemory,
                                EFI_SIZE_TO_PAGES(fdt_sz),
                                (EFI_PHYSICAL_ADDRESS*)&fdt);
        if (EFI_ERROR(err)) {
                Print(L"Cannot allocate when creating fdt\n");
                return NULL;
        }

        if (old_fdt) {
                r = fdt_open_into(old_fdt, fdt, fdt_sz);
                if (r != 0) {
                        Print(L"Error %d when copying fdt\n", r);
                        return NULL;
                }
        } else {
                r = fdt_create_empty_tree(fdt, fdt_sz);
                if (r != 0) {
                        Print(L"Error %d when creating empty fdt\n", r);
                        return NULL;
                }
        }

        /* Set in EFI configuration table */
        err = uefi_call_wrapper(BS->InstallConfigurationTable, 2,
                                &(EFI_GUID)EFI_DTB_TABLE_GUID, fdt);
        if (EFI_ERROR(err)) {
                Print(L"Cannot set fdt in EFI configuration\n");
                return NULL;
        }

        return fdt;
}

static void *open_fdt(void) {
        EFI_STATUS err;
        void *fdt;

        /* Look for a device tree configuration table entry. */
        err = LibGetSystemConfigurationTable(&(EFI_GUID)EFI_DTB_TABLE_GUID, (VOID**)&fdt);
        if (EFI_ERROR(err)) {
                Print(L"DTB table not found, create new one\n");
                fdt = create_new_fdt(NULL, 2048);
                if (!fdt)
                        return NULL;
        }

        if (fdt_check_header(fdt) != 0) {
                Print(L"Invalid header detected on UEFI supplied FDT\n");
                return NULL;
        }

        return fdt;
}

static int update_chosen(void *fdt, UINTN initrd_addr, UINTN initrd_size) {
        uint64_t initrd_start, initrd_end;
        int r, node;

        assert(fdt);

        node = fdt_subnode_offset(fdt, 0, "chosen");
        if (node < 0) {
                node = fdt_add_subnode(fdt, 0, "chosen");
                if (node < 0) {
                        /* 'node' is an error code when negative: */
                        r = node;
                        Print(L"Error creating chosen\n");
                        return r;
                }
        }

        initrd_start = cpu_to_fdt64(initrd_addr);
        initrd_end = cpu_to_fdt64(initrd_addr + initrd_size);

        r = fdt_setprop(fdt, node, "linux,initrd-start",
                        &initrd_start, sizeof(initrd_start));
        if (r) {
                Print(L"Cannot create initrd-start property\n");
                return r;
        }

        r = fdt_setprop(fdt, node, "linux,initrd-end",
                        &initrd_end, sizeof(initrd_end));
        if (r) {
                Print(L"Cannot create initrd-end property\n");
                return r;
        }

        return 0;
}

#define FDT_EXTRA_SIZE 0x400

/* Update fdt /chosen node with initrd address and size */
static void update_fdt(UINTN initrd_addr, UINTN initrd_size) {
        void *fdt;

        assert(initrd_addr);
        assert(initrd_size > 0);

        fdt = open_fdt();
        if (fdt == NULL)
                return;

        if (update_chosen(fdt, initrd_addr, initrd_size) == -FDT_ERR_NOSPACE) {
                /* Copy to new tree and re-try */
                fdt = create_new_fdt(fdt, fdt_totalsize(fdt) + FDT_EXTRA_SIZE);
                if (!fdt)
                        return;
                update_chosen(fdt, initrd_addr, initrd_size);
        }
}

/* linux_addr is the .linux section address */
/* We don't use cmdline in aarch64 (kernel EFI stub takes it itself from the
 * EFI LoadOptions) */
#pragma GCC diagnostic ignored "-Wunused-parameter"
EFI_STATUS linux_exec(EFI_HANDLE image,
                      CHAR8 *cmdline, UINTN cmdline_len,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size) {
        struct arm64_kernel_header *hdr;
        struct arm64_linux_pe_header *pe;
        handover_f handover;

        if (initrd_size != 0)
                update_fdt(initrd_addr, initrd_size);

        hdr = (struct arm64_kernel_header *)linux_addr;

        pe = (void *)(linux_addr + hdr->hdr_offset);
        handover = (handover_f)((UINTN)linux_addr + pe->opt.entry_point_addr);

        handover(image, ST, image);

        return EFI_LOAD_ERROR;
}
