/**
 * Bareflank EL2 boot stub
 * A simple program that sets up EL2 for later use by the Bareflank hypervsior.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <k@ktemkin.com>
 *
 * <insert license here>
 */

#include <stdint.h>
#include <microlib.h>

#include <libfdt.h>
#include <cache.h>

#include "image.h"
#include "regs.h"

/**
 * Switches to EL1, and then calls main_el1.
 * Implemented in assembly in entry.S.
 */
void switch_to_el1(void * fdt);

/**
 * C entry point for execution at EL1.
 */
void main_el1(void * fdt);

/**
 * Reference to the EL2 vector table.
 * Note that the type here isn't reprsentative-- we just need the address of the label.
 */
extern uint64_t el2_vector_table;


/**
 * Print our intro message
 */
void intro(uint32_t el)
{
    printf("_______ _     _ _     _ __   _ ______  _______  ______        _______ __   _ _______\n");
    printf("   |    |_____| |     | | \\  | |     \\ |______ |_____/ |      |_____| | \\  | |______\n");
    printf("   |    |     | |_____| |  \\_| |_____/ |______ |    \\_ |_____ |     | |  \\_| |______\n");
    printf("                                         --insert pony ascii here--                 \n");
    printf("");
    printf("\n\nInitializing Bareflank stub...\n");
    printf("  current execution level:               EL%u\n", el);
    printf("  hypervisor applications supported:     %s\n", (el == 2) ? "YES" : "NO");
    printf("  mmu is:                                %s\n", (get_el2_mmu_status()) ? "ON" : "OFF");

}

/**
 * Triggered on an unrecoverable condition; prints an error message
 * and terminates execution.
 */
void panic(const char * message)
{
    printf("\n\n");
    printf("-----------------------------------------------------------------\n");
    printf("PANIC: %s\n", message);
    printf("-----------------------------------------------------------------\n");

    // TODO: This should probably induce a reboot,
    // rather than sticking here.
    while(1);
}


/**
 * Main task for loading the system's device tree.
 */
void load_device_tree(void *fdt)
{
    int rc;
    char * fdt_raw = fdt;

    printf("\nFinding device tree...\n");
    rc = ensure_image_is_accessible(fdt);

    printf("  flattened device tree resident at:     0x%p\n", fdt);
    printf("  flattened device tree magic is:        %02x%02x%02x%02x\n", fdt_raw[0], fdt_raw[1], fdt_raw[2], fdt_raw[3]);
    printf("  flattened device tree is:              %s (%d)\n", rc == SUCCESS ? "valid" : "INVALID", rc);

    if(rc != SUCCESS)
        panic("Cannot continue without a valid device tree.");

    printf("  flattened device size:                 %d bytes \n", fdt_totalsize(fdt));
}

/**
 * Relocate the Linux kernel to the start of RAM. This is necessary for the
 * Linux start-of-day code to work properly if we don't modify TEXT_OFFSET
 * during its build process.
 *
 * @param kernel The kernel to be relocated.
 * @param size_t The size of the kernel.
 */
void * relocate_kernel(const void *kernel, size_t size, void *start_of_ram)
{
    const uint64_t *kernel_raw = kernel;

    // Read the requested TEXT_OFFSET from the kernel image header. This is how
    // many bytes after the START_OF_RAM Linux expects us to load it.
    uintptr_t text_offset = (uintptr_t)kernel_raw[1];

    // Determine the load address for the Linux kernel.
    uintptr_t load_addr = (uintptr_t)start_of_ram + text_offset;

    printf("\n\nRelocating hardware domain kernel to %p...\n", load_addr);

    // Trivial relocation, as the kernel handles its internal relocations:
    // move it to the relevant memory address.
    return memmove((void *)load_addr, kernel, size);
}


/**
 * Launch an executable kernel image. Should be the last thing called by
 * Discharge, as it does not return.
 *
 * @param kernel The kernel to be executed.
 * @param fdt The device tree to be passed to the given kernel.
 */
void launch_kernel(const void *kernel, const void *fdt)
{
    const uint32_t *kernel_raw = kernel;

    // Construct a function pointer to our kernel, which will allow us to
    // jump there immediately. Note that we don't care what this leaves on
    // the stack, as either our entire stack will be ignored, or it'll
    // be torn down by the target kernel anyways.
    void (*target_kernel)(const void *fdt) = kernel;

    // Validate that we seem to have a valid kernel image, and warn if
    // we don't.
    if(kernel_raw[14] != 0x644d5241) {
        printf("! WARNING: Kernel image has invalid magic (0x%x)\n", kernel_raw);
        printf("!          Attempting to boot anyways.\n");
    }

    printf("Launching hardware domain kernel...\n");
    target_kernel(fdt);
}

/**
 * Locates an image already loaded by the previous-stage bootloader from the
 * FDT provided by that bootloader.
 *
 * @param fdt The FDT passed from the previous-stage bootloader.
 * @param path The path to look for the given image.
 *    TODO: replace this with a compatible string, and search for it
 * @param description String description of the image, for error messages.
 * @param out_location Out argument; if non-null, will be populated with the
 *    starting location of the relevant image.
 * @param out_size Out argument; if non-null, will be populated with the
 */
int find_image_verbosely(void *fdt, const char *path, const char *description,
        void ** out_kernel_location, size_t *out_kernel_size)
{
    int kernel_node, rc;

    printf("\nFinding %s image...\n", description);

    // FIXME: Currently, for this early code, we assume the module paths
    // as passed by Discharge-- but for later code, we'll want to filter
    // through all of the nodes in the FDT and search for the appropriate
    // compatible strings. See Xen's early boot for an example of how to do this.
    kernel_node = find_node(fdt, path);
    if (kernel_node < 0) {
        printf("ERROR: Could not locate the %s image! (%d)\n", description, -kernel_node);
        printf("Did the previous stage bootloader not provide it?\n");
        return -kernel_node;
    }

    // Print where we found the image description in the FDT.
    printf("  image information found at offset:     %d\n", kernel_node);

    // Read the size of the location and size of the kernel.
    rc = get_image_extents(fdt, kernel_node, "kernel", out_kernel_location, out_kernel_size);
    if(rc != SUCCESS) {
        printf("ERROR: Could not locate the %s image! (%d)", description, rc);
    }

    // Printt the arguments we're fetching.
    if(out_kernel_location) {
        printf("  image resident at:                     0x%p\n", *out_kernel_location);
    }
    if(out_kernel_size) {
        printf("  image size:                            0x%p\n", *out_kernel_size);
    }

    return SUCCESS;
}


/**
 * Core section of the Bareflank stub-- sets up the hypervisor from up in EL2.
 */
void main(void *fdt)
{
    // Read the currrent execution level...
    uint32_t el = get_current_el();

    // Print our intro text...
    intro(el);

    // ... and ensure we're in EL2.
    if (el != 2) {
        panic("The bareflank stub must be launched from EL2!");
    }

    // Set up the vector table for EL2, so that the HVC instruction can be used
    // from EL1. This allows us to return to EL2 after starting the EL1 guest.
    set_vbar_el2(&el2_vector_table);

    // TODO:
    // Insert any setup you want done in EL2, here. For now, EL2 is set up
    // to do almost nothing-- it doesn't take control of any hardware,
    // and it hasn't set up any trap-to-hypervisor features.
    //
    // If you don't trust EL1 (e.g. in an Aeries model rather than a normal
    // Bareflank model), you might want to set up second-level page translation
    // here, and isolate this memory. (You'd create a second copy of this memory
    // space for EL1 to continue executing from, and then map the EL2 version
    // into the EL2 page table and the EL1 version into the EL1 page table.
    // You'd then let the kernel reclaim the EL1 version when it starts.)
    //
    // Note that this minimal stub doesn't do anything fancy, like enable paging
    // or caching. If you plan on doing anything _serious_ here, you probably want
    // to turn those on-- for performance sake, if nothing else.

    // Once we're done with EL2 (for now), switch down to EL1. The EL1 code can
    // request a service from this EL2 stub by using the 'hvc' instruction, at
    // which point the EL2 handler in exceptions.c will be invoked.
    printf("\nSwitching to EL1...\n");
    switch_to_el1(fdt);
}

/**
 * Excludes the memory used by EL2 from the 'available memory' list to be passed
 * to the EL1 kernel. This asks it nicely not to trounce our physical memory. :)
 *
 * @param fdt The FDT to be patched.
 * @param out_start_of_ram Out argument. Retrieves the start of RAM.
 */
int exclude_el2_memory_from_fdt(void *fdt, void **out_start_of_ram)
{
    // These symbols don't actually have a meaningful type-- instead,
    // we care about the locations at which the linker /placed/ these
    // symbols, which happen to be at the start and end of our memory allocation.
    extern int lds_bfstub_start, lds_el2_bfstub_end;

    // Figure out the span of the stub's memory, including text/data/bss/el2 stack,
    // but _not_ the EL1 stack, which we expect the target kernel to reclaim.
    uintptr_t start_addr = (uintptr_t)&lds_bfstub_start;
    uintptr_t end_addr = (uintptr_t)&lds_el2_bfstub_end;

    // Patch our FDT to exclude the relevant memory address.
    return update_fdt_to_exclude_memory(fdt, start_addr, end_addr, out_start_of_ram);
}


/**
 * Secondary section of the Bareflank stub, executed once we've surrendered
 * hypervisor privileges.
 */
void main_el1(void * fdt)
{
    int rc;
    size_t kernel_size;
    void *kernel_location, *start_of_ram;

    // Read the currrent execution level...
    uint32_t el = get_current_el();

    // Validate that we're in EL1.
    printf("Now executing from EL%d!\n", el);
    if(el != 1) {
        panic("Executing with more privilege than we expect!");
    }

    // Load the device tree.
    load_device_tree(fdt);

    // Find the kernel / ramdisk / etc. in the FDT we were passed.
    rc = find_image_verbosely(fdt, "/module@0", "kernel", &kernel_location, &kernel_size);
    if (rc) {
        panic("Could not find a kernel to launch!");
    }

    // Patch the FDT's memory nodes and remove the memory we're using.
    //  (This is necessary if we're not isolating ourself from EL1, and _not_
    //   necessary if we set up second-level page translation. If we set up
    //   second-level page translation, we'd need to synthesize a new FDT
    //   memory descripton that matches the guest-physical address space.)
    rc = exclude_el2_memory_from_fdt(fdt, &start_of_ram);
    if (rc) {
        panic("Could not exclude our stub's memory from the FDT!");
    }

    // TODO:
    // - Patch the FDT to remove the nodes we're consuming (e.g. kernel location)
    //   and to pass in e.g. the ramdisk in the place where it should be.

    // Launch our next-stage (e.g. Linux) kernel.
    __invalidate_cache_region(kernel_location, kernel_size);
    kernel_location = relocate_kernel(kernel_location, kernel_size, start_of_ram);

    launch_kernel(kernel_location, fdt);

    // If we've made it here, we failed to boot, and we can't recover.
    panic("The Bareflank stub terminated without transferring control to the first domain!");

}
