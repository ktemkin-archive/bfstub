/**
 * Routines to handle "subimage" payloads.
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: ktemkin <temkink@ainfosec.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation 
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the 
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in 
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 *  DEALINGS IN THE SOFTWARE.
 */

#include <microlib.h>

#include <cache.h>
#include "image.h"


/**
 * Ensures that a valid FDT/image is accessible for the system, performing any
 * steps necessary to make the image accessible, and validating the device tree.
 *
 * @return SUCCESS, or an FDT error code.
 */
int ensure_image_is_accessible(const void *image)
{
    int rc;

    // Depthcharge loads images into memory with the cache on, and doesn't
    // flush the relevant cache lines when it switches the cache off. As a
    // result, we'll need to flush the cache lines for it before we'll be able
    // to see the FDT.

    // We start by flushing our first cache line, which we assume is large
    // enough to provide the first two fields of the FDT: an 8-byte magic number,
    // and 8-byte size.
    __invalidate_cache_line(image);

    // Validate that we have a valid-appearing device tree. All images should
    // conform to the device tree standard, as they should be either Linux
    // device trees, or FIT images.
    rc = fdt_check_header(image);
    if(rc)
        return rc;

    // If we do, invalidate the remainder of its cache lines.
    __invalidate_cache_region(image, fdt_totalsize(image));

    return SUCCESS;
}


/**
 * Converts a 32-bit devicetree location (e.g. our subimage location)
 * into a full 64-bit address.
 *
 * @param metalocation The location of the location in the device tree.
 */
void * image_location_from_devicetree(const uint64_t* metalocation)
{
    uint64_t high_word_cpu, low_word_cpu;
    uintptr_t location;

    // Break the encoded location into its FDT-constituent parts.
    uint32_t *high_word_fdt = (uint32_t *) metalocation;
    uint32_t *low_word_fdt  = ((uint32_t *)metalocation) + 1;

    // Compute the full location.
    high_word_cpu  = fdt32_to_cpu(*high_word_fdt);
    low_word_cpu   = fdt32_to_cpu(*low_word_fdt);
    location       = (high_word_cpu << 32ULL) | low_word_cpu;

    return (void *)location;
}

/**
 * Converts a 32-bit devicetree location (e.g. our subimage location)
 * into a full 64-bit address.
 */
size_t image_size_from_devicetree(const uint64_t *metasize)
{
    return (size_t)image_location_from_devicetree(metasize);
}


/**
 * Finds the chosen node in the Discharged FDT, which contains
 * e.g. the location of our final payload.
 */
int find_node(const void * image, const char * path)
{
    int node = fdt_path_offset(image, path);

    // If we weren't able to get the chosen node, return NULL.
    if (node < 0)
        printf("ERROR: Could not find path %s in subimage! (%d)", path, node);
    else
        printf("  image node found at offset:            %d\n", node);

    return node;
}

/**
 * Gets a CPU-friendly representation of a memory table entry.
 *
 * @param memory_table_entry A four-byte FDT addray in <addr_h, addr_l, size_h, size_l> format.
 * @param out_addr Out argument. Recieves the bank's start address.
 * @param outsize Out argument. Recieves the bank's size
 */
static void _from_mem_table_entry(const uint32_t *memory_table_entry, uint64_t *out_addr, uint64_t *out_size)
{
    // Get the CPU-endian representations of each memory attribute...
    uint64_t cpu_addr_high = fdt32_to_cpu(memory_table_entry[0]);
    uint64_t cpu_addr_low  = fdt32_to_cpu(memory_table_entry[1]);
    uint64_t cpu_size_high = fdt32_to_cpu(memory_table_entry[2]);
    uint64_t cpu_size_low  = fdt32_to_cpu(memory_table_entry[3]);

    // ... and combine them into the requested format.
    *out_addr = (cpu_addr_high << 32ULL) | cpu_addr_low;
    *out_size = (cpu_size_high << 32ULL) | cpu_size_low;
}

/**
 * Gets a CPU-friendly representation of a memory table entry.
 *
 * @param memory_table_entry A four-byte FDT addray in <addr_h, addr_l, size_h, size_l> format.
 * @param out_addr Out argument. Recieves the bank's start address.
 * @param outsize Out argument. Recieves the bank's size
 */
static void _to_mem_table_entry(uint32_t *memory_table_entry, uint64_t addr, uint64_t size)
{
    // Get the CPU-endian representations of each memory attribute...
    uint64_t cpu_addr_high = addr >> 32ULL;
    uint64_t cpu_addr_low  = addr & 0xFFFFFFFFULL;
    uint64_t cpu_size_high = size >> 32ULL;
    uint64_t cpu_size_low  = size & 0xFFFFFFFFULL;

    // ... and combine them into the requested format.
    memory_table_entry[0] = cpu_to_fdt32(cpu_addr_high);
    memory_table_entry[1] = cpu_to_fdt32(cpu_addr_low);
    memory_table_entry[2] = cpu_to_fdt32(cpu_size_high);
    memory_table_entry[3] = cpu_to_fdt32(cpu_size_low);
}

/**
 * Copies a given memory table entry from a source table to the target table, excluding
 * the relevant region. May produce two entries, depending on the 
 */
static size_t copy_or_split_memory_table_entries(const uint32_t *source_entry, uint32_t *target_entry,
    uintptr_t exclude_start, uintptr_t exclude_end)
{
    size_t entries_generated = 0;
    uint64_t source_entry_addr, source_entry_size, source_entry_end;


    // Interpret the source entry.
    _from_mem_table_entry(source_entry, &source_entry_addr, &source_entry_size);
    source_entry_end = source_entry_addr + source_entry_size;

    // Case 1: Do we have a region before the exlcusion region? If so, include it.
    if (source_entry_addr < exclude_start) {

        // Determine where the new entry ends.
        uint64_t new_entry_end = min(source_entry_end, exclude_start);
        uint64_t new_entry_size = new_entry_end - source_entry_addr;

        // Generate the new entry, and add it to the entry table.
        _to_mem_table_entry(&target_entry[entries_generated * 4], source_entry_addr, new_entry_size);
        ++entries_generated;
    }

    // Case 2: Do we have a region after the exlcusion region? If so, include it.
    if (source_entry_end > exclude_end) {

        // Determine where the new entry ends.
        uint64_t new_entry_start = max(source_entry_addr, exclude_end);
        uint64_t new_entry_size = source_entry_end - new_entry_start;

        // Generate the new entry, and add it to the entry table.
        _to_mem_table_entry(&target_entry[entries_generated * 4], new_entry_start, new_entry_size);
        ++entries_generated;
    }

    // Return the number of entries we've generated.
    return entries_generated;
}

/**
 * Helper function that prints out a memory table entry.
 *
 * @param memory_table A memory table, as extracted from an FDT.
 * @param entries The number of entries in the memory table.
 */
static void print_memory_table(uint32_t *memory_table, size_t entries)
{
    uint32_t *current_entry = memory_table;

    // Iterate over each entry in the table.
    while(entries--) {
        uint64_t addr, size;

        // Print the memory table entry.
        _from_mem_table_entry(current_entry, &addr, &size);

        if ((addr == 0) && (size == 0)) {
          printf("  end of table");
        } else {
          printf("  memory bank at 0x%p, size 0x%p\n", addr, size);
        }

        // Move to the next memory table entry.
        current_entry += 4;
    }
}


/**
 * Helper function that finds the start of RAM.
 *
 * @param memory_table A memory table, as extracted from an FDT.
 * @param entries The number of entries in the memory table.
 */
static void *find_start_of_ram(uint32_t *memory_table, size_t entries)
{
    uint32_t *current_entry = memory_table;
    uint64_t start_of_ram = -1ULL;

    // Iterate over each entry in the table.
    while(entries--) {
        uint64_t addr, size;

        // Parse the memory table entry...
        _from_mem_table_entry(current_entry, &addr, &size);

        // If we've hit our senitnel, abort.
        if(!addr)
            break;

        // Otherwise, update the lowest seen RAM address.
        start_of_ram = min(addr, start_of_ram);

        // Move to the next memory table entry.
        current_entry += 4;
    }

    return (void *)start_of_ram;
}


/**
 * Adjust the target FDT's memory to exclude the provided region. This allows
 * the stub to carve out memory for itself that e.g. Linux knows not to touch.
 *
 * @param fdt The FDT to be updated.
 * @param start_addr The start of the memory region to be excluded.
 * @param end_addr The end of the memory region to be excluded.
 * @param out_start_of_ram Out arugument. Will be popualted with the address of the first available RAM.
 *
 * @return SUCCESS, or an error code on failure
 */
int update_fdt_to_exclude_memory(void *fdt, uintptr_t start_addr,
    uintptr_t end_addr, void **out_start_of_ram)
{
    const struct fdt_property *source_reg;

    int memory_node, rc;
    size_t source_memory_table_entries, target_memory_table_entries = 0;

    uint32_t *source_memory_table;
    uint32_t target_memory_table[MAX_MEM_TABLE_ENTRIES * sizeof(uint32_t) *  4];

    // Find the description of the system's memory in the FDT.
    memory_node = find_node(fdt, "/memory");

    // If we weren't able to resolve the memory node, fail out.
    if(memory_node < 0) {
        printf("ERROR: Could not find a description of the system's memory (%s)!\n", fdt_strerror(memory_node));
        return memory_node;
    }

    // Retreive the property that contains the bootloader-provided memory topology.
    source_reg = fdt_get_property(fdt, memory_node, "reg", NULL);
    if(!source_reg)
    {
        printf("ERROR: Could not process the bootloader-provided memory topology!\n");
        return -FDT_ERR_BADVALUE;
    }

    // Start off assuming we're keeping the memory table the same size. If we expand it,
    // we'll update this buffer accordingly.
    source_memory_table_entries = fdt32_to_cpu(source_reg->len) / (sizeof(*source_memory_table) * 4);
    source_memory_table = (uint32_t *)source_reg->data;

    // Iterate through the memory table, which we expect to be in the format
    // <address_high address_low size_high size_low>. Technically device trees can violate
    // this by changing their cell sizes. FIXME: Support cell sizes other than 4-bytes.
    for(int i = 0; i < source_memory_table_entries; i++) {

        // If we don't have space to potentially generate two entries, fail out.
        // (Theoretically we could continue if we knew this was only going to generate one entry
        //  and we knew we had one entry left, but this implementation favors simplicity.)
        if(target_memory_table_entries + 2 > MAX_MEM_TABLE_ENTRIES) {
            printf("ERROR: Not enough space to populate the FDT with an updated memory map (need >%d entires)!\n", target_memory_table_entries + 2);
            return -FDT_ERR_NOSPACE;
        }

        // Generate the new memory table entries...
        target_memory_table_entries += copy_or_split_memory_table_entries(&source_memory_table[i * 4],
            &target_memory_table[target_memory_table_entries * 4], start_addr, end_addr);
    }

    // Print the source and destination tables.
    printf("\nOriginal memory table:\n");
    print_memory_table(source_memory_table, source_memory_table_entries);
    printf("\nUpdated memory table:\n");
    print_memory_table(target_memory_table, target_memory_table_entries);

    // Find the start of RAM.
    if(out_start_of_ram) {
        *out_start_of_ram = find_start_of_ram(target_memory_table, target_memory_table_entries);
    }

    // Copy the memory topology over to the target FDT. For now, we assume the cell sizes
    // (address and size) match the target, as discharge does.
    rc = fdt_setprop(fdt, memory_node, "reg", target_memory_table, target_memory_table_entries * sizeof(*target_memory_table));
    if (rc) {
        printf("ERROR: Could not update the FDT memory table! (%d)\n", rc);
        return -rc;
    }

    return SUCCESS;
}



/**
 * Finds the extents (start, length) of a given image, as passed from our
 * bootloader via the FDT.
 *
 * @param fdt The FDT passed from the previous-stage bootloader.
 * @param image_node The bootloader node corresponding to the relevant image.
 * @param description String description of the image, for error messages.
 * @param out_location Out argument; if non-null, will be populated with the
 *    starting location of the relevant image.
 * @param out_size Out argument; if non-null, will be populated with the
 */
int get_image_extents(const void *fdt, int image_node,
    const char *description, void **out_location, size_t *out_size)
{
    int subimage_location_size;

    // Unfortunately, image locations received in the FDT are stored as 32-bit
    // integers for backwards compatibility. We'll have to expand this out
    // to a full 64-bit image ourselves.
    const uint64_t *subimage_location;

    // Find the location of the initrd property, which holds our subimage...
    subimage_location = fdt_getprop(fdt, image_node, "reg", &subimage_location_size);
    if(subimage_location_size <= 0) {
        printf("ERROR: Could not find the %s image location! (%d)\n", description, subimage_location);
        return -subimage_location_size;
    }

    // Populate our extents, if we have a valid pointer to populate them into.
    if (out_location) {
        *out_location = image_location_from_devicetree(subimage_location);
    }
    if (out_size) {
        *out_size = image_size_from_devicetree(&subimage_location[1]);
    }


    return SUCCESS;
}

