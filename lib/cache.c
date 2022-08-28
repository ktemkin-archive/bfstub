/**
 * Cache management helpers for Discharge
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: ktemkin <temkink@ainfosec.com>
 *
 * Portions from Coreboot:
 *      Copyright 2014 Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * Reads the CTRL_EL0 register.
 */
uint32_t raw_read_ctr_el0(void)
{
    uint32_t ctr_el0;

    __asm__ __volatile__("mrs %0, CTR_EL0\n\t" : "=r" (ctr_el0) :  : "memory");
    return ctr_el0;
}


/**
 * Returns the number of bytes per cache line.
 */
size_t __dcache_line_bytes(void)
{
    uint32_t ctr_el0;
    static unsigned int line_bytes = 0;

    if (line_bytes)
        return line_bytes;

    ctr_el0 = raw_read_ctr_el0();

    /* [19:16] - Indicates (Log2(number of words in cache line) */
    line_bytes = 1 << ((ctr_el0 >> 16) & 0xf);

    /* Bytes in a word (32-bit) */
    line_bytes *= sizeof(uint32_t);
    return line_bytes;
}

/**
 * Cleans the cache line that represents the provided address.
 */
void __invalidate_cache_line(const void * addr)
{
    asm volatile("dc civac, %0" :: "r" (addr));
}


/**
 * Invalides any cache lines that store data relevant to a given regsion.
 */
void __invalidate_cache_region(const void * addr, size_t length)
{
    size_t bytes_per_line = __dcache_line_bytes();
    const void * end_addr = addr + length;

    while(addr <= end_addr) {
        __invalidate_cache_line(addr);
        addr += bytes_per_line;
    }
}


