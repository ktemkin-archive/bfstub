/**
 * Microlib:
 * simple support library providing simple stdlib equivalents for
 * discharge
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

/**
 * Quick (and not particularly performant) implementation of the standard
 * library's memcpy.
 */
void * memcpy(void * dest, const void * src, size_t n)
{
    const char * src_byte = src;
    char * dest_byte = dest;

    size_t i = 0;

    for(i = 0; i < n; ++i)
        dest_byte[i] = src_byte[i];

    return dest;
}

#ifndef __RUNNING_ON_OS__

/**
 * Prints a single character (synchronously) via serial.
 *
 * @param c The character to be printed
 */
void putc(char c, void *stream)
{
    // If we're about to send a newline, prefix it with a carriage return.
    // This makes our putc behave like a normal console putc.
    if(c == '\n')
        putc('\r', stream);

    asm volatile(
          "mov x0, %0\n\t"
          "bl  _putc\n\t"
          :: "r" (c) : "x0", "x1", "x2", "x30"
    );
}

#endif

/**
 * Prints a string (synchronously) via serial.
 *
 * @param s The string to be printed; must be null terminated.
 */
extern int puts(const char * s)
{
    while(*s) {
        putc(*s, stdin);
        ++s;
    }

    return 0;
}


/**
 * Determines the length of a string, scanning at most max characters.
 */
size_t strnlen(const char *s, size_t max)
{
    size_t n = 0;

    while(*s) {
        ++n;
        ++s;

        if(n == max)
            return n;
    }

    return n;
}


/**
 * Determines the length of a string.
 */
size_t strlen(const char *s)
{
    return strnlen(s, SIZE_MAX);
}

/**
 * Determines if two memory regiohns are equal, and returns the difference if they are not.
 */
int memcmp(const void *s1, const void *s2, size_t n)
{
    int i;

    const char * c1 = s1;
    const char * c2 = s2;

    for(i = 0; i < n; ++i)
        if(c1[i] != c2[i])
            return c1[i] - c2[i];

    return 0;
}

/**
 * Returns a pointer to the first instance of character 'c' in the given block of memory.
 */
void * memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    int i;

    for(i = 0; i < n; ++i)
        if(p[i] == (unsigned char)c)
            return (void *)&(p[i]);

    return 0;
}

/**
 * Fills a given block with a byte value.
 */
void * memset(void *b, int c, size_t len)
{
    unsigned char *p = b;
    int i;

    for(i = 0; i < len; ++i)
        p[i] = c;

    return b;
}


#ifndef __RUNNING_ON_OS__

/**
 * Clear out the system's bss.
 */
void _clear_bss(void)
{
    // These symbols don't actually have a meaningful type-- instead,
    // we care about the locations at which the linker /placed/ these
    // symbols, which happen to be at the start and end of the BSS.
    extern int lds_bss_start, lds_bss_end;

    memset(&lds_bss_start, 0, &lds_bss_end - &lds_bss_start);
}

#endif
