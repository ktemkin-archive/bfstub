/**
 * Bareflank EL2 boot stub: tegra-specific UART code
 * This file contains all entry points (e.g. when launching or switching ELs).
 *
 * Copyright (C) Assured Information Security, Inc.
 *      Author: Kate J. Temkin <temkink@ainfosec.com>
 *
 * <insert license here>
 */

#define SERIAL_BASE 0x70006000

/*
 * Print a char in x0.
 * FIXME: Generalize so this works on most ARM boards with an 8250, and pull
 * out to another file so we can support other serial comms.
 *
 * Clobbers x0, x1, x2.
 */
.global _putc
_putc:
        ldr     x1, =SERIAL_BASE
1:      ldrb    w2, [x1, #20]
        tbz     w2, #5, 1b
        strb    w0, [x1]
        ret


