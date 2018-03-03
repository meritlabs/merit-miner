/*
 * Copyright 2012 pooler@litecoinpool.org
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"

#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)









	.text
	.code 32
	.align 2
	.globl sha256_transform
	.globl _sha256_transform
#ifdef __ELF__
	.type sha256_transform, %function
#endif
sha256_transform:
_sha256_transform:
	stmfd	sp!, {r4-r11, lr}
	cmp	r2, #0
	sub	sp, sp, #64*4
	bne	sha256_transform_swap
	
	ldmia	r1!, {r4-r11}
	stmia	sp, {r4-r11}
	add	r3, sp, #8*4
	ldmia	r1, {r4-r11}
	stmia	r3, {r4-r11}
	b	sha256_transform_extend


sha256_transform_swap:
	ldmia	r1!, {r4-r11}
	eor	r12, r4, r4, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r4, r4, ror #8
	eor	r4, r4, r12, lsr #8
	eor	r12, r5, r5, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r5, r5, ror #8
	eor	r5, r5, r12, lsr #8
	eor	r12, r6, r6, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r6, r6, ror #8
	eor	r6, r6, r12, lsr #8
	eor	r12, r7, r7, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r7, r7, ror #8
	eor	r7, r7, r12, lsr #8
	eor	r12, r8, r8, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r8, r8, ror #8
	eor	r8, r8, r12, lsr #8
	eor	r12, r9, r9, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r9, r9, ror #8
	eor	r9, r9, r12, lsr #8
	eor	r12, r10, r10, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r10, r10, ror #8
	eor	r10, r10, r12, lsr #8
	eor	r12, r11, r11, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r11, r11, ror #8
	eor	r11, r11, r12, lsr #8
	stmia	sp, {r4-r11}
	add	r3, sp, #8*4
	ldmia	r1, {r4-r11}
	eor	r12, r4, r4, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r4, r4, ror #8
	eor	r4, r4, r12, lsr #8
	eor	r12, r5, r5, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r5, r5, ror #8
	eor	r5, r5, r12, lsr #8
	eor	r12, r6, r6, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r6, r6, ror #8
	eor	r6, r6, r12, lsr #8
	eor	r12, r7, r7, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r7, r7, ror #8
	eor	r7, r7, r12, lsr #8
	eor	r12, r8, r8, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r8, r8, ror #8
	eor	r8, r8, r12, lsr #8
	eor	r12, r9, r9, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r9, r9, ror #8
	eor	r9, r9, r12, lsr #8
	eor	r12, r10, r10, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r10, r10, ror #8
	eor	r10, r10, r12, lsr #8
	eor	r12, r11, r11, ror #16
	bic	r12, r12, #0x00ff0000
	mov	r11, r11, ror #8
	eor	r11, r11, r12, lsr #8
	stmia	r3, {r4-r11}
	
sha256_transform_extend:
	add	r12, sp, #9*4
	ldr	r11, [sp, #0*4]
	ldmia	r12, {r4-r10}
	ldr	lr, [sp, #(0+1)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(0+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [sp, #(0+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [sp, #(0+3)*4]
	str	r5, [sp, #(2+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(2+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [sp, #(2+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [sp, #(2+3)*4]
	str	r7, [sp, #(4+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(4+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [sp, #(4+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	ldr	lr, [sp, #(4+3)*4]
	str	r9, [sp, #(6+15)*4]
	mov	r12, r8, ror #17
	add	r11, r11, r10
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(6+2)*4]
	eor	r10, r10, lr, lsr #3
	add	r10, r10, r12

	mov	r12, r9, ror #17
	str	r10, [sp, #(6+16)*4]
	add	lr, lr, r4
	eor	r12, r12, r9, ror #19
	mov	r4, r11, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, r11, ror #18
	add	lr, lr, r12
	eor	r4, r4, r11, lsr #3
	add	r4, r4, lr
	ldr	lr, [sp, #(6+3)*4]
	str	r4, [sp, #(8+15)*4]
	mov	r12, r10, ror #17
	add	r11, r11, r5
	eor	r12, r12, r10, ror #19
	mov	r5, lr, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(8+2)*4]
	eor	r5, r5, lr, lsr #3
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [sp, #(8+16)*4]
	add	lr, lr, r6
	eor	r12, r12, r4, ror #19
	mov	r6, r11, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, r11, ror #18
	add	lr, lr, r12
	eor	r6, r6, r11, lsr #3
	add	r6, r6, lr
	ldr	lr, [sp, #(8+3)*4]
	str	r6, [sp, #(10+15)*4]
	mov	r12, r5, ror #17
	add	r11, r11, r7
	eor	r12, r12, r5, ror #19
	mov	r7, lr, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(10+2)*4]
	eor	r7, r7, lr, lsr #3
	add	r7, r7, r12

	mov	r12, r6, ror #17
	str	r7, [sp, #(10+16)*4]
	add	lr, lr, r8
	eor	r12, r12, r6, ror #19
	mov	r8, r11, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, r11, ror #18
	add	lr, lr, r12
	eor	r8, r8, r11, lsr #3
	add	r8, r8, lr
	ldr	lr, [sp, #(10+3)*4]
	str	r8, [sp, #(12+15)*4]
	mov	r12, r7, ror #17
	add	r11, r11, r9
	eor	r12, r12, r7, ror #19
	mov	r9, lr, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(12+2)*4]
	eor	r9, r9, lr, lsr #3
	add	r9, r9, r12

	mov	r12, r8, ror #17
	str	r9, [sp, #(12+16)*4]
	add	lr, lr, r10
	eor	r12, r12, r8, ror #19
	mov	r10, r11, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, r11, ror #18
	add	lr, lr, r12
	eor	r10, r10, r11, lsr #3
	add	r10, r10, lr
	ldr	lr, [sp, #(12+3)*4]
	str	r10, [sp, #(14+15)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(14+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [sp, #(14+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [sp, #(14+3)*4]
	str	r5, [sp, #(16+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(16+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [sp, #(16+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [sp, #(16+3)*4]
	str	r7, [sp, #(18+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(18+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [sp, #(18+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	ldr	lr, [sp, #(18+3)*4]
	str	r9, [sp, #(20+15)*4]
	mov	r12, r8, ror #17
	add	r11, r11, r10
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(20+2)*4]
	eor	r10, r10, lr, lsr #3
	add	r10, r10, r12

	mov	r12, r9, ror #17
	str	r10, [sp, #(20+16)*4]
	add	lr, lr, r4
	eor	r12, r12, r9, ror #19
	mov	r4, r11, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, r11, ror #18
	add	lr, lr, r12
	eor	r4, r4, r11, lsr #3
	add	r4, r4, lr
	ldr	lr, [sp, #(20+3)*4]
	str	r4, [sp, #(22+15)*4]
	mov	r12, r10, ror #17
	add	r11, r11, r5
	eor	r12, r12, r10, ror #19
	mov	r5, lr, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(22+2)*4]
	eor	r5, r5, lr, lsr #3
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [sp, #(22+16)*4]
	add	lr, lr, r6
	eor	r12, r12, r4, ror #19
	mov	r6, r11, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, r11, ror #18
	add	lr, lr, r12
	eor	r6, r6, r11, lsr #3
	add	r6, r6, lr
	ldr	lr, [sp, #(22+3)*4]
	str	r6, [sp, #(24+15)*4]
	mov	r12, r5, ror #17
	add	r11, r11, r7
	eor	r12, r12, r5, ror #19
	mov	r7, lr, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(24+2)*4]
	eor	r7, r7, lr, lsr #3
	add	r7, r7, r12

	mov	r12, r6, ror #17
	str	r7, [sp, #(24+16)*4]
	add	lr, lr, r8
	eor	r12, r12, r6, ror #19
	mov	r8, r11, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, r11, ror #18
	add	lr, lr, r12
	eor	r8, r8, r11, lsr #3
	add	r8, r8, lr
	ldr	lr, [sp, #(24+3)*4]
	str	r8, [sp, #(26+15)*4]
	mov	r12, r7, ror #17
	add	r11, r11, r9
	eor	r12, r12, r7, ror #19
	mov	r9, lr, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(26+2)*4]
	eor	r9, r9, lr, lsr #3
	add	r9, r9, r12

	mov	r12, r8, ror #17
	str	r9, [sp, #(26+16)*4]
	add	lr, lr, r10
	eor	r12, r12, r8, ror #19
	mov	r10, r11, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, r11, ror #18
	add	lr, lr, r12
	eor	r10, r10, r11, lsr #3
	add	r10, r10, lr
	ldr	lr, [sp, #(26+3)*4]
	str	r10, [sp, #(28+15)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(28+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [sp, #(28+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [sp, #(28+3)*4]
	str	r5, [sp, #(30+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(30+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [sp, #(30+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [sp, #(30+3)*4]
	str	r7, [sp, #(32+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(32+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [sp, #(32+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	ldr	lr, [sp, #(32+3)*4]
	str	r9, [sp, #(34+15)*4]
	mov	r12, r8, ror #17
	add	r11, r11, r10
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(34+2)*4]
	eor	r10, r10, lr, lsr #3
	add	r10, r10, r12

	mov	r12, r9, ror #17
	str	r10, [sp, #(34+16)*4]
	add	lr, lr, r4
	eor	r12, r12, r9, ror #19
	mov	r4, r11, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, r11, ror #18
	add	lr, lr, r12
	eor	r4, r4, r11, lsr #3
	add	r4, r4, lr
	ldr	lr, [sp, #(34+3)*4]
	str	r4, [sp, #(36+15)*4]
	mov	r12, r10, ror #17
	add	r11, r11, r5
	eor	r12, r12, r10, ror #19
	mov	r5, lr, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(36+2)*4]
	eor	r5, r5, lr, lsr #3
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [sp, #(36+16)*4]
	add	lr, lr, r6
	eor	r12, r12, r4, ror #19
	mov	r6, r11, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, r11, ror #18
	add	lr, lr, r12
	eor	r6, r6, r11, lsr #3
	add	r6, r6, lr
	ldr	lr, [sp, #(36+3)*4]
	str	r6, [sp, #(38+15)*4]
	mov	r12, r5, ror #17
	add	r11, r11, r7
	eor	r12, r12, r5, ror #19
	mov	r7, lr, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(38+2)*4]
	eor	r7, r7, lr, lsr #3
	add	r7, r7, r12

	mov	r12, r6, ror #17
	str	r7, [sp, #(38+16)*4]
	add	lr, lr, r8
	eor	r12, r12, r6, ror #19
	mov	r8, r11, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, r11, ror #18
	add	lr, lr, r12
	eor	r8, r8, r11, lsr #3
	add	r8, r8, lr
	ldr	lr, [sp, #(38+3)*4]
	str	r8, [sp, #(40+15)*4]
	mov	r12, r7, ror #17
	add	r11, r11, r9
	eor	r12, r12, r7, ror #19
	mov	r9, lr, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(40+2)*4]
	eor	r9, r9, lr, lsr #3
	add	r9, r9, r12

	mov	r12, r8, ror #17
	str	r9, [sp, #(40+16)*4]
	add	lr, lr, r10
	eor	r12, r12, r8, ror #19
	mov	r10, r11, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, r11, ror #18
	add	lr, lr, r12
	eor	r10, r10, r11, lsr #3
	add	r10, r10, lr
	ldr	lr, [sp, #(40+3)*4]
	str	r10, [sp, #(42+15)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(42+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [sp, #(42+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [sp, #(42+3)*4]
	str	r5, [sp, #(44+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(44+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [sp, #(44+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [sp, #(44+3)*4]
	str	r7, [sp, #(46+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [sp, #(46+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [sp, #(46+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	str	r9, [sp, #(46+17)*4]
	
	ldmia	r0, {r4-r11}
	ldr	r12, [sp, #(0+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (0+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(0+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (0+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(0+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (0+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(0+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (0+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(4+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (4+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(4+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (4+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(4+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (4+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(4+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (4+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(8+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (8+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(8+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (8+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(8+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (8+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(8+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (8+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(12+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (12+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(12+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (12+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(12+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (12+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(12+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (12+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(16+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (16+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(16+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (16+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(16+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (16+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(16+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (16+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(20+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (20+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(20+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (20+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(20+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (20+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(20+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (20+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(24+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (24+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(24+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (24+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(24+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (24+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(24+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (24+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(28+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (28+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(28+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (28+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(28+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (28+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(28+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (28+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	b	sha256_transform_k_over
sha256_transform_k:
	.align 2
	.long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	.long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	.long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	.long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
sha256_transform_k_over:
	ldr	r12, [sp, #(32+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (32+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(32+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (32+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(32+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (32+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(32+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (32+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(36+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (36+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(36+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (36+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(36+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (36+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(36+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (36+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(40+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (40+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(40+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (40+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(40+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (40+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(40+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (40+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(44+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (44+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(44+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (44+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(44+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (44+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(44+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (44+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(48+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (48+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(48+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (48+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(48+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (48+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(48+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (48+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(52+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (52+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(52+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (52+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(52+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (52+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(52+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (52+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(56+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (56+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(56+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (56+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(56+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (56+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(56+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (56+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [sp, #(60+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (60+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [sp, #(60+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (60+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [sp, #(60+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (60+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [sp, #(60+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256_transform_k + (60+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	
	ldmia	r0, {r1, r2, r3, r12}
	add	r4, r4, r1
	add	r5, r5, r2
	add	r6, r6, r3
	add	r7, r7, r12
	stmia	r0!, {r4-r7}
	ldmia	r0, {r1, r2, r3, r12}
	add	r8, r8, r1
	add	r9, r9, r2
	add	r10, r10, r3
	add	r11, r11, r12
	stmia	r0, {r8-r11}
	
	add	sp, sp, #64*4
#ifdef __thumb__
	ldmfd	sp!, {r4-r11, lr}
	bx	lr
#else
	ldmfd	sp!, {r4-r11, pc}
#endif


	.text
	.code 32
	.align 2
	.globl sha256d_ms
	.globl _sha256d_ms
#ifdef __ELF__
	.type sha256d_ms, %function
#endif
sha256d_ms:
_sha256d_ms:
	stmfd	sp!, {r4-r11, lr}
	sub	sp, sp, #64*4
	
	cmp	r0, r0
	
	ldr	lr, [r1, #3*4]
	ldr	r6, [r1, #18*4]
	ldr	r7, [r1, #19*4]
	
	mov	r12, lr, ror #7
	str	r6, [sp, #18*4]
	eor	r12, r12, lr, ror #18
	str	r7, [sp, #19*4]
	eor	r12, r12, lr, lsr #3
	ldr	r8, [r1, #20*4]
	add	r6, r6, r12
	ldr	r10, [r1, #22*4]
	add	r7, r7, lr
	str	r6, [r1, #18*4]
	
	mov	r12, r6, ror #17
	str	r7, [r1, #19*4]
	eor	r12, r12, r6, ror #19
	str	r8, [sp, #20*4]
	eor	r12, r12, r6, lsr #10
	ldr	r4, [r1, #23*4]
	add	r8, r8, r12
	ldr	r5, [r1, #24*4]
	
	mov	r9, r7, ror #17
	str	r8, [r1, #20*4]
	eor	r9, r9, r7, ror #19
	str	r10, [sp, #21*4]
	eor	r9, r9, r7, lsr #10
	str	r4, [sp, #22*4]
	
	mov	r12, r8, ror #17
	str	r9, [r1, #21*4]
	eor	r12, r12, r8, ror #19
	str	r5, [sp, #23*4]
	eor	r12, r12, r8, lsr #10
	mov	lr, r9, ror #17
	add	r10, r10, r12
	ldr	r11, [r1, #30*4]
	
	eor	lr, lr, r9, ror #19
	str	r10, [r1, #22*4]
	eor	lr, lr, r9, lsr #10
	str	r11, [sp, #24*4]
	add	r4, r4, lr
	
	mov	r12, r10, ror #17
	str	r4, [r1, #23*4]
	eor	r12, r12, r10, ror #19
	mov	lr, r4, ror #17
	eor	r12, r12, r10, lsr #10
	eor	lr, lr, r4, ror #19
	add	r5, r5, r12
	eor	lr, lr, r4, lsr #10
	str	r5, [r1, #24*4]
	add	r6, r6, lr
	
	mov	r12, r5, ror #17
	str	r6, [r1, #25*4]
	eor	r12, r12, r5, ror #19
	mov	lr, r6, ror #17
	eor	r12, r12, r5, lsr #10
	eor	lr, lr, r6, ror #19
	add	r7, r7, r12
	eor	lr, lr, r6, lsr #10
	str	r7, [r1, #26*4]
	add	r8, r8, lr
	
	mov	r12, r7, ror #17
	str	r8, [r1, #27*4]
	eor	r12, r12, r7, ror #19
	mov	lr, r8, ror #17
	eor	r12, r12, r7, lsr #10
	eor	lr, lr, r8, ror #19
	add	r9, r9, r12
	eor	lr, lr, r8, lsr #10
	str	r9, [r1, #28*4]
	add	r10, r10, lr
	
	ldr	lr, [r1, #31*4]
	mov	r12, r9, ror #17
	str	r10, [r1, #29*4]
	eor	r12, r12, r9, ror #19
	str	lr, [sp, #25*4]
	eor	r12, r12, r9, lsr #10
	add	r11, r11, r12
	add	r5, r5, lr
	mov	r12, r10, ror #17
	add	r4, r4, r11
	
	ldr	r11, [r1, #16*4]
	eor	r12, r12, r10, ror #19
	str	r4, [r1, #30*4]
	eor	r12, r12, r10, lsr #10
	add	r5, r5, r12
	ldr	lr, [r1, #17*4]
	
sha256d_ms_extend_loop2:
	str	r5, [r1, #(16+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(16+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [r1, #(16+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [r1, #(16+3)*4]
	str	r7, [r1, #(18+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(18+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [r1, #(18+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	ldr	lr, [r1, #(18+3)*4]
	str	r9, [r1, #(20+15)*4]
	mov	r12, r8, ror #17
	add	r11, r11, r10
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(20+2)*4]
	eor	r10, r10, lr, lsr #3
	add	r10, r10, r12

	mov	r12, r9, ror #17
	str	r10, [r1, #(20+16)*4]
	add	lr, lr, r4
	eor	r12, r12, r9, ror #19
	mov	r4, r11, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, r11, ror #18
	add	lr, lr, r12
	eor	r4, r4, r11, lsr #3
	add	r4, r4, lr
	ldr	lr, [r1, #(20+3)*4]
	str	r4, [r1, #(22+15)*4]
	mov	r12, r10, ror #17
	add	r11, r11, r5
	eor	r12, r12, r10, ror #19
	mov	r5, lr, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(22+2)*4]
	eor	r5, r5, lr, lsr #3
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [r1, #(22+16)*4]
	add	lr, lr, r6
	eor	r12, r12, r4, ror #19
	mov	r6, r11, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, r11, ror #18
	add	lr, lr, r12
	eor	r6, r6, r11, lsr #3
	add	r6, r6, lr
	ldr	lr, [r1, #(22+3)*4]
	str	r6, [r1, #(24+15)*4]
	mov	r12, r5, ror #17
	add	r11, r11, r7
	eor	r12, r12, r5, ror #19
	mov	r7, lr, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(24+2)*4]
	eor	r7, r7, lr, lsr #3
	add	r7, r7, r12

	mov	r12, r6, ror #17
	str	r7, [r1, #(24+16)*4]
	add	lr, lr, r8
	eor	r12, r12, r6, ror #19
	mov	r8, r11, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, r11, ror #18
	add	lr, lr, r12
	eor	r8, r8, r11, lsr #3
	add	r8, r8, lr
	ldr	lr, [r1, #(24+3)*4]
	str	r8, [r1, #(26+15)*4]
	mov	r12, r7, ror #17
	add	r11, r11, r9
	eor	r12, r12, r7, ror #19
	mov	r9, lr, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(26+2)*4]
	eor	r9, r9, lr, lsr #3
	add	r9, r9, r12

	mov	r12, r8, ror #17
	str	r9, [r1, #(26+16)*4]
	add	lr, lr, r10
	eor	r12, r12, r8, ror #19
	mov	r10, r11, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, r11, ror #18
	add	lr, lr, r12
	eor	r10, r10, r11, lsr #3
	add	r10, r10, lr
	ldr	lr, [r1, #(26+3)*4]
	str	r10, [r1, #(28+15)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(28+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [r1, #(28+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [r1, #(28+3)*4]
	str	r5, [r1, #(30+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(30+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [r1, #(30+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [r1, #(30+3)*4]
	str	r7, [r1, #(32+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(32+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [r1, #(32+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	ldr	lr, [r1, #(32+3)*4]
	str	r9, [r1, #(34+15)*4]
	mov	r12, r8, ror #17
	add	r11, r11, r10
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(34+2)*4]
	eor	r10, r10, lr, lsr #3
	add	r10, r10, r12

	mov	r12, r9, ror #17
	str	r10, [r1, #(34+16)*4]
	add	lr, lr, r4
	eor	r12, r12, r9, ror #19
	mov	r4, r11, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, r11, ror #18
	add	lr, lr, r12
	eor	r4, r4, r11, lsr #3
	add	r4, r4, lr
	ldr	lr, [r1, #(34+3)*4]
	str	r4, [r1, #(36+15)*4]
	mov	r12, r10, ror #17
	add	r11, r11, r5
	eor	r12, r12, r10, ror #19
	mov	r5, lr, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(36+2)*4]
	eor	r5, r5, lr, lsr #3
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [r1, #(36+16)*4]
	add	lr, lr, r6
	eor	r12, r12, r4, ror #19
	mov	r6, r11, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, r11, ror #18
	add	lr, lr, r12
	eor	r6, r6, r11, lsr #3
	add	r6, r6, lr
	ldr	lr, [r1, #(36+3)*4]
	str	r6, [r1, #(38+15)*4]
	mov	r12, r5, ror #17
	add	r11, r11, r7
	eor	r12, r12, r5, ror #19
	mov	r7, lr, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(38+2)*4]
	eor	r7, r7, lr, lsr #3
	add	r7, r7, r12

	mov	r12, r6, ror #17
	str	r7, [r1, #(38+16)*4]
	add	lr, lr, r8
	eor	r12, r12, r6, ror #19
	mov	r8, r11, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, r11, ror #18
	add	lr, lr, r12
	eor	r8, r8, r11, lsr #3
	add	r8, r8, lr
	ldr	lr, [r1, #(38+3)*4]
	str	r8, [r1, #(40+15)*4]
	mov	r12, r7, ror #17
	add	r11, r11, r9
	eor	r12, r12, r7, ror #19
	mov	r9, lr, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(40+2)*4]
	eor	r9, r9, lr, lsr #3
	add	r9, r9, r12

	mov	r12, r8, ror #17
	str	r9, [r1, #(40+16)*4]
	add	lr, lr, r10
	eor	r12, r12, r8, ror #19
	mov	r10, r11, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, r11, ror #18
	add	lr, lr, r12
	eor	r10, r10, r11, lsr #3
	add	r10, r10, lr
	ldr	lr, [r1, #(40+3)*4]
	str	r10, [r1, #(42+15)*4]
	mov	r12, r9, ror #17
	add	r11, r11, r4
	eor	r12, r12, r9, ror #19
	mov	r4, lr, ror #7
	eor	r12, r12, r9, lsr #10
	eor	r4, r4, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(42+2)*4]
	eor	r4, r4, lr, lsr #3
	add	r4, r4, r12

	mov	r12, r10, ror #17
	str	r4, [r1, #(42+16)*4]
	add	lr, lr, r5
	eor	r12, r12, r10, ror #19
	mov	r5, r11, ror #7
	eor	r12, r12, r10, lsr #10
	eor	r5, r5, r11, ror #18
	add	lr, lr, r12
	eor	r5, r5, r11, lsr #3
	add	r5, r5, lr
	ldr	lr, [r1, #(42+3)*4]
	bne	sha256d_ms_extend_coda2
	str	r5, [r1, #(44+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(44+2)*4]
	eor	r6, r6, lr, lsr #3
	add	r6, r6, r12

	mov	r12, r5, ror #17
	str	r6, [r1, #(44+16)*4]
	add	lr, lr, r7
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	add	r7, r7, lr
	ldr	lr, [r1, #(44+3)*4]
	str	r7, [r1, #(46+15)*4]
	mov	r12, r6, ror #17
	add	r11, r11, r8
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r12, r12, r11
	ldr	r11, [r1, #(46+2)*4]
	eor	r8, r8, lr, lsr #3
	add	r8, r8, r12

	mov	r12, r7, ror #17
	str	r8, [r1, #(46+16)*4]
	add	lr, lr, r9
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	add	r9, r9, lr
	str	r9, [r1, #(46+17)*4]
	
	ldr	r4,  [r3, #0*4]
	ldr	r9,  [r3, #1*4]
	ldr	r10, [r3, #2*4]
	ldr	r11, [r3, #3*4]
	ldr	r8,  [r3, #4*4]
	ldr	r5,  [r3, #5*4]
	ldr	r6,  [r3, #6*4]
	ldr	r7,  [r3, #7*4]
	b	sha256d_ms_main_loop1
	
sha256d_ms_main_loop2:
	ldr	r12, [r1, #(0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
sha256d_ms_main_loop1:
	ldr	r12, [r1, #(3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(4+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (4+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(4+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (4+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(4+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (4+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(4+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (4+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(8+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (8+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(8+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (8+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(8+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (8+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(8+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (8+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(12+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (12+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(12+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (12+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(12+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (12+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(12+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (12+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(16+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (16+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(16+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (16+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(16+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (16+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(16+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (16+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(20+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (20+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(20+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (20+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(20+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (20+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(20+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (20+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(24+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (24+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(24+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (24+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(24+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (24+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(24+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (24+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(28+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (28+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(28+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (28+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(28+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (28+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(28+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (28+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	b	sha256d_ms_k_over
sha256d_ms_k:
	.align 2
	.long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	.long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	.long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	.long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
sha256d_ms_k_over:
	ldr	r12, [r1, #(32+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (32+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(32+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (32+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(32+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (32+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(32+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (32+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(36+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (36+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(36+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (36+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(36+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (36+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(36+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (36+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(40+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (40+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(40+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (40+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(40+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (40+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(40+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (40+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(44+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (44+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(44+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (44+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(44+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (44+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(44+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (44+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(48+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (48+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(48+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (48+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(48+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (48+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(48+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (48+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(52+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (52+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(52+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (52+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(52+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (52+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(52+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (52+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(56)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (56)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	bne	sha256d_ms_finish
	ldr	r12, [r1, #(57)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (57)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(58)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (58)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(59)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (59)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	ldr	r12, [r1, #(60+0)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (60+0)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	eor	r3, r4, r5
	add	r11, r11, lr, ror #6

	and	r3, r3, r6
	eor	r12, r4, r4, ror #11
	and	lr, r4, r5
	eor	r12, r12, r4, ror #20
	eor	lr, lr, r3
	add	r3, r11, lr
	add	r11, r11, r7
	add	r7, r3, r12, ror #2
	ldr	r12, [r1, #(60+1)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (60+1)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	eor	r3, r7, r4
	add	r10, r10, lr, ror #6

	and	r3, r3, r5
	eor	r12, r7, r7, ror #11
	and	lr, r7, r4
	eor	r12, r12, r7, ror #20
	eor	lr, lr, r3
	add	r3, r10, lr
	add	r10, r10, r6
	add	r6, r3, r12, ror #2
	ldr	r12, [r1, #(60+2)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (60+2)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	eor	r3, r6, r7
	add	r9, r9, lr, ror #6

	and	r3, r3, r4
	eor	r12, r6, r6, ror #11
	and	lr, r6, r7
	eor	r12, r12, r6, ror #20
	eor	lr, lr, r3
	add	r3, r9, lr
	add	r9, r9, r5
	add	r5, r3, r12, ror #2
	ldr	r12, [r1, #(60+3)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (60+3)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	eor	r3, r5, r6
	add	r8, r8, lr, ror #6

	and	r3, r3, r7
	eor	r12, r5, r5, ror #11
	and	lr, r5, r6
	eor	r12, r12, r5, ror #20
	eor	lr, lr, r3
	add	r3, r8, lr
	add	r8, r8, r4
	add	r4, r3, r12, ror #2
	
	ldmia	r2!, {r3, r12, lr}
	add	r4, r4, r3
	add	r5, r5, r12
	add	r6, r6, lr
	stmia	sp, {r4-r6}
	ldmia	r2, {r3, r4, r5, r6, r12}
	add	lr, sp, #3*4
	add	r7, r7, r3
	add	r8, r8, r4
	add	r9, r9, r5
	add	r10, r10, r6
	add	r11, r11, r12
	add	r12, sp, #18*4
	stmia	lr!, {r7-r11}
	
	ldmia	r12, {r4-r11}
	str	r4,  [r1, #18*4]
	str	r5,  [r1, #19*4]
	str	r6,  [r1, #20*4]
	str	r7,  [r1, #22*4]
	str	r8,  [r1, #23*4]
	str	r9,  [r1, #24*4]
	str	r10, [r1, #30*4]
	str	r11, [r1, #31*4]
	
	mov	r3,  #0x80000000
	mov	r4,  #0
	mov	r5,  #0
	mov	r6,  #0
	mov	r7,  #0
	mov	r8,  #0
	mov	r9,  #0
	mov	r10, #0x00000100
	stmia	lr, {r3-r10}
	
	ldr	lr, [sp, #1*4]
	movs	r1, sp
	ldr	r4, [sp, #0*4]
	
	ldr	r11, [sp, #2*4]
	mov	r12, lr, ror #7
	eor	r12, r12, lr, ror #18
	add	r5, lr, #0x00a00000
	eor	r12, r12, lr, lsr #3
	mov	lr, r11, ror #7
	add	r4, r4, r12
	eor	lr, lr, r11, ror #18
	str	r4, [sp, #16*4]
	eor	lr, lr, r11, lsr #3
	mov	r12, r4, ror #17
	add	r5, r5, lr
	ldr	lr, [sp, #3*4]
	
	str	r5, [sp, #17*4]
	eor	r12, r12, r4, ror #19
	mov	r6, lr, ror #7
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, ror #18
	add	r11, r11, r12
	eor	r6, r6, lr, lsr #3
	mov	r12, r5, ror #17
	add	r6, r6, r11
	ldr	r11, [sp, #4*4]
	
	str	r6, [sp, #18*4]
	eor	r12, r12, r5, ror #19
	mov	r7, r11, ror #7
	eor	r12, r12, r5, lsr #10
	eor	r7, r7, r11, ror #18
	add	lr, lr, r12
	eor	r7, r7, r11, lsr #3
	mov	r12, r6, ror #17
	add	r7, r7, lr
	ldr	lr, [sp, #5*4]
	
	str	r7, [sp, #19*4]
	eor	r12, r12, r6, ror #19
	mov	r8, lr, ror #7
	eor	r12, r12, r6, lsr #10
	eor	r8, r8, lr, ror #18
	add	r11, r11, r12
	eor	r8, r8, lr, lsr #3
	mov	r12, r7, ror #17
	add	r8, r8, r11
	ldr	r11, [sp, #6*4]
	
	str	r8, [sp, #20*4]
	eor	r12, r12, r7, ror #19
	mov	r9, r11, ror #7
	eor	r12, r12, r7, lsr #10
	eor	r9, r9, r11, ror #18
	add	lr, lr, r12
	eor	r9, r9, r11, lsr #3
	mov	r12, r8, ror #17
	add	r9, r9, lr
	ldr	lr, [sp, #7*4]
	
	str	r9, [sp, #21*4]
	eor	r12, r12, r8, ror #19
	mov	r10, lr, ror #7
	eor	r12, r12, r8, lsr #10
	eor	r10, r10, lr, ror #18
	add	r11, r11, r12
	eor	r10, r10, lr, lsr #3
	mov	r12, r9, ror #17
	add	r11, r11, #0x00000100
	add	lr, lr, r4
	add	r10, r10, r11
	
	eor	r12, r12, r9, ror #19
	str	r10, [sp, #22*4]
	add	lr, lr, #0x11000000
	eor	r12, r12, r9, lsr #10
	add	lr, lr, r12
	mov	r12, r10, ror #17
	add	r4, lr, #0x00002000
	eor	r12, r12, r10, ror #19
	str	r4, [sp, #23*4]
	add	r5, r5, #0x80000000
	eor	r12, r12, r10, lsr #10
	add	r5, r5, r12

	mov	r12, r4, ror #17
	str	r5, [sp, #24*4]
	eor	r12, r12, r4, ror #19
	mov	r11, r5, ror #17
	eor	r12, r12, r4, lsr #10
	eor	r11, r11, r5, ror #19
	add	r6, r6, r12
	eor	r11, r11, r5, lsr #10
	str	r6, [sp, #25*4]
	add	r7, r7, r11
	
	mov	r12, r6, ror #17
	str	r7, [sp, #26*4]
	eor	r12, r12, r6, ror #19
	mov	r11, r7, ror #17
	eor	r12, r12, r6, lsr #10
	eor	r11, r11, r7, ror #19
	add	r8, r8, r12
	eor	r11, r11, r7, lsr #10
	str	r8, [sp, #27*4]
	add	r9, r9, r11
	
	mov	lr, r8, ror #17
	mov	r12, r9, ror #17
	str	r9, [sp, #28*4]
	add	r4, r4, #0x00400000
	eor	lr, lr, r8, ror #19
	eor	r12, r12, r9, ror #19
	eor	lr, lr, r8, lsr #10
	eor	r12, r12, r9, lsr #10
	add	r4, r4, #0x00000022
	add	r10, r10, lr
	add	r4, r4, r12
	ldr	r11, [sp, #16*4]
	
	add	r5, r5, #0x00000100
	str	r4, [sp, #30*4]
	mov	lr, r11, ror #7
	str	r10, [sp, #29*4]
	mov	r12, r10, ror #17
	eor	lr, lr, r11, ror #18
	eor	r12, r12, r10, ror #19
	eor	lr, lr, r11, lsr #3
	eor	r12, r12, r10, lsr #10
	add	r5, r5, lr
	ldr	lr, [r1, #17*4]
	add	r5, r5, r12
	
	b	sha256d_ms_extend_loop2
	
sha256d_ms_extend_coda2:
	str	r5, [r1, #(44+15)*4]
	mov	r12, r4, ror #17
	add	r11, r11, r6
	mov	r6, lr, ror #7
	eor	r12, r12, r4, ror #19
	eor	r6, r6, lr, ror #18
	eor	r12, r12, r4, lsr #10
	eor	r6, r6, lr, lsr #3
	add	r12, r12, r11
	add	r6, r6, r12
	str	r6, [r1, #(44+16)*4]
	
	adr	r2, sha256d_ms_h
	ldmia	r2, {r4-r11}
	b	sha256d_ms_main_loop2

sha256d_ms_h:
	.long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	.long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	
sha256d_ms_finish:
	ldr	r12, [r1, #(57)*4]
	and	r3, r8, r11
	bic	lr, r9, r11
	add	r10, r10, r6
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (57)*4
	add	r10, r10, lr
	eor	lr, r11, r11, ror #5
	add	r10, r10, r12
	eor	lr, lr, r11, ror #19
	add	r10, r10, r3
	add	r10, r10, lr, ror #6
	ldr	r12, [r1, #(58)*4]
	and	r3, r11, r10
	bic	lr, r8, r10
	add	r9, r9, r5
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (58)*4
	add	r9, r9, lr
	eor	lr, r10, r10, ror #5
	add	r9, r9, r12
	eor	lr, lr, r10, ror #19
	add	r9, r9, r3
	add	r9, r9, lr, ror #6
	ldr	r12, [r1, #(59)*4]
	and	r3, r10, r9
	bic	lr, r11, r9
	add	r8, r8, r4
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (59)*4
	add	r8, r8, lr
	eor	lr, r9, r9, ror #5
	add	r8, r8, r12
	eor	lr, lr, r9, ror #19
	add	r8, r8, r3
	add	r8, r8, lr, ror #6
	ldr	r5, [r2, #7*4]
	ldr	r12, [r1, #(60)*4]
	and	r3, r9, r8
	bic	lr, r10, r8
	add	r11, r11, r7
	orr	lr, lr, r3
	ldr	r3, sha256d_ms_k + (60)*4
	add	r11, r11, lr
	eor	lr, r8, r8, ror #5
	add	r11, r11, r12
	eor	lr, lr, r8, ror #19
	add	r11, r11, r3
	add	r11, r11, lr, ror #6
	
	add	r11, r11, r5
	str	r11, [r0, #7*4]
	
	add	sp, sp, #64*4
#ifdef __thumb__
	ldmfd	sp!, {r4-r11, lr}
	bx	lr
#else
	ldmfd	sp!, {r4-r11, pc}
#endif


#ifdef __ARM_NEON__

	.text
	.code 32
	.align 2
	.globl sha256_init_4way
	.globl _sha256_init_4way
#ifdef __ELF__
	.type sha256_init_4way, %function
#endif
sha256_init_4way:
_sha256_init_4way:
	adr	r12, sha256_4h
	vldmia	r12, {q8-q15}
	vstmia	r0, {q8-q15}
	bx	lr
	.align 4
sha256_4h:
	.long 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667
	.long 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85
	.long 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372
	.long 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a
	.long 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f
	.long 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c
	.long 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab
	.long 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19









	.text
	.code 32
	.align 2
	.globl sha256_transform_4way
	.globl _sha256_transform_4way
#ifdef __ELF__
	.type sha256_transform_4way, %function
#endif
sha256_transform_4way:
_sha256_transform_4way:
	stmfd	sp!, {r4, lr}
	vpush	{q4-q7}
	mov	r12, sp
	sub	sp, sp, #64*16
	bic	sp, sp, #63
	cmp	r2, #0
	bne	sha256_transform_4way_swap
	
	vldmia	r1!, {q0-q7}
	vstmia	sp, {q0-q7}
	add	r3, sp, #8*16
	vldmia	r1, {q8-q15}
	vstmia	r3, {q8-q15}
	b	sha256_transform_4way_extend

sha256_transform_4way_swap:
	vldmia	r1!, {q0-q7}
	vrev32.8	q0, q0
	vrev32.8	q1, q1
	vrev32.8	q2, q2
	vrev32.8	q3, q3
	vldmia	r1, {q8-q15}
	vrev32.8	q4, q4
	vrev32.8	q5, q5
	vrev32.8	q6, q6
	vrev32.8	q7, q7
	vstmia	sp, {q0-q7}
	vrev32.8	q8, q8
	vrev32.8	q9, q9
	vrev32.8	q10, q10
	vrev32.8	q11, q11
	vrev32.8	q12, q12
	vrev32.8	q13, q13
	vrev32.8	q14, q14
	vrev32.8	q15, q15
	add	r3, sp, #8*16
	vstmia	r3, {q8-q15}
	
sha256_transform_4way_extend:
	add	r1, sp, #1*16
	add	r2, sp, #16*16
	vmov.u32	q5, q0
	vld1.u32	{q6}, [r1]!
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r2]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r2]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q14, q14, q1
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vst1.u32	{q14}, [r2]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q15, q15, q4

	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q15}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q14, #10
	veor.u32	q9, q9, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q9, q9, q1
	vadd.u32	q1, q6, q4
	veor.u32	q9, q9, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q9, q9, q1
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vst1.u32	{q9}, [r2]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshr.u32	q1, q15, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q10, q10, q1
	vadd.u32	q4, q4, q5
	veor.u32	q10, q10, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q10, q10, q4

	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q6, q6, q11
	vst1.u32	{q10}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q9, #10
	veor.u32	q11, q11, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q11, q11, q1
	vadd.u32	q1, q6, q4
	veor.u32	q11, q11, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q11, q11, q1
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q11}, [r2]!
	vadd.u32	q5, q5, q12
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshr.u32	q1, q10, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q12, q12, q1
	vadd.u32	q4, q4, q5
	veor.u32	q12, q12, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q12, q12, q4

	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q6, q6, q13
	vst1.u32	{q12}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q11, #10
	veor.u32	q13, q13, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q13, q13, q1
	vadd.u32	q1, q6, q4
	veor.u32	q13, q13, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q13, q13, q1
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q13}, [r2]!
	vadd.u32	q5, q5, q14
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshr.u32	q1, q12, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q14, q14, q1
	vadd.u32	q4, q4, q5
	veor.u32	q14, q14, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q14, q14, q4

	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q6, q6, q15
	vst1.u32	{q14}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q13, #10
	veor.u32	q15, q15, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q15, q15, q1
	vadd.u32	q1, q6, q4
	veor.u32	q15, q15, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q15, q15, q1
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vst1.u32	{q15}, [r2]!
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r2]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r2]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q14, q14, q1
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vst1.u32	{q14}, [r2]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q15, q15, q4

	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q15}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q14, #10
	veor.u32	q9, q9, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q9, q9, q1
	vadd.u32	q1, q6, q4
	veor.u32	q9, q9, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q9, q9, q1
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vst1.u32	{q9}, [r2]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshr.u32	q1, q15, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q10, q10, q1
	vadd.u32	q4, q4, q5
	veor.u32	q10, q10, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q10, q10, q4

	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q6, q6, q11
	vst1.u32	{q10}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q9, #10
	veor.u32	q11, q11, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q11, q11, q1
	vadd.u32	q1, q6, q4
	veor.u32	q11, q11, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q11, q11, q1
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q11}, [r2]!
	vadd.u32	q5, q5, q12
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshr.u32	q1, q10, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q12, q12, q1
	vadd.u32	q4, q4, q5
	veor.u32	q12, q12, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q12, q12, q4

	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q6, q6, q13
	vst1.u32	{q12}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q11, #10
	veor.u32	q13, q13, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q13, q13, q1
	vadd.u32	q1, q6, q4
	veor.u32	q13, q13, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q13, q13, q1
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q13}, [r2]!
	vadd.u32	q5, q5, q14
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshr.u32	q1, q12, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q14, q14, q1
	vadd.u32	q4, q4, q5
	veor.u32	q14, q14, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q14, q14, q4

	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q6, q6, q15
	vst1.u32	{q14}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q13, #10
	veor.u32	q15, q15, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q15, q15, q1
	vadd.u32	q1, q6, q4
	veor.u32	q15, q15, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q15, q15, q1
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vst1.u32	{q15}, [r2]!
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r2]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r2]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q14, q14, q1
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vst1.u32	{q14}, [r2]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q15, q15, q4

	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q15}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q14, #10
	veor.u32	q9, q9, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q9, q9, q1
	vadd.u32	q1, q6, q4
	veor.u32	q9, q9, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q9, q9, q1
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vst1.u32	{q9}, [r2]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshr.u32	q1, q15, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q10, q10, q1
	vadd.u32	q4, q4, q5
	veor.u32	q10, q10, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q10, q10, q4

	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q6, q6, q11
	vst1.u32	{q10}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q9, #10
	veor.u32	q11, q11, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q11, q11, q1
	vadd.u32	q1, q6, q4
	veor.u32	q11, q11, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q11, q11, q1
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q11}, [r2]!
	vadd.u32	q5, q5, q12
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshr.u32	q1, q10, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q12, q12, q1
	vadd.u32	q4, q4, q5
	veor.u32	q12, q12, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q12, q12, q4

	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q6, q6, q13
	vst1.u32	{q12}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q11, #10
	veor.u32	q13, q13, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q13, q13, q1
	vadd.u32	q1, q6, q4
	veor.u32	q13, q13, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q13, q13, q1
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q13}, [r2]!
	vadd.u32	q5, q5, q14
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshr.u32	q1, q12, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q14, q14, q1
	vadd.u32	q4, q4, q5
	veor.u32	q14, q14, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q14, q14, q4

	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q6, q6, q15
	vst1.u32	{q14}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q13, #10
	veor.u32	q15, q15, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q15, q15, q1
	vadd.u32	q1, q6, q4
	veor.u32	q15, q15, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q15, q15, q1
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vst1.u32	{q15}, [r2]!
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r2]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r1]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r2]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r1]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r2]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vadd.u32	q14, q14, q1
	vst1.u32	{q14}, [r2]!
	
	vldmia	r0, {q0-q7}
	adr	r4, sha256_transform_4way_4k
	b	sha256_transform_4way_4k_over
	.align 4
sha256_transform_4way_4k:
	.long 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98
	.long 0x71374491, 0x71374491, 0x71374491, 0x71374491
	.long 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf
	.long 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5
	.long 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b
	.long 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1
	.long 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4
	.long 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5
	.long 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98
	.long 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01
	.long 0x243185be, 0x243185be, 0x243185be, 0x243185be
	.long 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3
	.long 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74
	.long 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe
	.long 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7
	.long 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174
	.long 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1
	.long 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786
	.long 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6
	.long 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc
	.long 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f
	.long 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa
	.long 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc
	.long 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da
	.long 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152
	.long 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d
	.long 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8
	.long 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7
	.long 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3
	.long 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147
	.long 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351
	.long 0x14292967, 0x14292967, 0x14292967, 0x14292967
	.long 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85
	.long 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138
	.long 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc
	.long 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13
	.long 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354
	.long 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb
	.long 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e
	.long 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85
	.long 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1
	.long 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b
	.long 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70
	.long 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3
	.long 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819
	.long 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624
	.long 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585
	.long 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070
	.long 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116
	.long 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08
	.long 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c
	.long 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5
	.long 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3
	.long 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a
	.long 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f
	.long 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3
	.long 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee
	.long 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f
	.long 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814
	.long 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208
	.long 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa
	.long 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb
	.long 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7
	.long 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2
sha256_transform_4way_4k_over:
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [sp]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r4]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	
	vldmia	r0, {q8-q15}
	vadd.u32	q0, q0, q8
	vadd.u32	q1, q1, q9
	vadd.u32	q2, q2, q10
	vadd.u32	q3, q3, q11
	vadd.u32	q4, q4, q12
	vadd.u32	q5, q5, q13
	vadd.u32	q6, q6, q14
	vadd.u32	q7, q7, q15
	vstmia	r0, {q0-q7}
	
	mov	sp, r12
	vpop	{q4-q7}
	ldmfd	sp!, {r4, pc}
	

	.text
	.code 32
	.align 2
	.globl sha256d_ms_4way
	.globl _sha256d_ms_4way
#ifdef __ELF__
	.type sha256d_ms_4way, %function
#endif
sha256d_ms_4way:
_sha256d_ms_4way:
	stmfd	sp!, {r4, lr}
	vpush	{q4-q7}
	mov	r12, sp
	sub	sp, sp, #64*16
	bic	sp, sp, #63
	
	add	r4, r1, #3*16
	vld1.u32	{q6}, [r4]!
	add	r1, r1, #18*16
	vldmia	r1, {q11-q13}
	cmp	r0, r0
	
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	vshr.u32	q1, q6, #18
	veor.u32	q10, q10, q0
	vshl.u32	q0, q6, #32-18
	veor.u32	q10, q10, q1
	vshr.u32	q1, q6, #3
	veor.u32	q10, q10, q0
	vstmia	sp!, {q11-q13}
	veor.u32	q4, q10, q1
	vadd.u32	q12, q12, q6
	vadd.u32	q11, q11, q4
	
	vshr.u32	q14, q12, #17
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q12}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q11, #10
	vshl.u32	q0, q12, #32-17
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vadd.u32	q13, q13, q4
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q14, q14, q0
	vst1.u32	{q13}, [r1]!
	veor.u32	q14, q14, q1
	vshr.u32	q1, q12, #10
	
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	veor.u32	q14, q14, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q14}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q13, #10
	vld1.u32	{q15}, [r1]
	veor.u32	q4, q4, q1
	vst1.u32	{q15}, [sp]!
	vadd.u32	q15, q15, q4
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q0
	vld1.u32	{q9}, [r1]
	veor.u32	q4, q4, q1
	vshr.u32	q1, q14, #10
	vst1.u32	{q9}, [sp]!
	veor.u32	q5, q4, q1
	
	vshr.u32	q4, q15, #17
	vadd.u32	q9, q9, q5
	vshl.u32	q0, q15, #32-17
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vst1.u32	{q9}, [r1]!
	veor.u32	q4, q4, q0
	vld1.u32	{q10}, [r1]
	veor.u32	q4, q4, q1
	vshr.u32	q1, q15, #10
	vst1.u32	{q10}, [sp]!
	veor.u32	q4, q4, q1
	vshl.u32	q0, q9, #32-17
	vadd.u32	q10, q10, q4
	vshr.u32	q4, q9, #17
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	veor.u32	q4, q4, q1
	vshr.u32	q1, q9, #10
	veor.u32	q4, q4, q0
	vst1.u32	{q10}, [r1]!
	veor.u32	q5, q4, q1
	
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q11, q11, q5
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q10, #10
	vshl.u32	q0, q11, #32-17
	veor.u32	q2, q4, q1
	vshr.u32	q4, q11, #17
	vadd.u32	q12, q12, q2
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	veor.u32	q4, q4, q1
	vshr.u32	q1, q11, #10
	veor.u32	q4, q4, q0
	vst1.u32	{q12}, [r1]!
	veor.u32	q5, q4, q1
	
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q13, q13, q5
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q13}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q12, #10
	vshl.u32	q0, q13, #32-17
	veor.u32	q2, q4, q1
	vshr.u32	q4, q13, #17
	vadd.u32	q14, q14, q2
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	veor.u32	q4, q4, q1
	vshr.u32	q1, q13, #10
	veor.u32	q4, q4, q0
	vst1.u32	{q14}, [r1]!
	veor.u32	q5, q4, q1
	add	r4, r4, #12*16
	
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q15, q15, q5
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q14, #10
	vld1.u32	{q2}, [r1]
	veor.u32	q4, q4, q1
	vshl.u32	q0, q15, #32-17
	vadd.u32	q9, q9, q4
	vst1.u32	{q2}, [sp]!
	vadd.u32	q9, q9, q2
	vshr.u32	q4, q15, #17
	vshr.u32	q2, q15, #19
	veor.u32	q4, q4, q0
	vst1.u32	{q9}, [r1]!
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q2
	vshr.u32	q0, q15, #10
	veor.u32	q4, q4, q1
	vld1.u32	{q5-q6}, [r4]!
	veor.u32	q4, q4, q0
	vld1.u32	{q2}, [r1]
	vadd.u32	q10, q10, q4
	vst1.u32	{q2}, [sp]!
	vadd.u32	q10, q10, q2
	
	sub	sp, sp, #8*16
	
sha256d_ms_4way_extend_loop2:
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r1]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r1]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q14, q14, q1
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vst1.u32	{q14}, [r1]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q15, q15, q4

	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q14, #10
	veor.u32	q9, q9, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q9, q9, q1
	vadd.u32	q1, q6, q4
	veor.u32	q9, q9, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q9, q9, q1
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vst1.u32	{q9}, [r1]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshr.u32	q1, q15, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q10, q10, q1
	vadd.u32	q4, q4, q5
	veor.u32	q10, q10, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q10, q10, q4

	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q6, q6, q11
	vst1.u32	{q10}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q9, #10
	veor.u32	q11, q11, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q11, q11, q1
	vadd.u32	q1, q6, q4
	veor.u32	q11, q11, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q11, q11, q1
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q11}, [r1]!
	vadd.u32	q5, q5, q12
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshr.u32	q1, q10, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q12, q12, q1
	vadd.u32	q4, q4, q5
	veor.u32	q12, q12, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q12, q12, q4

	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q6, q6, q13
	vst1.u32	{q12}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q11, #10
	veor.u32	q13, q13, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q13, q13, q1
	vadd.u32	q1, q6, q4
	veor.u32	q13, q13, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q13, q13, q1
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q13}, [r1]!
	vadd.u32	q5, q5, q14
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshr.u32	q1, q12, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q14, q14, q1
	vadd.u32	q4, q4, q5
	veor.u32	q14, q14, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q14, q14, q4

	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q6, q6, q15
	vst1.u32	{q14}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q13, #10
	veor.u32	q15, q15, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q15, q15, q1
	vadd.u32	q1, q6, q4
	veor.u32	q15, q15, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q15, q15, q1
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vst1.u32	{q15}, [r1]!
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r1]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r1]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q14, q14, q1
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vst1.u32	{q14}, [r1]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q15, q15, q4

	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q14, #10
	veor.u32	q9, q9, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q9, q9, q1
	vadd.u32	q1, q6, q4
	veor.u32	q9, q9, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q9, q9, q1
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vst1.u32	{q9}, [r1]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshr.u32	q1, q15, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q10, q10, q1
	vadd.u32	q4, q4, q5
	veor.u32	q10, q10, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q10, q10, q4

	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q6, q6, q11
	vst1.u32	{q10}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q9, #10
	veor.u32	q11, q11, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q11, q11, q1
	vadd.u32	q1, q6, q4
	veor.u32	q11, q11, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q11, q11, q1
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q11}, [r1]!
	vadd.u32	q5, q5, q12
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshr.u32	q1, q10, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q12, q12, q1
	vadd.u32	q4, q4, q5
	veor.u32	q12, q12, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q12, q12, q4

	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q6, q6, q13
	vst1.u32	{q12}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q11, #10
	veor.u32	q13, q13, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q13, q13, q1
	vadd.u32	q1, q6, q4
	veor.u32	q13, q13, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q13, q13, q1
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q13}, [r1]!
	vadd.u32	q5, q5, q14
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshr.u32	q1, q12, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q14, q14, q1
	vadd.u32	q4, q4, q5
	veor.u32	q14, q14, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q14, q14, q4

	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q6, q6, q15
	vst1.u32	{q14}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q13, #10
	veor.u32	q15, q15, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q15, q15, q1
	vadd.u32	q1, q6, q4
	veor.u32	q15, q15, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q15, q15, q1
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vst1.u32	{q15}, [r1]!
	vadd.u32	q5, q5, q9
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q9, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshr.u32	q1, q14, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q9, q9, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q9, q9, q1
	vadd.u32	q4, q4, q5
	veor.u32	q9, q9, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q9, q9, q4

	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q10, q10, q1
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vst1.u32	{q10}, [r1]!
	vadd.u32	q5, q5, q11
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q11, q11, q4

	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q6, q6, q12
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q12, q12, q1
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q12, q12, q1
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vst1.u32	{q12}, [r1]!
	vadd.u32	q5, q5, q13
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q13, q13, q4

	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q6, q6, q14
	vst1.u32	{q13}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q14, q14, q1
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	vadd.u32	q14, q14, q1
	vst1.u32	{q14}, [r1]!
	bne	sha256d_ms_4way_extend_coda2
	
	vldmia	r3!, {q4-q7}
	vldmia	r3, {q0-q3}
	vswp	q0, q4
	adr	r3, sha256d_ms_4way_4k+3*16
	sub r1, r1, #(64-3)*16
	b	sha256d_ms_4way_main_loop1
	
	.align 4
sha256d_ms_4way_4k:
	.long 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98
	.long 0x71374491, 0x71374491, 0x71374491, 0x71374491
	.long 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf
	.long 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5
	.long 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b
	.long 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1
	.long 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4
	.long 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5
	.long 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98
	.long 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01
	.long 0x243185be, 0x243185be, 0x243185be, 0x243185be
	.long 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3
	.long 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74
	.long 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe
	.long 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7
	.long 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174
	.long 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1
	.long 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786
	.long 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6
	.long 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc
	.long 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f
	.long 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa
	.long 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc
	.long 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da
	.long 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152
	.long 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d
	.long 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8
	.long 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7
	.long 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3
	.long 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147
	.long 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351
	.long 0x14292967, 0x14292967, 0x14292967, 0x14292967
	.long 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85
	.long 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138
	.long 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc
	.long 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13
	.long 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354
	.long 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb
	.long 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e
	.long 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85
	.long 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1
	.long 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b
	.long 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70
	.long 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3
	.long 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819
	.long 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624
	.long 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585
	.long 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070
	.long 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116
	.long 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08
	.long 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c
	.long 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5
	.long 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3
	.long 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a
	.long 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f
	.long 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3
	.long 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee
	.long 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f
	.long 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814
	.long 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208
	.long 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa
	.long 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb
	.long 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7
	.long 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2
	
sha256d_ms_4way_main_loop2:
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
sha256d_ms_4way_main_loop1:
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	bne	sha256d_ms_4way_finish
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q10
	vshl.u32	q12, q4, #32-5
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vadd.u32	q7, q7, q9
	veor.u32	q9, q0, q1
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11

	vshr.u32	q11, q0, #11
	vshl.u32	q12, q0, #32-11
	veor.u32	q8, q0, q11
	vand.u32	q10, q0, q1
	veor.u32	q8, q8, q12
	vshr.u32	q11, q0, #20
	vshl.u32	q12, q0, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q2
	veor.u32	q8, q8, q12
	vadd.u32	q7, q7, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q7, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q7, q7, q3
	vadd.u32	q3, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q10
	vshl.u32	q12, q7, #32-5
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vadd.u32	q6, q6, q9
	veor.u32	q9, q3, q0
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11

	vshr.u32	q11, q3, #11
	vshl.u32	q12, q3, #32-11
	veor.u32	q8, q3, q11
	vand.u32	q10, q3, q0
	veor.u32	q8, q8, q12
	vshr.u32	q11, q3, #20
	vshl.u32	q12, q3, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q1
	veor.u32	q8, q8, q12
	vadd.u32	q6, q6, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q6, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q6, q6, q2
	vadd.u32	q2, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q10
	vshl.u32	q12, q6, #32-5
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vadd.u32	q5, q5, q9
	veor.u32	q9, q2, q3
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11

	vshr.u32	q11, q2, #11
	vshl.u32	q12, q2, #32-11
	veor.u32	q8, q2, q11
	vand.u32	q10, q2, q3
	veor.u32	q8, q8, q12
	vshr.u32	q11, q2, #20
	vshl.u32	q12, q2, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q0
	veor.u32	q8, q8, q12
	vadd.u32	q5, q5, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q5, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q5, q5, q1
	vadd.u32	q1, q9, q12
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q10
	vshl.u32	q12, q5, #32-5
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vadd.u32	q4, q4, q9
	veor.u32	q9, q1, q2
	vshr.u32	q11, q10, #6
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11

	vshr.u32	q11, q1, #11
	vshl.u32	q12, q1, #32-11
	veor.u32	q8, q1, q11
	vand.u32	q10, q1, q2
	veor.u32	q8, q8, q12
	vshr.u32	q11, q1, #20
	vshl.u32	q12, q1, #32-20
	veor.u32	q8, q8, q11
	vand.u32	q9, q9, q3
	veor.u32	q8, q8, q12
	vadd.u32	q4, q4, q13
	veor.u32	q10, q10, q9
	vshr.u32	q11, q8, #2
	vshl.u32	q12, q8, #32-2
	vadd.u32	q9, q4, q10
	vadd.u32	q12, q12, q11
	vadd.u32	q4, q4, q0
	vadd.u32	q0, q9, q12
	
	vldmia	r2, {q8-q15}
	vadd.u32	q0, q0, q8
	vadd.u32	q1, q1, q9
	vadd.u32	q2, q2, q10
	vadd.u32	q3, q3, q11
	vadd.u32	q4, q4, q12
	vadd.u32	q5, q5, q13
	vadd.u32	q6, q6, q14
	vadd.u32	q7, q7, q15
	
	vldmia	sp, {q8-q15}
	sub	r1, r1, #(64-18)*16
	vstmia	r1, {q8-q10}
	add	r1, r1, #4*16
	vstmia	r1, {q11-q13}
	add	r1, r1, #8*16
	vstmia	r1, {q14-q15}
	
	vstmia	sp, {q0-q7}
	vmov.u32	q8,  #0x80000000
	vmov.u32	q9,  #0
	vmov.u32	q10, #0
	vmov.u32	q11, #0
	vmov.u32	q12, #0
	vmov.u32	q13, #0
	vmov.u32	q14, #0
	vmov.u32	q15, #0x00000100
	add	r1, sp, #8*16
	vstmia	r1!, {q8-q15}
	adds	r4, sp, #2*16
	
	vshr.u32	q9, q1, #7
	vshl.u32	q2, q1, #32-7
	vshr.u32	q4, q1, #18
	veor.u32	q9, q9, q2
	vshl.u32	q3, q1, #32-18
	veor.u32	q9, q9, q4
	vshr.u32	q2, q1, #3
	veor.u32	q9, q9, q3
	vld1.u32	{q5}, [r4]!
	veor.u32	q9, q9, q2
	vmov.u32	q7, #0x00a00000
	vadd.u32	q9, q9, q0
	vshr.u32	q10, q5, #7
	vshl.u32	q0, q5, #32-7
	vshl.u32	q3, q5, #32-18
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q10, q10, q3
	vst1.u32	{q9}, [r1]!
	vadd.u32	q3, q1, q7
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #3
	vld1.u32	{q6}, [r4]!
	veor.u32	q10, q10, q0
	
	vshr.u32	q4, q9, #17
	vshl.u32	q0, q9, #32-17
	vadd.u32	q10, q10, q3
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q11, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshr.u32	q1, q9, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q11, q11, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q11, q11, q1
	vadd.u32	q4, q4, q5
	veor.u32	q11, q11, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q11, q11, q4
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vst1.u32	{q10}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q12, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q10, #10
	veor.u32	q12, q12, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q12, q12, q0
	vshl.u32	q1, q5, #32-18
	vst1.u32	{q11}, [r1]!
	veor.u32	q12, q12, q1
	vshr.u32	q0, q5, #3
	vadd.u32	q1, q6, q4
	veor.u32	q12, q12, q0
	
	vshr.u32	q4, q11, #17
	vshl.u32	q0, q11, #32-17
	vadd.u32	q12, q12, q1
	vld1.u32	{q6}, [r4]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q13, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshr.u32	q1, q11, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q13, q13, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q13, q13, q1
	vadd.u32	q4, q4, q5
	veor.u32	q13, q13, q0
	vld1.u32	{q5}, [r4]!
	vadd.u32	q13, q13, q4
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vst1.u32	{q12}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q14, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q12, #10
	veor.u32	q14, q14, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q14, q14, q0
	vshl.u32	q1, q5, #32-18
	vst1.u32	{q13}, [r1]!
	veor.u32	q14, q14, q1
	vshr.u32	q0, q5, #3
	vadd.u32	q1, q6, q4
	veor.u32	q14, q14, q0
	
	vshr.u32	q4, q13, #17
	vshl.u32	q0, q13, #32-17
	vadd.u32	q14, q14, q1
	vld1.u32	{q6}, [r4]!
	vadd.u32	q5, q5, q15
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q15, q6, #7
	vshl.u32	q0, q6, #32-7
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshr.u32	q1, q13, #10
	vshr.u32	q0, q6, #18
	veor.u32	q4, q4, q1
	veor.u32	q15, q15, q0
	vshl.u32	q1, q6, #32-18
	vshr.u32	q0, q6, #3
	veor.u32	q15, q15, q1
	vadd.u32	q4, q4, q5
	veor.u32	q15, q15, q0
	vmov.u32	q5, #0x80000000
	vadd.u32	q15, q15, q4
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vadd.u32	q6, q6, q9
	vst1.u32	{q14}, [r1]!
	vmov.u32	q7, #0x11000000
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	vadd.u32	q6, q6, q7
	vmov.u32	q2, #0x00002000
	veor.u32	q4, q4, q0
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q14, #10
	vadd.u32	q6, q6, q2
	veor.u32	q1, q4, q1
	add	r4, r4, #8*16
	
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q9, q6, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q9}, [r1]!
	vadd.u32	q5, q5, q10
	veor.u32	q4, q4, q1
	vshr.u32	q1, q15, #10
	vshl.u32	q0, q9, #32-17
	veor.u32	q10, q4, q1
	vshr.u32	q4, q9, #17
	vadd.u32	q10, q10, q5
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #19
	vshl.u32	q1, q9, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q9, #10
	veor.u32	q4, q4, q1
	vst1.u32	{q10}, [r1]!
	veor.u32	q1, q4, q0
	
	vshr.u32	q4, q10, #17
	vshl.u32	q0, q10, #32-17
	vadd.u32	q11, q11, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q10, #19
	vshl.u32	q1, q10, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q11}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q10, #10
	vshl.u32	q0, q11, #32-17
	veor.u32	q1, q4, q1
	vshr.u32	q4, q11, #17
	vadd.u32	q12, q12, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #19
	vshl.u32	q1, q11, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q11, #10
	veor.u32	q4, q4, q1
	vst1.u32	{q12}, [r1]!
	veor.u32	q1, q4, q0
	
	vshr.u32	q4, q12, #17
	vshl.u32	q0, q12, #32-17
	vadd.u32	q13, q13, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q12, #19
	vshl.u32	q1, q12, #32-19
	veor.u32	q4, q4, q0
	vst1.u32	{q13}, [r1]!
	veor.u32	q4, q4, q1
	vshr.u32	q1, q12, #10
	vshl.u32	q0, q13, #32-17
	veor.u32	q1, q4, q1
	vshr.u32	q4, q13, #17
	vadd.u32	q14, q14, q1
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #19
	vshl.u32	q1, q13, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q0, q13, #10
	veor.u32	q4, q4, q1
	vst1.u32	{q14}, [r1]!
	veor.u32	q4, q4, q0
	vmov.u32	q6, #0x00000100
	vadd.u32	q15, q15, q4
	
	vshr.u32	q4, q14, #17
	vshl.u32	q0, q14, #32-17
	vmov.u32	q7, #0x00400000
	vst1.u32	{q15}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q14, #19
	vshl.u32	q1, q14, #32-19
	veor.u32	q4, q4, q0
	vadd.u32	q9, q9, q7
	veor.u32	q4, q4, q1
	vshr.u32	q1, q14, #10
	vmov.u32	q2, #0x00000022
	veor.u32	q4, q4, q1
	vadd.u32	q9, q9, q2
	vld1.u32	{q5}, [r4]!
	vadd.u32	q9, q9, q4
	vshr.u32	q4, q15, #17
	vshl.u32	q0, q15, #32-17
	vadd.u32	q6, q6, q10
	vst1.u32	{q9}, [r1]!
	veor.u32	q4, q4, q0
	vshr.u32	q0, q15, #19
	vshl.u32	q1, q15, #32-19
	veor.u32	q4, q4, q0
	vshr.u32	q10, q5, #7
	veor.u32	q4, q4, q1
	vshl.u32	q0, q5, #32-7
	vshr.u32	q1, q15, #10
	veor.u32	q10, q10, q0
	vshr.u32	q0, q5, #18
	veor.u32	q4, q4, q1
	veor.u32	q10, q10, q0
	vshl.u32	q1, q5, #32-18
	vshr.u32	q0, q5, #3
	veor.u32	q10, q10, q1
	vadd.u32	q1, q6, q4
	veor.u32	q10, q10, q0
	vld1.u32	{q6}, [r4]!
	vadd.u32	q10, q10, q1
	
	b	sha256d_ms_4way_extend_loop2
	
	.align 4
sha256d_ms_4way_4h:
	.long 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667
	.long 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85
	.long 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372
	.long 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a
	.long 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f
	.long 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c
	.long 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab
	.long 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19
	
sha256d_ms_4way_extend_coda2:
	adr	r4, sha256d_ms_4way_4h
	mov	r1, sp
	vldmia	r4, {q0-q7}
	vmov.u32	q15, q7
	sub	r3, r3, #64*16
	b	sha256d_ms_4way_main_loop2


sha256d_ms_4way_finish:
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q4, q7
	vbic.u32	q10, q5, q7
	vshr.u32	q11, q7, #5
	vorr.u32	q10, q10, q9
	vshl.u32	q12, q7, #32-5
	vadd.u32	q6, q6, q10
	veor.u32	q10, q7, q11
	vshr.u32	q11, q7, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q7, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q6, q6, q8
	veor.u32	q10, q10, q12
	vld1.u32	{q9}, [r3]!
	vadd.u32	q6, q6, q2
	vshr.u32	q11, q10, #6
	vadd.u32	q6, q6, q9
	vshl.u32	q13, q10, #32-6
	vadd.u32	q6, q6, q11
	vadd.u32	q6, q6, q13
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q7, q6
	vbic.u32	q10, q4, q6
	vshr.u32	q11, q6, #5
	vorr.u32	q10, q10, q9
	vshl.u32	q12, q6, #32-5
	vadd.u32	q5, q5, q10
	veor.u32	q10, q6, q11
	vshr.u32	q11, q6, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q6, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q5, q5, q8
	veor.u32	q10, q10, q12
	vld1.u32	{q9}, [r3]!
	vadd.u32	q5, q5, q1
	vshr.u32	q11, q10, #6
	vadd.u32	q5, q5, q9
	vshl.u32	q13, q10, #32-6
	vadd.u32	q5, q5, q11
	vadd.u32	q5, q5, q13
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q6, q5
	vbic.u32	q10, q7, q5
	vshr.u32	q11, q5, #5
	vorr.u32	q10, q10, q9
	vshl.u32	q12, q5, #32-5
	vadd.u32	q4, q4, q10
	veor.u32	q10, q5, q11
	vshr.u32	q11, q5, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q5, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q4, q4, q8
	veor.u32	q10, q10, q12
	vld1.u32	{q9}, [r3]!
	vadd.u32	q4, q4, q0
	vshr.u32	q11, q10, #6
	vadd.u32	q4, q4, q9
	vshl.u32	q13, q10, #32-6
	vadd.u32	q4, q4, q11
	vadd.u32	q4, q4, q13
	vld1.u32	{q8}, [r1]!
	vand.u32	q9, q5, q4
	vbic.u32	q10, q6, q4
	vshr.u32	q11, q4, #5
	vorr.u32	q10, q10, q9
	vshl.u32	q12, q4, #32-5
	vadd.u32	q7, q7, q10
	veor.u32	q10, q4, q11
	vshr.u32	q11, q4, #19
	veor.u32	q10, q10, q12
	vshl.u32	q12, q4, #32-19
	veor.u32	q10, q10, q11
	vadd.u32	q7, q7, q8
	veor.u32	q10, q10, q12
	vld1.u32	{q9}, [r3]!
	vadd.u32	q7, q7, q3
	vshr.u32	q11, q10, #6
	vadd.u32	q7, q7, q9
	vshl.u32	q13, q10, #32-6
	vadd.u32	q7, q7, q11
	vadd.u32	q7, q7, q13
	
	vadd.u32	q7, q7, q15
	add	r0, r0, #7*16
	vst1.u32	{q7}, [r0]
	
	mov	sp, r12
	vpop	{q4-q7}
	ldmfd	sp!, {r4, pc}


	.text
	.code 32
	.align 2
	.globl sha256_use_4way
	.globl _sha256_use_4way
#ifdef __ELF__
	.type sha256_use_4way, %function
#endif
sha256_use_4way:
_sha256_use_4way:
	mov	r0, #1
	bx	lr

#endif /* __ARM_NEON__ */

#endif
