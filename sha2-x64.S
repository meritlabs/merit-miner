/*
 * Copyright 2012-2015 pooler@litecoinpool.org
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"

#if defined(__linux__) && defined(__ELF__)
	.section .note.GNU-stack,"",%progbits
#endif

#if defined(USE_ASM) && defined(__x86_64__)

	.data
	.p2align 4
sha256_h:
	.long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	.long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	.data
	.p2align 6
sha256_k:
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

bswap_xmm_mask:
	.long 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f





	.text
	.p2align 6
sha256_transform_sse2:
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	pushq	%rsi
	subq	$5*16, %rsp
	movdqa	%xmm6, 1*16(%rsp)
	movdqa	%xmm7, 2*16(%rsp)
	movdqa	%xmm8, 3*16(%rsp)
	movdqa	%xmm9, 4*16(%rsp)
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#else
	subq	$16, %rsp
#endif
	
	movl	0*4(%rdi), %r8d
	movl	1*4(%rdi), %r9d
	movl	2*4(%rdi), %r10d
	movl	3*4(%rdi), %r11d
	movl	4*4(%rdi), %r12d
	movl	5*4(%rdi), %r13d
	movl	6*4(%rdi), %r14d
	movl	7*4(%rdi), %r15d
	
	testq	%rdx, %rdx
	jnz sha256_transform_sse2_swap
	
	movdqu	0*16(%rsi), %xmm0
	movdqu	1*16(%rsi), %xmm1
	movdqu	2*16(%rsi), %xmm2
	movdqu	3*16(%rsi), %xmm3
	jmp sha256_transform_sse2_core
	
sha256_transform_sse2_swap:
	movdqu	0*16(%rsi), %xmm0
	movdqu	1*16(%rsi), %xmm1
	movdqu	2*16(%rsi), %xmm2
	movdqu	3*16(%rsi), %xmm3
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm1, %xmm1
	pshuflw	$0xb1, %xmm2, %xmm2
	pshuflw	$0xb1, %xmm3, %xmm3
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm1, %xmm1
	pshufhw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm3, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm1, %xmm5
	movdqa	%xmm2, %xmm6
	movdqa	%xmm3, %xmm7
	psrlw	$8, %xmm4
	psrlw	$8, %xmm5
	psrlw	$8, %xmm6
	psrlw	$8, %xmm7
	psllw	$8, %xmm0
	psllw	$8, %xmm1
	psllw	$8, %xmm2
	psllw	$8, %xmm3
	pxor	%xmm4, %xmm0
	pxor	%xmm5, %xmm1
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	
sha256_transform_sse2_core:
	leaq	sha256_k(%rip), %rdx
	movq	$48, %rsi
	.p2align 4
sha256_transform_sse2_loop:
	movdqa	0*16(%rdx), %xmm9
	paddd	%xmm0, %xmm9
	movdqa	%xmm9, (%rsp)
	movdqa	%xmm3, %xmm4
	movl	%r12d, %eax
	movdqa	%xmm2, %xmm6
	rorl	$(25-11), %eax
	movl	%r8d, %ebx
	pslldq	$12, %xmm4
	rorl	$(22-13), %ebx
	psrldq	$4, %xmm6
	xorl	%r12d, %eax
	movl	%r13d, %ecx
	rorl	$(11-6), %eax
	pxor	%xmm6, %xmm4
	movdqa	%xmm1, %xmm5
	xorl	%r8d, %ebx
	xorl	%r14d, %ecx
	xorl	%r12d, %eax
	paddd	%xmm0, %xmm4
	movdqa	%xmm0, %xmm7
	andl	%r12d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r8d, %ebx
	pslldq	$12, %xmm5
	psrldq	$4, %xmm7
	rorl	$6, %eax
	xorl	%r14d, %ecx
	pxor	%xmm7, %xmm5
	rorl	$2, %ebx
	addl	%eax, %ecx
	addl	(%rsp) , %ecx
	movdqa	%xmm5, %xmm6
	movl	%r8d, %eax
	addl	%ecx, %r15d
	movl	%r8d, %ecx
	movdqa	%xmm5, %xmm7
	orl	%r10d, %eax
	addl	%r15d, %r11d
	andl	%r10d, %ecx
	pslld	$(32-7), %xmm5
	psrld	$7, %xmm6
	andl	%r9d, %eax
	addl	%ebx, %r15d
	orl	%ecx, %eax
	por	%xmm6, %xmm5
	addl	%eax, %r15d
	
	movl	%r11d, %eax
	movdqa	%xmm7, %xmm6
	movl	%r15d, %ebx
	rorl	$(25-11), %eax
	xorl	%r11d, %eax
	movdqa	%xmm7, %xmm8
	movl	%r12d, %ecx
	rorl	$(22-13), %ebx
	xorl	%r15d, %ebx
	pslld	$(32-18), %xmm7
	rorl	$(11-6), %eax
	xorl	%r13d, %ecx
	rorl	$(13-2), %ebx
	psrld	$18, %xmm6
	xorl	%r11d, %eax
	andl	%r11d, %ecx
	rorl	$6, %eax
	pxor	%xmm7, %xmm5
	xorl	%r15d, %ebx
	xorl	%r13d, %ecx
	psrld	$3, %xmm8
	addl	%eax, %ecx
	addl	1*4(%rsp), %ecx
	rorl	$2, %ebx
	pxor	%xmm6, %xmm5
	movl	%r15d, %eax
	addl	%ecx, %r14d
	movl	%r15d, %ecx
	pxor	%xmm8, %xmm5
	orl	%r9d, %eax
	addl	%r14d, %r10d
	andl	%r9d, %ecx
	pshufd	$0xfa, %xmm3, %xmm6
	andl	%r8d, %eax
	addl	%ebx, %r14d
	paddd	%xmm5, %xmm4
	orl	%ecx, %eax
	addl	%eax, %r14d
	
	movl	%r10d, %eax
	movdqa	%xmm6, %xmm7
	movl	%r14d, %ebx
	rorl	$(25-11), %eax
	xorl	%r10d, %eax
	movdqa	%xmm6, %xmm8
	rorl	$(22-13), %ebx
	movl	%r11d, %ecx
	xorl	%r14d, %ebx
	psrlq	$17, %xmm6
	psrlq	$19, %xmm7
	rorl	$(11-6), %eax
	xorl	%r12d, %ecx
	xorl	%r10d, %eax
	psrld	$10, %xmm8
	pxor	%xmm7, %xmm6
	andl	%r10d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r14d, %ebx
	pxor	%xmm6, %xmm8
	xorl	%r12d, %ecx
	rorl	$6, %eax
	addl	%eax, %ecx
	pshufd	$0x8f, %xmm8, %xmm8
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r14d, %eax
	psrldq	$8, %xmm8
	addl	%ecx, %r13d
	movl	%r14d, %ecx
	orl	%r8d, %eax
	paddd	%xmm8, %xmm4
	addl	%r13d, %r9d
	andl	%r8d, %ecx
	andl	%r15d, %eax
	pshufd	$0x50, %xmm4, %xmm6
	addl	%ebx, %r13d
	orl	%ecx, %eax
	addl	%eax, %r13d
	
	movdqa	%xmm6, %xmm7
	movl	%r9d, %eax
	rorl	$(25-11), %eax
	movl	%r13d, %ebx
	movdqa	%xmm6, %xmm0
	rorl	$(22-13), %ebx
	xorl	%r9d, %eax
	movl	%r10d, %ecx
	psrlq	$17, %xmm6
	rorl	$(11-6), %eax
	xorl	%r13d, %ebx
	xorl	%r11d, %ecx
	psrlq	$19, %xmm7
	xorl	%r9d, %eax
	andl	%r9d, %ecx
	rorl	$(13-2), %ebx
	psrld	$10, %xmm0
	xorl	%r13d, %ebx
	rorl	$6, %eax
	pxor	%xmm7, %xmm6
	xorl	%r11d, %ecx
	rorl	$2, %ebx
	addl	%eax, %ecx
	pxor	%xmm6, %xmm0
	addl	3*4(%rsp), %ecx
	movl	%r13d, %eax
	addl	%ecx, %r12d
	pshufd	$0xf8, %xmm0, %xmm0
	movl	%r13d, %ecx
	orl	%r15d, %eax
	addl	%r12d, %r8d
	pslldq	$8, %xmm0
	andl	%r15d, %ecx
	andl	%r14d, %eax
	paddd	%xmm4, %xmm0
	addl	%ebx, %r12d
	orl	%ecx, %eax
	addl	%eax, %r12d
	movdqa	1*16(%rdx), %xmm9
	paddd	%xmm1, %xmm9
	movdqa	%xmm9, (%rsp)
	movdqa	%xmm0, %xmm4
	movl	%r8d, %eax
	movdqa	%xmm3, %xmm6
	rorl	$(25-11), %eax
	movl	%r12d, %ebx
	pslldq	$12, %xmm4
	rorl	$(22-13), %ebx
	psrldq	$4, %xmm6
	xorl	%r8d, %eax
	movl	%r9d, %ecx
	rorl	$(11-6), %eax
	pxor	%xmm6, %xmm4
	movdqa	%xmm2, %xmm5
	xorl	%r12d, %ebx
	xorl	%r10d, %ecx
	xorl	%r8d, %eax
	paddd	%xmm1, %xmm4
	movdqa	%xmm1, %xmm7
	andl	%r8d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r12d, %ebx
	pslldq	$12, %xmm5
	psrldq	$4, %xmm7
	rorl	$6, %eax
	xorl	%r10d, %ecx
	pxor	%xmm7, %xmm5
	rorl	$2, %ebx
	addl	%eax, %ecx
	addl	(%rsp) , %ecx
	movdqa	%xmm5, %xmm6
	movl	%r12d, %eax
	addl	%ecx, %r11d
	movl	%r12d, %ecx
	movdqa	%xmm5, %xmm7
	orl	%r14d, %eax
	addl	%r11d, %r15d
	andl	%r14d, %ecx
	pslld	$(32-7), %xmm5
	psrld	$7, %xmm6
	andl	%r13d, %eax
	addl	%ebx, %r11d
	orl	%ecx, %eax
	por	%xmm6, %xmm5
	addl	%eax, %r11d
	
	movl	%r15d, %eax
	movdqa	%xmm7, %xmm6
	movl	%r11d, %ebx
	rorl	$(25-11), %eax
	xorl	%r15d, %eax
	movdqa	%xmm7, %xmm8
	movl	%r8d, %ecx
	rorl	$(22-13), %ebx
	xorl	%r11d, %ebx
	pslld	$(32-18), %xmm7
	rorl	$(11-6), %eax
	xorl	%r9d, %ecx
	rorl	$(13-2), %ebx
	psrld	$18, %xmm6
	xorl	%r15d, %eax
	andl	%r15d, %ecx
	rorl	$6, %eax
	pxor	%xmm7, %xmm5
	xorl	%r11d, %ebx
	xorl	%r9d, %ecx
	psrld	$3, %xmm8
	addl	%eax, %ecx
	addl	1*4(%rsp), %ecx
	rorl	$2, %ebx
	pxor	%xmm6, %xmm5
	movl	%r11d, %eax
	addl	%ecx, %r10d
	movl	%r11d, %ecx
	pxor	%xmm8, %xmm5
	orl	%r13d, %eax
	addl	%r10d, %r14d
	andl	%r13d, %ecx
	pshufd	$0xfa, %xmm0, %xmm6
	andl	%r12d, %eax
	addl	%ebx, %r10d
	paddd	%xmm5, %xmm4
	orl	%ecx, %eax
	addl	%eax, %r10d
	
	movl	%r14d, %eax
	movdqa	%xmm6, %xmm7
	movl	%r10d, %ebx
	rorl	$(25-11), %eax
	xorl	%r14d, %eax
	movdqa	%xmm6, %xmm8
	rorl	$(22-13), %ebx
	movl	%r15d, %ecx
	xorl	%r10d, %ebx
	psrlq	$17, %xmm6
	psrlq	$19, %xmm7
	rorl	$(11-6), %eax
	xorl	%r8d, %ecx
	xorl	%r14d, %eax
	psrld	$10, %xmm8
	pxor	%xmm7, %xmm6
	andl	%r14d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r10d, %ebx
	pxor	%xmm6, %xmm8
	xorl	%r8d, %ecx
	rorl	$6, %eax
	addl	%eax, %ecx
	pshufd	$0x8f, %xmm8, %xmm8
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r10d, %eax
	psrldq	$8, %xmm8
	addl	%ecx, %r9d
	movl	%r10d, %ecx
	orl	%r12d, %eax
	paddd	%xmm8, %xmm4
	addl	%r9d, %r13d
	andl	%r12d, %ecx
	andl	%r11d, %eax
	pshufd	$0x50, %xmm4, %xmm6
	addl	%ebx, %r9d
	orl	%ecx, %eax
	addl	%eax, %r9d
	
	movdqa	%xmm6, %xmm7
	movl	%r13d, %eax
	rorl	$(25-11), %eax
	movl	%r9d, %ebx
	movdqa	%xmm6, %xmm1
	rorl	$(22-13), %ebx
	xorl	%r13d, %eax
	movl	%r14d, %ecx
	psrlq	$17, %xmm6
	rorl	$(11-6), %eax
	xorl	%r9d, %ebx
	xorl	%r15d, %ecx
	psrlq	$19, %xmm7
	xorl	%r13d, %eax
	andl	%r13d, %ecx
	rorl	$(13-2), %ebx
	psrld	$10, %xmm1
	xorl	%r9d, %ebx
	rorl	$6, %eax
	pxor	%xmm7, %xmm6
	xorl	%r15d, %ecx
	rorl	$2, %ebx
	addl	%eax, %ecx
	pxor	%xmm6, %xmm1
	addl	3*4(%rsp), %ecx
	movl	%r9d, %eax
	addl	%ecx, %r8d
	pshufd	$0xf8, %xmm1, %xmm1
	movl	%r9d, %ecx
	orl	%r11d, %eax
	addl	%r8d, %r12d
	pslldq	$8, %xmm1
	andl	%r11d, %ecx
	andl	%r10d, %eax
	paddd	%xmm4, %xmm1
	addl	%ebx, %r8d
	orl	%ecx, %eax
	addl	%eax, %r8d
	movdqa	2*16(%rdx), %xmm9
	paddd	%xmm2, %xmm9
	movdqa	%xmm9, (%rsp)
	movdqa	%xmm1, %xmm4
	movl	%r12d, %eax
	movdqa	%xmm0, %xmm6
	rorl	$(25-11), %eax
	movl	%r8d, %ebx
	pslldq	$12, %xmm4
	rorl	$(22-13), %ebx
	psrldq	$4, %xmm6
	xorl	%r12d, %eax
	movl	%r13d, %ecx
	rorl	$(11-6), %eax
	pxor	%xmm6, %xmm4
	movdqa	%xmm3, %xmm5
	xorl	%r8d, %ebx
	xorl	%r14d, %ecx
	xorl	%r12d, %eax
	paddd	%xmm2, %xmm4
	movdqa	%xmm2, %xmm7
	andl	%r12d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r8d, %ebx
	pslldq	$12, %xmm5
	psrldq	$4, %xmm7
	rorl	$6, %eax
	xorl	%r14d, %ecx
	pxor	%xmm7, %xmm5
	rorl	$2, %ebx
	addl	%eax, %ecx
	addl	(%rsp) , %ecx
	movdqa	%xmm5, %xmm6
	movl	%r8d, %eax
	addl	%ecx, %r15d
	movl	%r8d, %ecx
	movdqa	%xmm5, %xmm7
	orl	%r10d, %eax
	addl	%r15d, %r11d
	andl	%r10d, %ecx
	pslld	$(32-7), %xmm5
	psrld	$7, %xmm6
	andl	%r9d, %eax
	addl	%ebx, %r15d
	orl	%ecx, %eax
	por	%xmm6, %xmm5
	addl	%eax, %r15d
	
	movl	%r11d, %eax
	movdqa	%xmm7, %xmm6
	movl	%r15d, %ebx
	rorl	$(25-11), %eax
	xorl	%r11d, %eax
	movdqa	%xmm7, %xmm8
	movl	%r12d, %ecx
	rorl	$(22-13), %ebx
	xorl	%r15d, %ebx
	pslld	$(32-18), %xmm7
	rorl	$(11-6), %eax
	xorl	%r13d, %ecx
	rorl	$(13-2), %ebx
	psrld	$18, %xmm6
	xorl	%r11d, %eax
	andl	%r11d, %ecx
	rorl	$6, %eax
	pxor	%xmm7, %xmm5
	xorl	%r15d, %ebx
	xorl	%r13d, %ecx
	psrld	$3, %xmm8
	addl	%eax, %ecx
	addl	1*4(%rsp), %ecx
	rorl	$2, %ebx
	pxor	%xmm6, %xmm5
	movl	%r15d, %eax
	addl	%ecx, %r14d
	movl	%r15d, %ecx
	pxor	%xmm8, %xmm5
	orl	%r9d, %eax
	addl	%r14d, %r10d
	andl	%r9d, %ecx
	pshufd	$0xfa, %xmm1, %xmm6
	andl	%r8d, %eax
	addl	%ebx, %r14d
	paddd	%xmm5, %xmm4
	orl	%ecx, %eax
	addl	%eax, %r14d
	
	movl	%r10d, %eax
	movdqa	%xmm6, %xmm7
	movl	%r14d, %ebx
	rorl	$(25-11), %eax
	xorl	%r10d, %eax
	movdqa	%xmm6, %xmm8
	rorl	$(22-13), %ebx
	movl	%r11d, %ecx
	xorl	%r14d, %ebx
	psrlq	$17, %xmm6
	psrlq	$19, %xmm7
	rorl	$(11-6), %eax
	xorl	%r12d, %ecx
	xorl	%r10d, %eax
	psrld	$10, %xmm8
	pxor	%xmm7, %xmm6
	andl	%r10d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r14d, %ebx
	pxor	%xmm6, %xmm8
	xorl	%r12d, %ecx
	rorl	$6, %eax
	addl	%eax, %ecx
	pshufd	$0x8f, %xmm8, %xmm8
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r14d, %eax
	psrldq	$8, %xmm8
	addl	%ecx, %r13d
	movl	%r14d, %ecx
	orl	%r8d, %eax
	paddd	%xmm8, %xmm4
	addl	%r13d, %r9d
	andl	%r8d, %ecx
	andl	%r15d, %eax
	pshufd	$0x50, %xmm4, %xmm6
	addl	%ebx, %r13d
	orl	%ecx, %eax
	addl	%eax, %r13d
	
	movdqa	%xmm6, %xmm7
	movl	%r9d, %eax
	rorl	$(25-11), %eax
	movl	%r13d, %ebx
	movdqa	%xmm6, %xmm2
	rorl	$(22-13), %ebx
	xorl	%r9d, %eax
	movl	%r10d, %ecx
	psrlq	$17, %xmm6
	rorl	$(11-6), %eax
	xorl	%r13d, %ebx
	xorl	%r11d, %ecx
	psrlq	$19, %xmm7
	xorl	%r9d, %eax
	andl	%r9d, %ecx
	rorl	$(13-2), %ebx
	psrld	$10, %xmm2
	xorl	%r13d, %ebx
	rorl	$6, %eax
	pxor	%xmm7, %xmm6
	xorl	%r11d, %ecx
	rorl	$2, %ebx
	addl	%eax, %ecx
	pxor	%xmm6, %xmm2
	addl	3*4(%rsp), %ecx
	movl	%r13d, %eax
	addl	%ecx, %r12d
	pshufd	$0xf8, %xmm2, %xmm2
	movl	%r13d, %ecx
	orl	%r15d, %eax
	addl	%r12d, %r8d
	pslldq	$8, %xmm2
	andl	%r15d, %ecx
	andl	%r14d, %eax
	paddd	%xmm4, %xmm2
	addl	%ebx, %r12d
	orl	%ecx, %eax
	addl	%eax, %r12d
	movdqa	3*16(%rdx), %xmm9
	paddd	%xmm3, %xmm9
	movdqa	%xmm9, (%rsp)
	addq	$4*16, %rdx
	movdqa	%xmm2, %xmm4
	movl	%r8d, %eax
	movdqa	%xmm1, %xmm6
	rorl	$(25-11), %eax
	movl	%r12d, %ebx
	pslldq	$12, %xmm4
	rorl	$(22-13), %ebx
	psrldq	$4, %xmm6
	xorl	%r8d, %eax
	movl	%r9d, %ecx
	rorl	$(11-6), %eax
	pxor	%xmm6, %xmm4
	movdqa	%xmm0, %xmm5
	xorl	%r12d, %ebx
	xorl	%r10d, %ecx
	xorl	%r8d, %eax
	paddd	%xmm3, %xmm4
	movdqa	%xmm3, %xmm7
	andl	%r8d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r12d, %ebx
	pslldq	$12, %xmm5
	psrldq	$4, %xmm7
	rorl	$6, %eax
	xorl	%r10d, %ecx
	pxor	%xmm7, %xmm5
	rorl	$2, %ebx
	addl	%eax, %ecx
	addl	(%rsp) , %ecx
	movdqa	%xmm5, %xmm6
	movl	%r12d, %eax
	addl	%ecx, %r11d
	movl	%r12d, %ecx
	movdqa	%xmm5, %xmm7
	orl	%r14d, %eax
	addl	%r11d, %r15d
	andl	%r14d, %ecx
	pslld	$(32-7), %xmm5
	psrld	$7, %xmm6
	andl	%r13d, %eax
	addl	%ebx, %r11d
	orl	%ecx, %eax
	por	%xmm6, %xmm5
	addl	%eax, %r11d
	
	movl	%r15d, %eax
	movdqa	%xmm7, %xmm6
	movl	%r11d, %ebx
	rorl	$(25-11), %eax
	xorl	%r15d, %eax
	movdqa	%xmm7, %xmm8
	movl	%r8d, %ecx
	rorl	$(22-13), %ebx
	xorl	%r11d, %ebx
	pslld	$(32-18), %xmm7
	rorl	$(11-6), %eax
	xorl	%r9d, %ecx
	rorl	$(13-2), %ebx
	psrld	$18, %xmm6
	xorl	%r15d, %eax
	andl	%r15d, %ecx
	rorl	$6, %eax
	pxor	%xmm7, %xmm5
	xorl	%r11d, %ebx
	xorl	%r9d, %ecx
	psrld	$3, %xmm8
	addl	%eax, %ecx
	addl	1*4(%rsp), %ecx
	rorl	$2, %ebx
	pxor	%xmm6, %xmm5
	movl	%r11d, %eax
	addl	%ecx, %r10d
	movl	%r11d, %ecx
	pxor	%xmm8, %xmm5
	orl	%r13d, %eax
	addl	%r10d, %r14d
	andl	%r13d, %ecx
	pshufd	$0xfa, %xmm2, %xmm6
	andl	%r12d, %eax
	addl	%ebx, %r10d
	paddd	%xmm5, %xmm4
	orl	%ecx, %eax
	addl	%eax, %r10d
	
	movl	%r14d, %eax
	movdqa	%xmm6, %xmm7
	movl	%r10d, %ebx
	rorl	$(25-11), %eax
	xorl	%r14d, %eax
	movdqa	%xmm6, %xmm8
	rorl	$(22-13), %ebx
	movl	%r15d, %ecx
	xorl	%r10d, %ebx
	psrlq	$17, %xmm6
	psrlq	$19, %xmm7
	rorl	$(11-6), %eax
	xorl	%r8d, %ecx
	xorl	%r14d, %eax
	psrld	$10, %xmm8
	pxor	%xmm7, %xmm6
	andl	%r14d, %ecx
	rorl	$(13-2), %ebx
	xorl	%r10d, %ebx
	pxor	%xmm6, %xmm8
	xorl	%r8d, %ecx
	rorl	$6, %eax
	addl	%eax, %ecx
	pshufd	$0x8f, %xmm8, %xmm8
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r10d, %eax
	psrldq	$8, %xmm8
	addl	%ecx, %r9d
	movl	%r10d, %ecx
	orl	%r12d, %eax
	paddd	%xmm8, %xmm4
	addl	%r9d, %r13d
	andl	%r12d, %ecx
	andl	%r11d, %eax
	pshufd	$0x50, %xmm4, %xmm6
	addl	%ebx, %r9d
	orl	%ecx, %eax
	addl	%eax, %r9d
	
	movdqa	%xmm6, %xmm7
	movl	%r13d, %eax
	rorl	$(25-11), %eax
	movl	%r9d, %ebx
	movdqa	%xmm6, %xmm3
	rorl	$(22-13), %ebx
	xorl	%r13d, %eax
	movl	%r14d, %ecx
	psrlq	$17, %xmm6
	rorl	$(11-6), %eax
	xorl	%r9d, %ebx
	xorl	%r15d, %ecx
	psrlq	$19, %xmm7
	xorl	%r13d, %eax
	andl	%r13d, %ecx
	rorl	$(13-2), %ebx
	psrld	$10, %xmm3
	xorl	%r9d, %ebx
	rorl	$6, %eax
	pxor	%xmm7, %xmm6
	xorl	%r15d, %ecx
	rorl	$2, %ebx
	addl	%eax, %ecx
	pxor	%xmm6, %xmm3
	addl	3*4(%rsp), %ecx
	movl	%r9d, %eax
	addl	%ecx, %r8d
	pshufd	$0xf8, %xmm3, %xmm3
	movl	%r9d, %ecx
	orl	%r11d, %eax
	addl	%r8d, %r12d
	pslldq	$8, %xmm3
	andl	%r11d, %ecx
	andl	%r10d, %eax
	paddd	%xmm4, %xmm3
	addl	%ebx, %r8d
	orl	%ecx, %eax
	addl	%eax, %r8d
	
	subq	$16, %rsi
	jne sha256_transform_sse2_loop
	
	paddd	0*16(%rdx), %xmm0
	movdqa	%xmm0, (%rsp)
	movl	%r12d, %eax
	rorl	$(25-11), %eax
	movl	%r8d, %ebx
	xorl	%r12d, %eax
	rorl	$(22-13), %ebx
	movl	%r13d, %ecx
	xorl	%r8d, %ebx
	rorl	$(11-6), %eax
	xorl	%r14d, %ecx
	xorl	%r12d, %eax
	rorl	$(13-2), %ebx
	andl	%r12d, %ecx
	xorl	%r8d, %ebx
	rorl	$6, %eax
	xorl	%r14d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	0*4(%rsp), %ecx
	movl	%r8d, %eax
	addl	%ecx, %r15d
	movl	%r8d, %ecx
	orl	%r10d, %eax
	addl	%r15d, %r11d
	andl	%r10d, %ecx
	andl	%r9d, %eax
	addl	%ebx, %r15d
	orl	%ecx, %eax
	addl	%eax, %r15d
	movl	%r11d, %eax
	rorl	$(25-11), %eax
	movl	%r15d, %ebx
	xorl	%r11d, %eax
	rorl	$(22-13), %ebx
	movl	%r12d, %ecx
	xorl	%r15d, %ebx
	rorl	$(11-6), %eax
	xorl	%r13d, %ecx
	xorl	%r11d, %eax
	rorl	$(13-2), %ebx
	andl	%r11d, %ecx
	xorl	%r15d, %ebx
	rorl	$6, %eax
	xorl	%r13d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	1*4(%rsp), %ecx
	movl	%r15d, %eax
	addl	%ecx, %r14d
	movl	%r15d, %ecx
	orl	%r9d, %eax
	addl	%r14d, %r10d
	andl	%r9d, %ecx
	andl	%r8d, %eax
	addl	%ebx, %r14d
	orl	%ecx, %eax
	addl	%eax, %r14d
	movl	%r10d, %eax
	rorl	$(25-11), %eax
	movl	%r14d, %ebx
	xorl	%r10d, %eax
	rorl	$(22-13), %ebx
	movl	%r11d, %ecx
	xorl	%r14d, %ebx
	rorl	$(11-6), %eax
	xorl	%r12d, %ecx
	xorl	%r10d, %eax
	rorl	$(13-2), %ebx
	andl	%r10d, %ecx
	xorl	%r14d, %ebx
	rorl	$6, %eax
	xorl	%r12d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r14d, %eax
	addl	%ecx, %r13d
	movl	%r14d, %ecx
	orl	%r8d, %eax
	addl	%r13d, %r9d
	andl	%r8d, %ecx
	andl	%r15d, %eax
	addl	%ebx, %r13d
	orl	%ecx, %eax
	addl	%eax, %r13d
	movl	%r9d, %eax
	rorl	$(25-11), %eax
	movl	%r13d, %ebx
	xorl	%r9d, %eax
	rorl	$(22-13), %ebx
	movl	%r10d, %ecx
	xorl	%r13d, %ebx
	rorl	$(11-6), %eax
	xorl	%r11d, %ecx
	xorl	%r9d, %eax
	rorl	$(13-2), %ebx
	andl	%r9d, %ecx
	xorl	%r13d, %ebx
	rorl	$6, %eax
	xorl	%r11d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	3*4(%rsp), %ecx
	movl	%r13d, %eax
	addl	%ecx, %r12d
	movl	%r13d, %ecx
	orl	%r15d, %eax
	addl	%r12d, %r8d
	andl	%r15d, %ecx
	andl	%r14d, %eax
	addl	%ebx, %r12d
	orl	%ecx, %eax
	addl	%eax, %r12d
	paddd	1*16(%rdx), %xmm1
	movdqa	%xmm1, (%rsp)
	movl	%r8d, %eax
	rorl	$(25-11), %eax
	movl	%r12d, %ebx
	xorl	%r8d, %eax
	rorl	$(22-13), %ebx
	movl	%r9d, %ecx
	xorl	%r12d, %ebx
	rorl	$(11-6), %eax
	xorl	%r10d, %ecx
	xorl	%r8d, %eax
	rorl	$(13-2), %ebx
	andl	%r8d, %ecx
	xorl	%r12d, %ebx
	rorl	$6, %eax
	xorl	%r10d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	0*4(%rsp), %ecx
	movl	%r12d, %eax
	addl	%ecx, %r11d
	movl	%r12d, %ecx
	orl	%r14d, %eax
	addl	%r11d, %r15d
	andl	%r14d, %ecx
	andl	%r13d, %eax
	addl	%ebx, %r11d
	orl	%ecx, %eax
	addl	%eax, %r11d
	movl	%r15d, %eax
	rorl	$(25-11), %eax
	movl	%r11d, %ebx
	xorl	%r15d, %eax
	rorl	$(22-13), %ebx
	movl	%r8d, %ecx
	xorl	%r11d, %ebx
	rorl	$(11-6), %eax
	xorl	%r9d, %ecx
	xorl	%r15d, %eax
	rorl	$(13-2), %ebx
	andl	%r15d, %ecx
	xorl	%r11d, %ebx
	rorl	$6, %eax
	xorl	%r9d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	1*4(%rsp), %ecx
	movl	%r11d, %eax
	addl	%ecx, %r10d
	movl	%r11d, %ecx
	orl	%r13d, %eax
	addl	%r10d, %r14d
	andl	%r13d, %ecx
	andl	%r12d, %eax
	addl	%ebx, %r10d
	orl	%ecx, %eax
	addl	%eax, %r10d
	movl	%r14d, %eax
	rorl	$(25-11), %eax
	movl	%r10d, %ebx
	xorl	%r14d, %eax
	rorl	$(22-13), %ebx
	movl	%r15d, %ecx
	xorl	%r10d, %ebx
	rorl	$(11-6), %eax
	xorl	%r8d, %ecx
	xorl	%r14d, %eax
	rorl	$(13-2), %ebx
	andl	%r14d, %ecx
	xorl	%r10d, %ebx
	rorl	$6, %eax
	xorl	%r8d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r10d, %eax
	addl	%ecx, %r9d
	movl	%r10d, %ecx
	orl	%r12d, %eax
	addl	%r9d, %r13d
	andl	%r12d, %ecx
	andl	%r11d, %eax
	addl	%ebx, %r9d
	orl	%ecx, %eax
	addl	%eax, %r9d
	movl	%r13d, %eax
	rorl	$(25-11), %eax
	movl	%r9d, %ebx
	xorl	%r13d, %eax
	rorl	$(22-13), %ebx
	movl	%r14d, %ecx
	xorl	%r9d, %ebx
	rorl	$(11-6), %eax
	xorl	%r15d, %ecx
	xorl	%r13d, %eax
	rorl	$(13-2), %ebx
	andl	%r13d, %ecx
	xorl	%r9d, %ebx
	rorl	$6, %eax
	xorl	%r15d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	3*4(%rsp), %ecx
	movl	%r9d, %eax
	addl	%ecx, %r8d
	movl	%r9d, %ecx
	orl	%r11d, %eax
	addl	%r8d, %r12d
	andl	%r11d, %ecx
	andl	%r10d, %eax
	addl	%ebx, %r8d
	orl	%ecx, %eax
	addl	%eax, %r8d
	paddd	2*16(%rdx), %xmm2
	movdqa	%xmm2, (%rsp)
	movl	%r12d, %eax
	rorl	$(25-11), %eax
	movl	%r8d, %ebx
	xorl	%r12d, %eax
	rorl	$(22-13), %ebx
	movl	%r13d, %ecx
	xorl	%r8d, %ebx
	rorl	$(11-6), %eax
	xorl	%r14d, %ecx
	xorl	%r12d, %eax
	rorl	$(13-2), %ebx
	andl	%r12d, %ecx
	xorl	%r8d, %ebx
	rorl	$6, %eax
	xorl	%r14d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	0*4(%rsp), %ecx
	movl	%r8d, %eax
	addl	%ecx, %r15d
	movl	%r8d, %ecx
	orl	%r10d, %eax
	addl	%r15d, %r11d
	andl	%r10d, %ecx
	andl	%r9d, %eax
	addl	%ebx, %r15d
	orl	%ecx, %eax
	addl	%eax, %r15d
	movl	%r11d, %eax
	rorl	$(25-11), %eax
	movl	%r15d, %ebx
	xorl	%r11d, %eax
	rorl	$(22-13), %ebx
	movl	%r12d, %ecx
	xorl	%r15d, %ebx
	rorl	$(11-6), %eax
	xorl	%r13d, %ecx
	xorl	%r11d, %eax
	rorl	$(13-2), %ebx
	andl	%r11d, %ecx
	xorl	%r15d, %ebx
	rorl	$6, %eax
	xorl	%r13d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	1*4(%rsp), %ecx
	movl	%r15d, %eax
	addl	%ecx, %r14d
	movl	%r15d, %ecx
	orl	%r9d, %eax
	addl	%r14d, %r10d
	andl	%r9d, %ecx
	andl	%r8d, %eax
	addl	%ebx, %r14d
	orl	%ecx, %eax
	addl	%eax, %r14d
	movl	%r10d, %eax
	rorl	$(25-11), %eax
	movl	%r14d, %ebx
	xorl	%r10d, %eax
	rorl	$(22-13), %ebx
	movl	%r11d, %ecx
	xorl	%r14d, %ebx
	rorl	$(11-6), %eax
	xorl	%r12d, %ecx
	xorl	%r10d, %eax
	rorl	$(13-2), %ebx
	andl	%r10d, %ecx
	xorl	%r14d, %ebx
	rorl	$6, %eax
	xorl	%r12d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r14d, %eax
	addl	%ecx, %r13d
	movl	%r14d, %ecx
	orl	%r8d, %eax
	addl	%r13d, %r9d
	andl	%r8d, %ecx
	andl	%r15d, %eax
	addl	%ebx, %r13d
	orl	%ecx, %eax
	addl	%eax, %r13d
	movl	%r9d, %eax
	rorl	$(25-11), %eax
	movl	%r13d, %ebx
	xorl	%r9d, %eax
	rorl	$(22-13), %ebx
	movl	%r10d, %ecx
	xorl	%r13d, %ebx
	rorl	$(11-6), %eax
	xorl	%r11d, %ecx
	xorl	%r9d, %eax
	rorl	$(13-2), %ebx
	andl	%r9d, %ecx
	xorl	%r13d, %ebx
	rorl	$6, %eax
	xorl	%r11d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	3*4(%rsp), %ecx
	movl	%r13d, %eax
	addl	%ecx, %r12d
	movl	%r13d, %ecx
	orl	%r15d, %eax
	addl	%r12d, %r8d
	andl	%r15d, %ecx
	andl	%r14d, %eax
	addl	%ebx, %r12d
	orl	%ecx, %eax
	addl	%eax, %r12d
	paddd	3*16(%rdx), %xmm3
	movdqa	%xmm3, (%rsp)
	movl	%r8d, %eax
	rorl	$(25-11), %eax
	movl	%r12d, %ebx
	xorl	%r8d, %eax
	rorl	$(22-13), %ebx
	movl	%r9d, %ecx
	xorl	%r12d, %ebx
	rorl	$(11-6), %eax
	xorl	%r10d, %ecx
	xorl	%r8d, %eax
	rorl	$(13-2), %ebx
	andl	%r8d, %ecx
	xorl	%r12d, %ebx
	rorl	$6, %eax
	xorl	%r10d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	0*4(%rsp), %ecx
	movl	%r12d, %eax
	addl	%ecx, %r11d
	movl	%r12d, %ecx
	orl	%r14d, %eax
	addl	%r11d, %r15d
	andl	%r14d, %ecx
	andl	%r13d, %eax
	addl	%ebx, %r11d
	orl	%ecx, %eax
	addl	%eax, %r11d
	movl	%r15d, %eax
	rorl	$(25-11), %eax
	movl	%r11d, %ebx
	xorl	%r15d, %eax
	rorl	$(22-13), %ebx
	movl	%r8d, %ecx
	xorl	%r11d, %ebx
	rorl	$(11-6), %eax
	xorl	%r9d, %ecx
	xorl	%r15d, %eax
	rorl	$(13-2), %ebx
	andl	%r15d, %ecx
	xorl	%r11d, %ebx
	rorl	$6, %eax
	xorl	%r9d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	1*4(%rsp), %ecx
	movl	%r11d, %eax
	addl	%ecx, %r10d
	movl	%r11d, %ecx
	orl	%r13d, %eax
	addl	%r10d, %r14d
	andl	%r13d, %ecx
	andl	%r12d, %eax
	addl	%ebx, %r10d
	orl	%ecx, %eax
	addl	%eax, %r10d
	movl	%r14d, %eax
	rorl	$(25-11), %eax
	movl	%r10d, %ebx
	xorl	%r14d, %eax
	rorl	$(22-13), %ebx
	movl	%r15d, %ecx
	xorl	%r10d, %ebx
	rorl	$(11-6), %eax
	xorl	%r8d, %ecx
	xorl	%r14d, %eax
	rorl	$(13-2), %ebx
	andl	%r14d, %ecx
	xorl	%r10d, %ebx
	rorl	$6, %eax
	xorl	%r8d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	2*4(%rsp), %ecx
	movl	%r10d, %eax
	addl	%ecx, %r9d
	movl	%r10d, %ecx
	orl	%r12d, %eax
	addl	%r9d, %r13d
	andl	%r12d, %ecx
	andl	%r11d, %eax
	addl	%ebx, %r9d
	orl	%ecx, %eax
	addl	%eax, %r9d
	movl	%r13d, %eax
	rorl	$(25-11), %eax
	movl	%r9d, %ebx
	xorl	%r13d, %eax
	rorl	$(22-13), %ebx
	movl	%r14d, %ecx
	xorl	%r9d, %ebx
	rorl	$(11-6), %eax
	xorl	%r15d, %ecx
	xorl	%r13d, %eax
	rorl	$(13-2), %ebx
	andl	%r13d, %ecx
	xorl	%r9d, %ebx
	rorl	$6, %eax
	xorl	%r15d, %ecx
	addl	%eax, %ecx
	rorl	$2, %ebx
	addl	3*4(%rsp), %ecx
	movl	%r9d, %eax
	addl	%ecx, %r8d
	movl	%r9d, %ecx
	orl	%r11d, %eax
	addl	%r8d, %r12d
	andl	%r11d, %ecx
	andl	%r10d, %eax
	addl	%ebx, %r8d
	orl	%ecx, %eax
	addl	%eax, %r8d
	
	addl	%r8d, 0*4(%rdi)
	addl	%r9d, 1*4(%rdi)
	addl	%r10d, 2*4(%rdi)
	addl	%r11d, 3*4(%rdi)
	addl	%r12d, 4*4(%rdi)
	addl	%r13d, 5*4(%rdi)
	addl	%r14d, 6*4(%rdi)
	addl	%r15d, 7*4(%rdi)
	
#if defined(_WIN64) || defined(__CYGWIN__)
	movdqa	1*16(%rsp), %xmm6
	movdqa	2*16(%rsp), %xmm7
	movdqa	3*16(%rsp), %xmm8
	movdqa	4*16(%rsp), %xmm9
	addq	$5*16, %rsp
	popq	%rsi
	popq	%rdi
#else
	addq	$16, %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	ret


	.text
	.p2align 6
sha256_transform_phe:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	movq	%rsp, %r8
	subq	$64, %rsp
	andq	$-64, %rsp
	
	testq	%rdx, %rdx
	jnz sha256_transform_phe_noswap
	
	movl	0*4(%rsi), %eax
	movl	1*4(%rsi), %ecx
	movl	2*4(%rsi), %edx
	movl	3*4(%rsi), %r9d
	bswapl	%eax
	bswapl	%ecx
	bswapl	%edx
	bswapl	%r9d
	movl	%eax, 0*4(%rsp)
	movl	%ecx, 1*4(%rsp)
	movl	%edx, 2*4(%rsp)
	movl	%r9d, 3*4(%rsp)
	movl	4*4(%rsi), %eax
	movl	5*4(%rsi), %ecx
	movl	6*4(%rsi), %edx
	movl	7*4(%rsi), %r9d
	bswapl	%eax
	bswapl	%ecx
	bswapl	%edx
	bswapl	%r9d
	movl	%eax, 4*4(%rsp)
	movl	%ecx, 5*4(%rsp)
	movl	%edx, 6*4(%rsp)
	movl	%r9d, 7*4(%rsp)
	
	movdqu	2*16(%rsi), %xmm0
	movdqu	3*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 2*16(%rsp)
	movdqa	%xmm2, 3*16(%rsp)
	
	jmp sha256_transform_phe_core
	
sha256_transform_phe_noswap:
	movdqu	0*16(%rsi), %xmm0
	movdqu	1*16(%rsi), %xmm1
	movdqu	2*16(%rsi), %xmm2
	movdqu	3*16(%rsi), %xmm3
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
	movdqa	%xmm3, 3*16(%rsp)
	
sha256_transform_phe_core:
	movq	%rsp, %rsi
	movq	$-1, %rax
	movq	$1, %rcx
	/* rep xsha256 */
	.byte 0xf3, 0x0f, 0xa6, 0xd0
	
	movq	%r8, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
#endif
	ret
	
	
	.data
	.p2align 3
sha256_transform_addr:
	.quad sha256_transform_sse2
	
	.text
	.p2align 3
	.globl sha256_transform
	.globl _sha256_transform
sha256_transform:
_sha256_transform:
	jmp *sha256_transform_addr(%rip)


	.text
	.p2align 6
	.globl sha256d_ms
	.globl _sha256d_ms
sha256d_ms:
_sha256d_ms:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	movq	%rsp, %r8
	subq	$32, %rsp
	andq	$-32, %rsp
	
	movdqa	0*16(%rdx), %xmm0
	movdqa	1*16(%rdx), %xmm1
	movdqa	%xmm0, 0*16(%rdi)
	movdqa	%xmm1, 1*16(%rdi)
	
	movl	0*4(%rsi), %eax
	movl	1*4(%rsi), %ecx
	movl	2*4(%rsi), %edx
	movl	3*4(%rsi), %r9d
	bswapl	%eax
	bswapl	%ecx
	bswapl	%edx
	bswapl	%r9d
	movl	%eax, 0*4(%rsp)
	movl	%ecx, 1*4(%rsp)
	movl	%edx, 2*4(%rsp)
	movl	%r9d, 3*4(%rsp)
	
	movq	%rsp, %rsi
	movl	$64, %eax
	movl	$80, %ecx
	/* rep xsha256 */
	.byte 0xf3, 0x0f, 0xa6, 0xd0
	
	movdqa	bswap_xmm_mask(%rip), %xmm1
	movdqa	0*16(%rdi), %xmm0
	movdqa	1*16(%rdi), %xmm2
	pshufb	%xmm1, %xmm0
	pshufb	%xmm1, %xmm2
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm2, 1*16(%rsp)
	
	movdqa	sha256_h+0*16(%rip), %xmm0
	movdqa	sha256_h+1*16(%rip), %xmm1
	movdqa	%xmm0, 0*16(%rdi)
	movdqa	%xmm1, 1*16(%rdi)
	
	movq	%rsp, %rsi
	xorq	%rax, %rax
	movl	$32, %ecx
	/* rep xsha256 */
	.byte 0xf3, 0x0f, 0xa6, 0xd0
	
	movq	%r8, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
#endif
	ret


	.data
	.p2align 7
sha256_4h:
	.long 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667
	.long 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85
	.long 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372
	.long 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a
	.long 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f
	.long 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c
	.long 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab
	.long 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19

	.data
	.p2align 7
sha256_4k:
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

	.data
	.p2align 6
sha256d_4preext2_17:
	.long 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000
sha256d_4preext2_23:
	.long 0x11002000, 0x11002000, 0x11002000, 0x11002000
sha256d_4preext2_24:
	.long 0x80000000, 0x80000000, 0x80000000, 0x80000000
sha256d_4preext2_30:
	.long 0x00400022, 0x00400022, 0x00400022, 0x00400022


#ifdef USE_AVX2

	.data
	.p2align 7
sha256_8h:
	.long 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667
	.long 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85
	.long 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372
	.long 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a
	.long 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f
	.long 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c
	.long 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab
	.long 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19

	.data
	.p2align 7
sha256_8k:
	.long 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98
	.long 0x71374491, 0x71374491, 0x71374491, 0x71374491, 0x71374491, 0x71374491, 0x71374491, 0x71374491
	.long 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf
	.long 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5
	.long 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b
	.long 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1
	.long 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4
	.long 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5
	.long 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98
	.long 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01
	.long 0x243185be, 0x243185be, 0x243185be, 0x243185be, 0x243185be, 0x243185be, 0x243185be, 0x243185be
	.long 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3
	.long 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74
	.long 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe
	.long 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7
	.long 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174
	.long 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1
	.long 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786
	.long 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6
	.long 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc
	.long 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f
	.long 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa
	.long 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc
	.long 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da
	.long 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152
	.long 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d
	.long 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8
	.long 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7
	.long 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3
	.long 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147
	.long 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351
	.long 0x14292967, 0x14292967, 0x14292967, 0x14292967, 0x14292967, 0x14292967, 0x14292967, 0x14292967
	.long 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85
	.long 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138
	.long 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc
	.long 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13
	.long 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354
	.long 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb
	.long 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e
	.long 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85
	.long 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1
	.long 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b
	.long 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70
	.long 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3
	.long 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819
	.long 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624
	.long 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585
	.long 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070
	.long 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116
	.long 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08
	.long 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c
	.long 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5
	.long 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3
	.long 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a
	.long 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f
	.long 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3
	.long 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee
	.long 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f
	.long 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814
	.long 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208
	.long 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa
	.long 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb
	.long 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7
	.long 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2

	.data
	.p2align 6
sha256d_8preext2_17:
	.long 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000, 0x00a00000
sha256d_8preext2_23:
	.long 0x11002000, 0x11002000, 0x11002000, 0x11002000, 0x11002000, 0x11002000, 0x11002000, 0x11002000
sha256d_8preext2_24:
	.long 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000
sha256d_8preext2_30:
	.long 0x00400022, 0x00400022, 0x00400022, 0x00400022, 0x00400022, 0x00400022, 0x00400022, 0x00400022

#endif /* USE_AVX2 */


	.text
	.p2align 6
	.globl sha256_init_4way
	.globl _sha256_init_4way
sha256_init_4way:
_sha256_init_4way:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	movq	%rcx, %rdi
#endif
	movdqa	sha256_4h+0(%rip), %xmm0
	movdqa	sha256_4h+16(%rip), %xmm1
	movdqa	sha256_4h+32(%rip), %xmm2
	movdqa	sha256_4h+48(%rip), %xmm3
	movdqu	%xmm0, 0(%rdi)
	movdqu	%xmm1, 16(%rdi)
	movdqu	%xmm2, 32(%rdi)
	movdqu	%xmm3, 48(%rdi)
	movdqa	sha256_4h+64(%rip), %xmm0
	movdqa	sha256_4h+80(%rip), %xmm1
	movdqa	sha256_4h+96(%rip), %xmm2
	movdqa	sha256_4h+112(%rip), %xmm3
	movdqu	%xmm0, 64(%rdi)
	movdqu	%xmm1, 80(%rdi)
	movdqu	%xmm2, 96(%rdi)
	movdqu	%xmm3, 112(%rdi)
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rdi
#endif
	ret


#ifdef USE_AVX2
	.text
	.p2align 6
	.globl sha256_init_8way
	.globl _sha256_init_8way
sha256_init_8way:
_sha256_init_8way:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	movq	%rcx, %rdi
#endif
	vpbroadcastd	sha256_4h+0(%rip), %ymm0
	vpbroadcastd	sha256_4h+16(%rip), %ymm1
	vpbroadcastd	sha256_4h+32(%rip), %ymm2
	vpbroadcastd	sha256_4h+48(%rip), %ymm3
	vmovdqu	%ymm0, 0*32(%rdi)
	vmovdqu	%ymm1, 1*32(%rdi)
	vmovdqu	%ymm2, 2*32(%rdi)
	vmovdqu	%ymm3, 3*32(%rdi)
	vpbroadcastd	sha256_4h+64(%rip), %ymm0
	vpbroadcastd	sha256_4h+80(%rip), %ymm1
	vpbroadcastd	sha256_4h+96(%rip), %ymm2
	vpbroadcastd	sha256_4h+112(%rip), %ymm3
	vmovdqu	%ymm0, 4*32(%rdi)
	vmovdqu	%ymm1, 5*32(%rdi)
	vmovdqu	%ymm2, 6*32(%rdi)
	vmovdqu	%ymm3, 7*32(%rdi)
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rdi
#endif
	ret
#endif /* USE_AVX2 */







#if defined(USE_AVX)





#endif /* USE_AVX */


#if defined(USE_AVX2)





#endif /* USE_AVX2 */


#if defined(USE_XOP)


	


#endif /* USE_XOP */


	.text
	.p2align 6
sha256_transform_4way_core_sse2:
	leaq	256(%rsp), %rcx
	leaq	48*16(%rcx), %rax
	movdqa	-2*16(%rcx), %xmm3
	movdqa	-1*16(%rcx), %xmm7
sha256_transform_4way_sse2_extend_loop:
	movdqa	-15*16(%rcx), %xmm0
	movdqa	-14*16(%rcx), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	-16*16(%rcx), %xmm0
	paddd	-15*16(%rcx), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	-7*16(%rcx), %xmm0
	paddd	-6*16(%rcx), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, (%rcx)
	movdqa	%xmm7, 16(%rcx)
	addq	$2*16, %rcx
	cmpq	%rcx, %rax
	jne sha256_transform_4way_sse2_extend_loop
	
	movdqu	0(%rdi), %xmm7
	movdqu	16(%rdi), %xmm5
	movdqu	32(%rdi), %xmm4
	movdqu	48(%rdi), %xmm3
	movdqu	64(%rdi), %xmm0
	movdqu	80(%rdi), %xmm8
	movdqu	96(%rdi), %xmm9
	movdqu	112(%rdi), %xmm10
	
	leaq	sha256_4k(%rip), %rcx
	xorq	%rax, %rax
sha256_transform_4way_sse2_main_loop:
	movdqa	(%rsp, %rax), %xmm6
	paddd	(%rcx, %rax), %xmm6
	paddd	%xmm10, %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	%xmm9, %xmm2
	pandn	%xmm2, %xmm1

	movdqa	%xmm2, %xmm10
	movdqa	%xmm8, %xmm2
	movdqa	%xmm2, %xmm9

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, %xmm8

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm1, %xmm0
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	paddd	%xmm6, %xmm0

	movdqa	%xmm5, %xmm1
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm4
	pand	%xmm7, %xmm1
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pxor	%xmm1, %xmm7
	pslld	$9, %xmm2
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pxor	%xmm1, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	
	addq	$16, %rax
	cmpq	$16*64, %rax
	jne sha256_transform_4way_sse2_main_loop
	jmp sha256_transform_4way_finish


#if defined(USE_AVX)
	.text
	.p2align 6
sha256_transform_4way_core_avx:
	leaq	256(%rsp), %rax
	movdqa	-2*16(%rax), %xmm3
	movdqa	-1*16(%rax), %xmm7
	vmovdqa	(0-15)*16(%rax), %xmm0
	vmovdqa	(0-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(0-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(0-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(0-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 0*16(%rax)
	vmovdqa	%xmm7, (0+1)*16(%rax)
	vmovdqa	(2-15)*16(%rax), %xmm0
	vmovdqa	(2-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(2-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(2-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, (2+1)*16(%rax)
	vmovdqa	(4-15)*16(%rax), %xmm0
	vmovdqa	(4-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(4-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(4-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, (4+1)*16(%rax)
	vmovdqa	(6-15)*16(%rax), %xmm0
	vmovdqa	(6-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(6-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(6-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(6-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, (6+1)*16(%rax)
	vmovdqa	(8-15)*16(%rax), %xmm0
	vmovdqa	(8-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(8-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(8-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(8-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, (8+1)*16(%rax)
	vmovdqa	(10-15)*16(%rax), %xmm0
	vmovdqa	(10-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(10-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(10-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(10-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, (10+1)*16(%rax)
	vmovdqa	(12-15)*16(%rax), %xmm0
	vmovdqa	(12-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(12-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(12-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(12-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, (12+1)*16(%rax)
	vmovdqa	(14-15)*16(%rax), %xmm0
	vmovdqa	(14-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(14-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(14-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(14-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, (14+1)*16(%rax)
	vmovdqa	(16-15)*16(%rax), %xmm0
	vmovdqa	(16-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(16-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(16-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 16*16(%rax)
	vmovdqa	%xmm7, (16+1)*16(%rax)
	vmovdqa	(18-15)*16(%rax), %xmm0
	vmovdqa	(18-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(18-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(18-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 18*16(%rax)
	vmovdqa	%xmm7, (18+1)*16(%rax)
	vmovdqa	(20-15)*16(%rax), %xmm0
	vmovdqa	(20-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(20-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(20-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 20*16(%rax)
	vmovdqa	%xmm7, (20+1)*16(%rax)
	vmovdqa	(22-15)*16(%rax), %xmm0
	vmovdqa	(22-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(22-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(22-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 22*16(%rax)
	vmovdqa	%xmm7, (22+1)*16(%rax)
	vmovdqa	(24-15)*16(%rax), %xmm0
	vmovdqa	(24-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(24-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(24-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 24*16(%rax)
	vmovdqa	%xmm7, (24+1)*16(%rax)
	vmovdqa	(26-15)*16(%rax), %xmm0
	vmovdqa	(26-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(26-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(26-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 26*16(%rax)
	vmovdqa	%xmm7, (26+1)*16(%rax)
	vmovdqa	(28-15)*16(%rax), %xmm0
	vmovdqa	(28-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(28-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(28-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 28*16(%rax)
	vmovdqa	%xmm7, (28+1)*16(%rax)
	vmovdqa	(30-15)*16(%rax), %xmm0
	vmovdqa	(30-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(30-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(30-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 30*16(%rax)
	vmovdqa	%xmm7, (30+1)*16(%rax)
	vmovdqa	(32-15)*16(%rax), %xmm0
	vmovdqa	(32-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(32-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(32-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 32*16(%rax)
	vmovdqa	%xmm7, (32+1)*16(%rax)
	vmovdqa	(34-15)*16(%rax), %xmm0
	vmovdqa	(34-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(34-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(34-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 34*16(%rax)
	vmovdqa	%xmm7, (34+1)*16(%rax)
	vmovdqa	(36-15)*16(%rax), %xmm0
	vmovdqa	(36-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(36-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(36-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 36*16(%rax)
	vmovdqa	%xmm7, (36+1)*16(%rax)
	vmovdqa	(38-15)*16(%rax), %xmm0
	vmovdqa	(38-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(38-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(38-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 38*16(%rax)
	vmovdqa	%xmm7, (38+1)*16(%rax)
	vmovdqa	(40-15)*16(%rax), %xmm0
	vmovdqa	(40-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(40-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(40-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 40*16(%rax)
	vmovdqa	%xmm7, (40+1)*16(%rax)
	vmovdqa	(42-15)*16(%rax), %xmm0
	vmovdqa	(42-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(42-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(42-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 42*16(%rax)
	vmovdqa	%xmm7, (42+1)*16(%rax)
	vmovdqa	(44-15)*16(%rax), %xmm0
	vmovdqa	(44-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(44-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 44*16(%rax)
	vmovdqa	%xmm7, (44+1)*16(%rax)
	vmovdqa	(46-15)*16(%rax), %xmm0
	vmovdqa	(46-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(46-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(46-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 46*16(%rax)
	vmovdqa	%xmm7, (46+1)*16(%rax)
	movdqu	0(%rdi), %xmm7
	movdqu	16(%rdi), %xmm5
	movdqu	32(%rdi), %xmm4
	movdqu	48(%rdi), %xmm3
	movdqu	64(%rdi), %xmm0
	movdqu	80(%rdi), %xmm8
	movdqu	96(%rdi), %xmm9
	movdqu	112(%rdi), %xmm10
	movq	%rsp, %rax
	leaq	sha256_4k(%rip), %rcx
	vpaddd	16*(0+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(0+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(0+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(0+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(0+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(0+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(0+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(0+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(4+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(4+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(4+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(4+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(4+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(4+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(4+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(4+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(8+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(8+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(8+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(8+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(8+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(8+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(8+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(8+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(12+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(12+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(12+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(12+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(12+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(12+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(12+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(12+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(16+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(16+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(16+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(16+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(16+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(16+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(16+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(16+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(20+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(20+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(20+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(20+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(20+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(20+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(20+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(20+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(24+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(24+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(24+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(24+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(24+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(24+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(24+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(24+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(28+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(28+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(28+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(28+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(28+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(28+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(28+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(28+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(32+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(32+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(32+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(32+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(32+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(32+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(32+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(32+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(36+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(36+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(36+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(36+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(36+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(36+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(36+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(36+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(40+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(40+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(40+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(40+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(40+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(40+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(40+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(40+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(44+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(44+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(44+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(44+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(44+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(44+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(44+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(44+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(48+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(48+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(48+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(48+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(48+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(48+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(48+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(48+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(52+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(52+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(52+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(52+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(52+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(52+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(52+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(52+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(56+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(56+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(56+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(56+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(56+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(56+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(56+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(56+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(60+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(60+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(60+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(60+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(60+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(60+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(60+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(60+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	jmp sha256_transform_4way_finish
#endif /* USE_AVX */


#if defined(USE_XOP)
	.text
	.p2align 6
sha256_transform_4way_core_xop:
	leaq	256(%rsp), %rax
	movdqa	-2*16(%rax), %xmm3
	movdqa	-1*16(%rax), %xmm7
	vmovdqa	(0-15)*16(%rax), %xmm0
	vmovdqa	(0-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(0-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(0-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(0-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(0-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 0*16(%rax)
	vmovdqa	%xmm7, (0+1)*16(%rax)
	vmovdqa	(2-15)*16(%rax), %xmm0
	vmovdqa	(2-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(2-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(2-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, (2+1)*16(%rax)
	vmovdqa	(4-15)*16(%rax), %xmm0
	vmovdqa	(4-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(4-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(4-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, (4+1)*16(%rax)
	vmovdqa	(6-15)*16(%rax), %xmm0
	vmovdqa	(6-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(6-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(6-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(6-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(6-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, (6+1)*16(%rax)
	vmovdqa	(8-15)*16(%rax), %xmm0
	vmovdqa	(8-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(8-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(8-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(8-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(8-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, (8+1)*16(%rax)
	vmovdqa	(10-15)*16(%rax), %xmm0
	vmovdqa	(10-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(10-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(10-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(10-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(10-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, (10+1)*16(%rax)
	vmovdqa	(12-15)*16(%rax), %xmm0
	vmovdqa	(12-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(12-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(12-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(12-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(12-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, (12+1)*16(%rax)
	vmovdqa	(14-15)*16(%rax), %xmm0
	vmovdqa	(14-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(14-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(14-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(14-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(14-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, (14+1)*16(%rax)
	vmovdqa	(16-15)*16(%rax), %xmm0
	vmovdqa	(16-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(16-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(16-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 16*16(%rax)
	vmovdqa	%xmm7, (16+1)*16(%rax)
	vmovdqa	(18-15)*16(%rax), %xmm0
	vmovdqa	(18-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(18-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(18-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 18*16(%rax)
	vmovdqa	%xmm7, (18+1)*16(%rax)
	vmovdqa	(20-15)*16(%rax), %xmm0
	vmovdqa	(20-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(20-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(20-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 20*16(%rax)
	vmovdqa	%xmm7, (20+1)*16(%rax)
	vmovdqa	(22-15)*16(%rax), %xmm0
	vmovdqa	(22-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(22-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(22-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 22*16(%rax)
	vmovdqa	%xmm7, (22+1)*16(%rax)
	vmovdqa	(24-15)*16(%rax), %xmm0
	vmovdqa	(24-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(24-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(24-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 24*16(%rax)
	vmovdqa	%xmm7, (24+1)*16(%rax)
	vmovdqa	(26-15)*16(%rax), %xmm0
	vmovdqa	(26-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(26-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(26-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 26*16(%rax)
	vmovdqa	%xmm7, (26+1)*16(%rax)
	vmovdqa	(28-15)*16(%rax), %xmm0
	vmovdqa	(28-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(28-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(28-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 28*16(%rax)
	vmovdqa	%xmm7, (28+1)*16(%rax)
	vmovdqa	(30-15)*16(%rax), %xmm0
	vmovdqa	(30-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(30-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(30-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 30*16(%rax)
	vmovdqa	%xmm7, (30+1)*16(%rax)
	vmovdqa	(32-15)*16(%rax), %xmm0
	vmovdqa	(32-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(32-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(32-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 32*16(%rax)
	vmovdqa	%xmm7, (32+1)*16(%rax)
	vmovdqa	(34-15)*16(%rax), %xmm0
	vmovdqa	(34-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(34-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(34-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 34*16(%rax)
	vmovdqa	%xmm7, (34+1)*16(%rax)
	vmovdqa	(36-15)*16(%rax), %xmm0
	vmovdqa	(36-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(36-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(36-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 36*16(%rax)
	vmovdqa	%xmm7, (36+1)*16(%rax)
	vmovdqa	(38-15)*16(%rax), %xmm0
	vmovdqa	(38-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(38-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(38-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 38*16(%rax)
	vmovdqa	%xmm7, (38+1)*16(%rax)
	vmovdqa	(40-15)*16(%rax), %xmm0
	vmovdqa	(40-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(40-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(40-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 40*16(%rax)
	vmovdqa	%xmm7, (40+1)*16(%rax)
	vmovdqa	(42-15)*16(%rax), %xmm0
	vmovdqa	(42-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(42-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(42-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 42*16(%rax)
	vmovdqa	%xmm7, (42+1)*16(%rax)
	vmovdqa	(44-15)*16(%rax), %xmm0
	vmovdqa	(44-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(44-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 44*16(%rax)
	vmovdqa	%xmm7, (44+1)*16(%rax)
	vmovdqa	(46-15)*16(%rax), %xmm0
	vmovdqa	(46-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(46-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(46-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 46*16(%rax)
	vmovdqa	%xmm7, (46+1)*16(%rax)
	movdqu	0(%rdi), %xmm7
	movdqu	16(%rdi), %xmm5
	movdqu	32(%rdi), %xmm4
	movdqu	48(%rdi), %xmm3
	movdqu	64(%rdi), %xmm0
	movdqu	80(%rdi), %xmm8
	movdqu	96(%rdi), %xmm9
	movdqu	112(%rdi), %xmm10
	movq	%rsp, %rax
	leaq	sha256_4k(%rip), %rcx
	vpaddd	16*(0+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(0+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(0+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(0+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(0+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(0+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(0+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(0+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(4+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(4+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(4+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(4+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(4+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(4+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(4+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(4+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(8+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(8+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(8+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(8+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(8+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(8+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(8+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(8+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(12+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(12+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(12+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(12+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(12+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(12+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(12+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(12+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(16+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(16+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(16+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(16+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(16+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(16+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(16+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(16+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(20+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(20+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(20+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(20+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(20+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(20+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(20+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(20+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(24+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(24+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(24+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(24+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(24+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(24+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(24+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(24+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(28+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(28+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(28+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(28+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(28+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(28+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(28+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(28+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(32+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(32+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(32+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(32+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(32+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(32+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(32+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(32+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(36+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(36+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(36+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(36+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(36+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(36+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(36+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(36+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(40+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(40+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(40+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(40+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(40+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(40+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(40+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(40+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(44+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(44+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(44+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(44+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(44+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(44+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(44+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(44+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(48+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(48+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(48+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(48+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(48+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(48+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(48+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(48+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(52+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(52+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(52+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(52+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(52+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(52+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(52+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(52+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(56+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(56+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(56+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(56+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(56+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(56+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(56+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(56+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(60+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(60+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(60+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(60+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(60+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(60+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(60+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(60+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	jmp sha256_transform_4way_finish
#endif /* USE_XOP */


	.data
	.p2align 3
sha256_transform_4way_core_addr:
	.quad 0x0

	
	.text
	.p2align 6
	.globl sha256_transform_4way
	.globl _sha256_transform_4way
sha256_transform_4way:
_sha256_transform_4way:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$96, %rsp
	movdqa	%xmm6, 0(%rsp)
	movdqa	%xmm7, 16(%rsp)
	movdqa	%xmm8, 32(%rsp)
	movdqa	%xmm9, 48(%rsp)
	movdqa	%xmm10, 64(%rsp)
	movdqa	%xmm11, 80(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	movq	%rsp, %r8
	subq	$1032, %rsp
	andq	$-128, %rsp
	
	testq	%rdx, %rdx
	jnz sha256_transform_4way_swap
	
	movdqu	0*16(%rsi), %xmm0
	movdqu	1*16(%rsi), %xmm1
	movdqu	2*16(%rsi), %xmm2
	movdqu	3*16(%rsi), %xmm3
	movdqu	4*16(%rsi), %xmm4
	movdqu	5*16(%rsi), %xmm5
	movdqu	6*16(%rsi), %xmm6
	movdqu	7*16(%rsi), %xmm7
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
	movdqa	%xmm3, 3*16(%rsp)
	movdqa	%xmm4, 4*16(%rsp)
	movdqa	%xmm5, 5*16(%rsp)
	movdqa	%xmm6, 6*16(%rsp)
	movdqa	%xmm7, 7*16(%rsp)
	movdqu	8*16(%rsi), %xmm0
	movdqu	9*16(%rsi), %xmm1
	movdqu	10*16(%rsi), %xmm2
	movdqu	11*16(%rsi), %xmm3
	movdqu	12*16(%rsi), %xmm4
	movdqu	13*16(%rsi), %xmm5
	movdqu	14*16(%rsi), %xmm6
	movdqu	15*16(%rsi), %xmm7
	movdqa	%xmm0, 8*16(%rsp)
	movdqa	%xmm1, 9*16(%rsp)
	movdqa	%xmm2, 10*16(%rsp)
	movdqa	%xmm3, 11*16(%rsp)
	movdqa	%xmm4, 12*16(%rsp)
	movdqa	%xmm5, 13*16(%rsp)
	movdqa	%xmm6, 14*16(%rsp)
	movdqa	%xmm7, 15*16(%rsp)
	jmp *sha256_transform_4way_core_addr(%rip)
	
	.p2align 6
sha256_transform_4way_swap:
	movdqu	0*16(%rsi), %xmm0
	movdqu	(0+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm2, (0+1)*16(%rsp)
	movdqu	2*16(%rsi), %xmm0
	movdqu	(2+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 2*16(%rsp)
	movdqa	%xmm2, (2+1)*16(%rsp)
	movdqu	4*16(%rsi), %xmm0
	movdqu	(4+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 4*16(%rsp)
	movdqa	%xmm2, (4+1)*16(%rsp)
	movdqu	6*16(%rsi), %xmm0
	movdqu	(6+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 6*16(%rsp)
	movdqa	%xmm2, (6+1)*16(%rsp)
	movdqu	8*16(%rsi), %xmm0
	movdqu	(8+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 8*16(%rsp)
	movdqa	%xmm2, (8+1)*16(%rsp)
	movdqu	10*16(%rsi), %xmm0
	movdqu	(10+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 10*16(%rsp)
	movdqa	%xmm2, (10+1)*16(%rsp)
	movdqu	12*16(%rsi), %xmm0
	movdqu	(12+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 12*16(%rsp)
	movdqa	%xmm2, (12+1)*16(%rsp)
	movdqu	14*16(%rsi), %xmm0
	movdqu	(14+1)*16(%rsi), %xmm2
	pshuflw	$0xb1, %xmm0, %xmm0
	pshuflw	$0xb1, %xmm2, %xmm2
	pshufhw	$0xb1, %xmm0, %xmm0
	pshufhw	$0xb1, %xmm2, %xmm2
	movdqa	%xmm0, %xmm1
	movdqa	%xmm2, %xmm3
	psrlw	$8, %xmm1
	psrlw	$8, %xmm3
	psllw	$8, %xmm0
	psllw	$8, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm3, %xmm2
	movdqa	%xmm0, 14*16(%rsp)
	movdqa	%xmm2, (14+1)*16(%rsp)
	jmp *sha256_transform_4way_core_addr(%rip)
	
	.p2align 6
sha256_transform_4way_finish:
	movdqu	0(%rdi), %xmm2
	movdqu	16(%rdi), %xmm6
	movdqu	32(%rdi), %xmm11
	movdqu	48(%rdi), %xmm1
	paddd	%xmm2, %xmm7
	paddd	%xmm6, %xmm5
	paddd	%xmm11, %xmm4
	paddd	%xmm1, %xmm3
	movdqu	64(%rdi), %xmm2
	movdqu	80(%rdi), %xmm6
	movdqu	96(%rdi), %xmm11
	movdqu	112(%rdi), %xmm1
	paddd	%xmm2, %xmm0
	paddd	%xmm6, %xmm8
	paddd	%xmm11, %xmm9
	paddd	%xmm1, %xmm10
	
	movdqu	%xmm7, 0(%rdi)
	movdqu	%xmm5, 16(%rdi)
	movdqu	%xmm4, 32(%rdi)
	movdqu	%xmm3, 48(%rdi)
	movdqu	%xmm0, 64(%rdi)
	movdqu	%xmm8, 80(%rdi)
	movdqu	%xmm9, 96(%rdi)
	movdqu	%xmm10, 112(%rdi)
	
	movq	%r8, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	movdqa	0(%rsp), %xmm6
	movdqa	16(%rsp), %xmm7
	movdqa	32(%rsp), %xmm8
	movdqa	48(%rsp), %xmm9
	movdqa	64(%rsp), %xmm10
	movdqa	80(%rsp), %xmm11
	addq	$96, %rsp
	popq	%rdi
#endif
	ret


#ifdef USE_AVX2

	.text
	.p2align 6
sha256_transform_8way_core_avx2:
	leaq	8*64(%rsp), %rax
	vmovdqa	-2*32(%rax), %ymm3
	vmovdqa	-1*32(%rax), %ymm7
	vmovdqa	(0-15)*32(%rax), %ymm0
	vmovdqa	(0-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(0-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(0-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(0-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 0*32(%rax)
	vmovdqa	%ymm7, (0+1)*32(%rax)
	vmovdqa	(2-15)*32(%rax), %ymm0
	vmovdqa	(2-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(2-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(2-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(2-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 2*32(%rax)
	vmovdqa	%ymm7, (2+1)*32(%rax)
	vmovdqa	(4-15)*32(%rax), %ymm0
	vmovdqa	(4-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(4-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(4-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(4-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 4*32(%rax)
	vmovdqa	%ymm7, (4+1)*32(%rax)
	vmovdqa	(6-15)*32(%rax), %ymm0
	vmovdqa	(6-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(6-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(6-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(6-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 6*32(%rax)
	vmovdqa	%ymm7, (6+1)*32(%rax)
	vmovdqa	(8-15)*32(%rax), %ymm0
	vmovdqa	(8-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(8-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(8-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(8-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 8*32(%rax)
	vmovdqa	%ymm7, (8+1)*32(%rax)
	vmovdqa	(10-15)*32(%rax), %ymm0
	vmovdqa	(10-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(10-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(10-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(10-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 10*32(%rax)
	vmovdqa	%ymm7, (10+1)*32(%rax)
	vmovdqa	(12-15)*32(%rax), %ymm0
	vmovdqa	(12-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(12-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(12-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(12-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 12*32(%rax)
	vmovdqa	%ymm7, (12+1)*32(%rax)
	vmovdqa	(14-15)*32(%rax), %ymm0
	vmovdqa	(14-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(14-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(14-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(14-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 14*32(%rax)
	vmovdqa	%ymm7, (14+1)*32(%rax)
	vmovdqa	(16-15)*32(%rax), %ymm0
	vmovdqa	(16-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(16-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(16-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(16-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 16*32(%rax)
	vmovdqa	%ymm7, (16+1)*32(%rax)
	vmovdqa	(18-15)*32(%rax), %ymm0
	vmovdqa	(18-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(18-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(18-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(18-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 18*32(%rax)
	vmovdqa	%ymm7, (18+1)*32(%rax)
	vmovdqa	(20-15)*32(%rax), %ymm0
	vmovdqa	(20-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(20-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(20-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(20-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 20*32(%rax)
	vmovdqa	%ymm7, (20+1)*32(%rax)
	vmovdqa	(22-15)*32(%rax), %ymm0
	vmovdqa	(22-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(22-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(22-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(22-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 22*32(%rax)
	vmovdqa	%ymm7, (22+1)*32(%rax)
	vmovdqa	(24-15)*32(%rax), %ymm0
	vmovdqa	(24-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(24-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(24-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(24-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 24*32(%rax)
	vmovdqa	%ymm7, (24+1)*32(%rax)
	vmovdqa	(26-15)*32(%rax), %ymm0
	vmovdqa	(26-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(26-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(26-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(26-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 26*32(%rax)
	vmovdqa	%ymm7, (26+1)*32(%rax)
	vmovdqa	(28-15)*32(%rax), %ymm0
	vmovdqa	(28-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(28-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(28-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(28-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 28*32(%rax)
	vmovdqa	%ymm7, (28+1)*32(%rax)
	vmovdqa	(30-15)*32(%rax), %ymm0
	vmovdqa	(30-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(30-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(30-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(30-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 30*32(%rax)
	vmovdqa	%ymm7, (30+1)*32(%rax)
	vmovdqa	(32-15)*32(%rax), %ymm0
	vmovdqa	(32-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(32-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(32-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(32-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 32*32(%rax)
	vmovdqa	%ymm7, (32+1)*32(%rax)
	vmovdqa	(34-15)*32(%rax), %ymm0
	vmovdqa	(34-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(34-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(34-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(34-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 34*32(%rax)
	vmovdqa	%ymm7, (34+1)*32(%rax)
	vmovdqa	(36-15)*32(%rax), %ymm0
	vmovdqa	(36-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(36-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(36-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(36-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 36*32(%rax)
	vmovdqa	%ymm7, (36+1)*32(%rax)
	vmovdqa	(38-15)*32(%rax), %ymm0
	vmovdqa	(38-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(38-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(38-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(38-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 38*32(%rax)
	vmovdqa	%ymm7, (38+1)*32(%rax)
	vmovdqa	(40-15)*32(%rax), %ymm0
	vmovdqa	(40-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(40-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(40-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(40-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 40*32(%rax)
	vmovdqa	%ymm7, (40+1)*32(%rax)
	vmovdqa	(42-15)*32(%rax), %ymm0
	vmovdqa	(42-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(42-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(42-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(42-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 42*32(%rax)
	vmovdqa	%ymm7, (42+1)*32(%rax)
	vmovdqa	(44-15)*32(%rax), %ymm0
	vmovdqa	(44-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(44-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(44-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(44-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 44*32(%rax)
	vmovdqa	%ymm7, (44+1)*32(%rax)
	vmovdqa	(46-15)*32(%rax), %ymm0
	vmovdqa	(46-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(46-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(46-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(46-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 46*32(%rax)
	vmovdqa	%ymm7, (46+1)*32(%rax)
	vmovdqu	0*32(%rdi), %ymm7
	vmovdqu	1*32(%rdi), %ymm5
	vmovdqu	2*32(%rdi), %ymm4
	vmovdqu	3*32(%rdi), %ymm3
	vmovdqu	4*32(%rdi), %ymm0
	vmovdqu	5*32(%rdi), %ymm8
	vmovdqu	6*32(%rdi), %ymm9
	vmovdqu	7*32(%rdi), %ymm10
	movq	%rsp, %rax
	leaq	sha256_8k(%rip), %rcx
	vpaddd	32*(0+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(0+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(0+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(0+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(0+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(0+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(0+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(0+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(4+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(4+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(4+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(4+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(4+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(4+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(4+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(4+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(8+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(8+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(8+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(8+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(8+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(8+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(8+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(8+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(12+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(12+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(12+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(12+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(12+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(12+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(12+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(12+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(16+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(16+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(16+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(16+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(16+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(16+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(16+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(16+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(20+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(20+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(20+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(20+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(20+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(20+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(20+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(20+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(24+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(24+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(24+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(24+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(24+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(24+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(24+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(24+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(28+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(28+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(28+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(28+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(28+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(28+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(28+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(28+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(32+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(32+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(32+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(32+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(32+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(32+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(32+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(32+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(36+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(36+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(36+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(36+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(36+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(36+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(36+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(36+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(40+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(40+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(40+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(40+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(40+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(40+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(40+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(40+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(44+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(44+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(44+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(44+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(44+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(44+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(44+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(44+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(48+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(48+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(48+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(48+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(48+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(48+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(48+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(48+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(52+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(52+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(52+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(52+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(52+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(52+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(52+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(52+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(56+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(56+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(56+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(56+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(56+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(56+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(56+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(56+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(60+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(60+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(60+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(60+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(60+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(60+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(60+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(60+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	jmp sha256_transform_8way_finish

	
	.text
	.p2align 6
	.globl sha256_transform_8way
	.globl _sha256_transform_8way
sha256_transform_8way:
_sha256_transform_8way:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$96, %rsp
	vmovdqa	%xmm6, 0(%rsp)
	vmovdqa	%xmm7, 16(%rsp)
	vmovdqa	%xmm8, 32(%rsp)
	vmovdqa	%xmm9, 48(%rsp)
	vmovdqa	%xmm10, 64(%rsp)
	vmovdqa	%xmm11, 80(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	movq	%rsp, %r8
	subq	$64*32, %rsp
	andq	$-128, %rsp
	
	testq	%rdx, %rdx
	jnz sha256_transform_8way_swap
	
	vmovdqu	0*32(%rsi), %ymm0
	vmovdqu	1*32(%rsi), %ymm1
	vmovdqu	2*32(%rsi), %ymm2
	vmovdqu	3*32(%rsi), %ymm3
	vmovdqu	4*32(%rsi), %ymm4
	vmovdqu	5*32(%rsi), %ymm5
	vmovdqu	6*32(%rsi), %ymm6
	vmovdqu	7*32(%rsi), %ymm7
	vmovdqa	%ymm0, 0*32(%rsp)
	vmovdqa	%ymm1, 1*32(%rsp)
	vmovdqa	%ymm2, 2*32(%rsp)
	vmovdqa	%ymm3, 3*32(%rsp)
	vmovdqa	%ymm4, 4*32(%rsp)
	vmovdqa	%ymm5, 5*32(%rsp)
	vmovdqa	%ymm6, 6*32(%rsp)
	vmovdqa	%ymm7, 7*32(%rsp)
	vmovdqu	8*32(%rsi), %ymm0
	vmovdqu	9*32(%rsi), %ymm1
	vmovdqu	10*32(%rsi), %ymm2
	vmovdqu	11*32(%rsi), %ymm3
	vmovdqu	12*32(%rsi), %ymm4
	vmovdqu	13*32(%rsi), %ymm5
	vmovdqu	14*32(%rsi), %ymm6
	vmovdqu	15*32(%rsi), %ymm7
	vmovdqa	%ymm0, 8*32(%rsp)
	vmovdqa	%ymm1, 9*32(%rsp)
	vmovdqa	%ymm2, 10*32(%rsp)
	vmovdqa	%ymm3, 11*32(%rsp)
	vmovdqa	%ymm4, 12*32(%rsp)
	vmovdqa	%ymm5, 13*32(%rsp)
	vmovdqa	%ymm6, 14*32(%rsp)
	vmovdqa	%ymm7, 15*32(%rsp)
	jmp sha256_transform_8way_core_avx2
	
	.p2align 6
sha256_transform_8way_swap:
	vmovdqu	0*32(%rsi), %ymm0
	vmovdqu	(0+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 0*32(%rsp)
	vmovdqa	%ymm2, (0+1)*32(%rsp)
	vmovdqu	2*32(%rsi), %ymm0
	vmovdqu	(2+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 2*32(%rsp)
	vmovdqa	%ymm2, (2+1)*32(%rsp)
	vmovdqu	4*32(%rsi), %ymm0
	vmovdqu	(4+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 4*32(%rsp)
	vmovdqa	%ymm2, (4+1)*32(%rsp)
	vmovdqu	6*32(%rsi), %ymm0
	vmovdqu	(6+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 6*32(%rsp)
	vmovdqa	%ymm2, (6+1)*32(%rsp)
	vmovdqu	8*32(%rsi), %ymm0
	vmovdqu	(8+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 8*32(%rsp)
	vmovdqa	%ymm2, (8+1)*32(%rsp)
	vmovdqu	10*32(%rsi), %ymm0
	vmovdqu	(10+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 10*32(%rsp)
	vmovdqa	%ymm2, (10+1)*32(%rsp)
	vmovdqu	12*32(%rsi), %ymm0
	vmovdqu	(12+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 12*32(%rsp)
	vmovdqa	%ymm2, (12+1)*32(%rsp)
	vmovdqu	14*32(%rsi), %ymm0
	vmovdqu	(14+1)*32(%rsi), %ymm2
	vpshuflw	$0xb1, %ymm0, %ymm0
	vpshuflw	$0xb1, %ymm2, %ymm2
	vpshufhw	$0xb1, %ymm0, %ymm0
	vpshufhw	$0xb1, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm1
	vpsrlw	$8, %ymm2, %ymm3
	vpsllw	$8, %ymm0, %ymm0
	vpsllw	$8, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm0, 14*32(%rsp)
	vmovdqa	%ymm2, (14+1)*32(%rsp)
	jmp sha256_transform_8way_core_avx2
	
	.p2align 6
sha256_transform_8way_finish:
	vmovdqu	0*32(%rdi), %ymm2
	vmovdqu	1*32(%rdi), %ymm6
	vmovdqu	2*32(%rdi), %ymm11
	vmovdqu	3*32(%rdi), %ymm1
	vpaddd	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	%ymm11, %ymm4, %ymm4
	vpaddd	%ymm1, %ymm3, %ymm3
	vmovdqu	4*32(%rdi), %ymm2
	vmovdqu	5*32(%rdi), %ymm6
	vmovdqu	6*32(%rdi), %ymm11
	vmovdqu	7*32(%rdi), %ymm1
	vpaddd	%ymm2, %ymm0, %ymm0
	vpaddd	%ymm6, %ymm8, %ymm8
	vpaddd	%ymm11, %ymm9, %ymm9
	vpaddd	%ymm1, %ymm10, %ymm10
	
	vmovdqu	%ymm7, 0*32(%rdi)
	vmovdqu	%ymm5, 1*32(%rdi)
	vmovdqu	%ymm4, 2*32(%rdi)
	vmovdqu	%ymm3, 3*32(%rdi)
	vmovdqu	%ymm0, 4*32(%rdi)
	vmovdqu	%ymm8, 5*32(%rdi)
	vmovdqu	%ymm9, 6*32(%rdi)
	vmovdqu	%ymm10, 7*32(%rdi)
	
	movq	%r8, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	vmovdqa	0(%rsp), %xmm6
	vmovdqa	16(%rsp), %xmm7
	vmovdqa	32(%rsp), %xmm8
	vmovdqa	48(%rsp), %xmm9
	vmovdqa	64(%rsp), %xmm10
	vmovdqa	80(%rsp), %xmm11
	addq	$96, %rsp
	popq	%rdi
#endif
	ret

#endif /* USE_AVX2 */
	
	
	.data
	.p2align 3
sha256d_ms_4way_addr:
	.quad 0x0
	
	.text
	.p2align 6
	.globl sha256d_ms_4way
	.globl _sha256d_ms_4way
sha256d_ms_4way:
_sha256d_ms_4way:
	jmp *sha256d_ms_4way_addr(%rip)
	
	
	.p2align 6
sha256d_ms_4way_sse2:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$32, %rsp
	movdqa	%xmm6, 0(%rsp)
	movdqa	%xmm7, 16(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
	movq	%r9, %rcx
#endif
	subq	$8+67*16, %rsp
	
	leaq	256(%rsi), %rax
	
sha256d_ms_4way_sse2_extend_loop1:
	movdqa	3*16(%rsi), %xmm0
	movdqa	2*16(%rax), %xmm3
	movdqa	3*16(%rax), %xmm7
	movdqa	%xmm3, 5*16(%rsp)
	movdqa	%xmm7, 6*16(%rsp)
	movdqa	%xmm0, %xmm2
	paddd	%xmm0, %xmm7
	psrld	$3, %xmm0
	movdqa	%xmm0, %xmm1
	pslld	$14, %xmm2
	psrld	$4, %xmm1
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	psrld	$11, %xmm1
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	paddd	%xmm0, %xmm3
	movdqa	%xmm3, 2*16(%rax)
	movdqa	%xmm7, 3*16(%rax)
	
	movdqa	4*16(%rax), %xmm0
	movdqa	%xmm0, 7*16(%rsp)
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	movdqa	%xmm3, 4*16(%rax)
	movdqa	%xmm7, 5*16(%rax)
	
	movdqa	6*16(%rax), %xmm0
	movdqa	7*16(%rax), %xmm4
	movdqa	%xmm0, 9*16(%rsp)
	movdqa	%xmm4, 10*16(%rsp)
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 6*16(%rax)
	movdqa	%xmm7, 7*16(%rax)
	
	movdqa	8*16(%rax), %xmm0
	movdqa	2*16(%rax), %xmm4
	movdqa	%xmm0, 11*16(%rsp)
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 8*16(%rax)
	movdqa	%xmm7, 9*16(%rax)
	
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	3*16(%rax), %xmm3
	paddd	4*16(%rax), %xmm7
	movdqa	%xmm3, 10*16(%rax)
	movdqa	%xmm7, 11*16(%rax)
	
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	5*16(%rax), %xmm3
	paddd	6*16(%rax), %xmm7
	movdqa	%xmm3, 12*16(%rax)
	movdqa	%xmm7, 13*16(%rax)
	
	movdqa	14*16(%rax), %xmm0
	movdqa	15*16(%rax), %xmm4
	movdqa	%xmm0, 17*16(%rsp)
	movdqa	%xmm4, 18*16(%rsp)
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	paddd	7*16(%rax), %xmm0
	paddd	8*16(%rax), %xmm4
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 14*16(%rax)
	movdqa	%xmm7, 15*16(%rax)
	
sha256d_ms_4way_sse2_extend_loop2:
	movdqa	(16-15)*16(%rax), %xmm0
	movdqa	(16-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(16-16)*16(%rax), %xmm0
	paddd	(16-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(16-7)*16(%rax), %xmm0
	paddd	(16-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 16*16(%rax)
	movdqa	%xmm7, (16+1)*16(%rax)
	movdqa	(18-15)*16(%rax), %xmm0
	movdqa	(18-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(18-16)*16(%rax), %xmm0
	paddd	(18-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(18-7)*16(%rax), %xmm0
	paddd	(18-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 18*16(%rax)
	movdqa	%xmm7, (18+1)*16(%rax)
	movdqa	(20-15)*16(%rax), %xmm0
	movdqa	(20-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(20-16)*16(%rax), %xmm0
	paddd	(20-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(20-7)*16(%rax), %xmm0
	paddd	(20-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 20*16(%rax)
	movdqa	%xmm7, (20+1)*16(%rax)
	movdqa	(22-15)*16(%rax), %xmm0
	movdqa	(22-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(22-16)*16(%rax), %xmm0
	paddd	(22-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(22-7)*16(%rax), %xmm0
	paddd	(22-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 22*16(%rax)
	movdqa	%xmm7, (22+1)*16(%rax)
	movdqa	(24-15)*16(%rax), %xmm0
	movdqa	(24-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(24-16)*16(%rax), %xmm0
	paddd	(24-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(24-7)*16(%rax), %xmm0
	paddd	(24-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 24*16(%rax)
	movdqa	%xmm7, (24+1)*16(%rax)
	movdqa	(26-15)*16(%rax), %xmm0
	movdqa	(26-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(26-16)*16(%rax), %xmm0
	paddd	(26-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(26-7)*16(%rax), %xmm0
	paddd	(26-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 26*16(%rax)
	movdqa	%xmm7, (26+1)*16(%rax)
	movdqa	(28-15)*16(%rax), %xmm0
	movdqa	(28-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(28-16)*16(%rax), %xmm0
	paddd	(28-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(28-7)*16(%rax), %xmm0
	paddd	(28-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 28*16(%rax)
	movdqa	%xmm7, (28+1)*16(%rax)
	movdqa	(30-15)*16(%rax), %xmm0
	movdqa	(30-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(30-16)*16(%rax), %xmm0
	paddd	(30-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(30-7)*16(%rax), %xmm0
	paddd	(30-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 30*16(%rax)
	movdqa	%xmm7, (30+1)*16(%rax)
	movdqa	(32-15)*16(%rax), %xmm0
	movdqa	(32-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(32-16)*16(%rax), %xmm0
	paddd	(32-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(32-7)*16(%rax), %xmm0
	paddd	(32-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 32*16(%rax)
	movdqa	%xmm7, (32+1)*16(%rax)
	movdqa	(34-15)*16(%rax), %xmm0
	movdqa	(34-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(34-16)*16(%rax), %xmm0
	paddd	(34-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(34-7)*16(%rax), %xmm0
	paddd	(34-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 34*16(%rax)
	movdqa	%xmm7, (34+1)*16(%rax)
	movdqa	(36-15)*16(%rax), %xmm0
	movdqa	(36-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(36-16)*16(%rax), %xmm0
	paddd	(36-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(36-7)*16(%rax), %xmm0
	paddd	(36-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 36*16(%rax)
	movdqa	%xmm7, (36+1)*16(%rax)
	movdqa	(38-15)*16(%rax), %xmm0
	movdqa	(38-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(38-16)*16(%rax), %xmm0
	paddd	(38-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(38-7)*16(%rax), %xmm0
	paddd	(38-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 38*16(%rax)
	movdqa	%xmm7, (38+1)*16(%rax)
	movdqa	(40-15)*16(%rax), %xmm0
	movdqa	(40-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(40-16)*16(%rax), %xmm0
	paddd	(40-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(40-7)*16(%rax), %xmm0
	paddd	(40-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 40*16(%rax)
	movdqa	%xmm7, (40+1)*16(%rax)
	movdqa	(42-15)*16(%rax), %xmm0
	movdqa	(42-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(42-16)*16(%rax), %xmm0
	paddd	(42-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(42-7)*16(%rax), %xmm0
	paddd	(42-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 42*16(%rax)
	movdqa	%xmm7, (42+1)*16(%rax)
	jz sha256d_ms_4way_sse2_extend_coda2
	movdqa	(44-15)*16(%rax), %xmm0
	movdqa	(44-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(44-16)*16(%rax), %xmm0
	paddd	(44-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(44-7)*16(%rax), %xmm0
	paddd	(44-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 44*16(%rax)
	movdqa	%xmm7, (44+1)*16(%rax)
	movdqa	(46-15)*16(%rax), %xmm0
	movdqa	(46-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(46-16)*16(%rax), %xmm0
	paddd	(46-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(46-7)*16(%rax), %xmm0
	paddd	(46-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 46*16(%rax)
	movdqa	%xmm7, (46+1)*16(%rax)
	
	movdqa	0(%rcx), %xmm3
	movdqa	16(%rcx), %xmm0
	movdqa	32(%rcx), %xmm1
	movdqa	48(%rcx), %xmm2
	movdqa	64(%rcx), %xmm6
	movdqa	80(%rcx), %xmm7
	movdqa	96(%rcx), %xmm5
	movdqa	112(%rcx), %xmm4
	movdqa	%xmm1, 0(%rsp)
	movdqa	%xmm2, 16(%rsp)
	movdqa	%xmm6, 32(%rsp)
	
	movq	%rsi, %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_sse2_main_loop1
	
sha256d_ms_4way_sse2_main_loop2:
	movdqa	16*(0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
sha256d_ms_4way_sse2_main_loop1:
	movdqa	16*(3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(4+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(4+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(4+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(4+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(4+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(4+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(4+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(4+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(8+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(8+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(8+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(8+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(8+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(8+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(8+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(8+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(12+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(12+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(12+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(12+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(12+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(12+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(12+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(12+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(16+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(16+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(16+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(16+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(16+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(16+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(16+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(16+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(20+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(20+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(20+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(20+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(20+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(20+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(20+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(20+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(24+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(24+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(24+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(24+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(24+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(24+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(24+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(24+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(28+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(28+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(28+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(28+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(28+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(28+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(28+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(28+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(32+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(32+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(32+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(32+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(32+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(32+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(32+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(32+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(36+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(36+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(36+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(36+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(36+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(36+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(36+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(36+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(40+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(40+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(40+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(40+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(40+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(40+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(40+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(40+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(44+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(44+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(44+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(44+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(44+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(44+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(44+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(44+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(48+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(48+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(48+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(48+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(48+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(48+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(48+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(48+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(52+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(52+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(52+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(52+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(52+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(52+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(52+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(52+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(56)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(56)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	jz sha256d_ms_4way_sse2_finish
	movdqa	16*(57)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(57)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(58)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(58)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(59)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(59)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(60+0)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(60+0)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(60+1)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(60+1)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(60+2)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(60+2)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	movdqa	16*(60+3)(%rax), %xmm6

	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	pandn	%xmm2, %xmm1
	paddd	32(%rsp), %xmm6

	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)

	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)

	paddd	%xmm1, %xmm6

	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	paddd	16*(60+3)(%rcx), %xmm6
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm5, %xmm1
	paddd	%xmm0, %xmm6

	movdqa	%xmm3, %xmm0
	movdqa	%xmm4, %xmm3
	movdqa	%xmm4, %xmm2
	paddd	%xmm6, %xmm0
	pand	%xmm5, %xmm2
	pand	%xmm7, %xmm1
	pand	%xmm7, %xmm4
	pxor	%xmm4, %xmm1
	movdqa	%xmm5, %xmm4
	movdqa	%xmm7, %xmm5
	pxor	%xmm2, %xmm1
	paddd	%xmm1, %xmm6

	movdqa	%xmm7, %xmm2
	psrld	$2, %xmm7
	movdqa	%xmm7, %xmm1
	pslld	$10, %xmm2
	psrld	$11, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$9, %xmm2
	pxor	%xmm1, %xmm7
	psrld	$9, %xmm1
	pxor	%xmm2, %xmm7
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm7
	pxor	%xmm2, %xmm7
	paddd	%xmm6, %xmm7
	
	movdqa	5*16(%rsp), %xmm1
	movdqa	6*16(%rsp), %xmm2
	movdqa	7*16(%rsp), %xmm6
	movdqa	%xmm1, 18*16(%rsi)
	movdqa	%xmm2, 19*16(%rsi)
	movdqa	%xmm6, 20*16(%rsi)
	movdqa	9*16(%rsp), %xmm1
	movdqa	10*16(%rsp), %xmm2
	movdqa	11*16(%rsp), %xmm6
	movdqa	%xmm1, 22*16(%rsi)
	movdqa	%xmm2, 23*16(%rsi)
	movdqa	%xmm6, 24*16(%rsi)
	movdqa	17*16(%rsp), %xmm1
	movdqa	18*16(%rsp), %xmm2
	movdqa	%xmm1, 30*16(%rsi)
	movdqa	%xmm2, 31*16(%rsi)
	
	movdqa	0(%rsp), %xmm1
	movdqa	16(%rsp), %xmm2
	movdqa	32(%rsp), %xmm6
	paddd	0(%rdx), %xmm7
	paddd	16(%rdx), %xmm5
	paddd	32(%rdx), %xmm4
	paddd	48(%rdx), %xmm3
	paddd	64(%rdx), %xmm0
	paddd	80(%rdx), %xmm1
	paddd	96(%rdx), %xmm2
	paddd	112(%rdx), %xmm6
	
	movdqa	%xmm7, 48+0(%rsp)
	movdqa	%xmm5, 48+16(%rsp)
	movdqa	%xmm4, 48+32(%rsp)
	movdqa	%xmm3, 48+48(%rsp)
	movdqa	%xmm0, 48+64(%rsp)
	movdqa	%xmm1, 48+80(%rsp)
	movdqa	%xmm2, 48+96(%rsp)
	movdqa	%xmm6, 48+112(%rsp)
	
	pxor	%xmm0, %xmm0
	movq	$0x8000000000000100, %rax
	movd	%rax, %xmm1
	pshufd	$0x55, %xmm1, %xmm2
	pshufd	$0x00, %xmm1, %xmm1
	movdqa	%xmm2, 48+128(%rsp)
	movdqa	%xmm0, 48+144(%rsp)
	movdqa	%xmm0, 48+160(%rsp)
	movdqa	%xmm0, 48+176(%rsp)
	movdqa	%xmm0, 48+192(%rsp)
	movdqa	%xmm0, 48+208(%rsp)
	movdqa	%xmm0, 48+224(%rsp)
	movdqa	%xmm1, 48+240(%rsp)
	
	leaq	19*16(%rsp), %rax
	cmpq	%rax, %rax
	
	movdqa	-15*16(%rax), %xmm0
	movdqa	-14*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	paddd	-16*16(%rax), %xmm0
	paddd	-15*16(%rax), %xmm4
	paddd	sha256d_4preext2_17(%rip), %xmm4
	movdqa	%xmm0, %xmm3
	movdqa	%xmm4, %xmm7
	movdqa	%xmm3, 0*16(%rax)
	movdqa	%xmm7, 1*16(%rax)
	
	movdqa	(2-15)*16(%rax), %xmm0
	movdqa	(2-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(2-16)*16(%rax), %xmm0
	paddd	(2-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(2-7)*16(%rax), %xmm0
	paddd	(2-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 2*16(%rax)
	movdqa	%xmm7, (2+1)*16(%rax)
	movdqa	(4-15)*16(%rax), %xmm0
	movdqa	(4-14)*16(%rax), %xmm4
	movdqa	%xmm0, %xmm2
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm0
	psrld	$3, %xmm4
	movdqa	%xmm0, %xmm1
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm2
	pslld	$14, %xmm6
	psrld	$4, %xmm1
	psrld	$4, %xmm5
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	psrld	$11, %xmm1
	psrld	$11, %xmm5
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4
	pslld	$11, %xmm2
	pslld	$11, %xmm6
	pxor	%xmm1, %xmm0
	pxor	%xmm5, %xmm4
	pxor	%xmm2, %xmm0
	pxor	%xmm6, %xmm4

	paddd	(4-16)*16(%rax), %xmm0
	paddd	(4-15)*16(%rax), %xmm4

	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5

	paddd	(4-7)*16(%rax), %xmm0
	paddd	(4-6)*16(%rax), %xmm4

	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7

	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 4*16(%rax)
	movdqa	%xmm7, (4+1)*16(%rax)
	
	movdqa	-9*16(%rax), %xmm0
	movdqa	sha256d_4preext2_23(%rip), %xmm4
	movdqa	%xmm0, %xmm2
	psrld	$3, %xmm0
	movdqa	%xmm0, %xmm1
	pslld	$14, %xmm2
	psrld	$4, %xmm1
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	psrld	$11, %xmm1
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	paddd	-10*16(%rax), %xmm0
	paddd	-9*16(%rax), %xmm4
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	paddd	-1*16(%rax), %xmm0
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	paddd	0*16(%rax), %xmm4
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 6*16(%rax)
	movdqa	%xmm7, 7*16(%rax)
	
	movdqa	sha256d_4preext2_24(%rip), %xmm0
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	paddd	1*16(%rax), %xmm0
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	2*16(%rax), %xmm7
	movdqa	%xmm3, 8*16(%rax)
	movdqa	%xmm7, 9*16(%rax)
	
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	3*16(%rax), %xmm3
	paddd	4*16(%rax), %xmm7
	movdqa	%xmm3, 10*16(%rax)
	movdqa	%xmm7, 11*16(%rax)
	
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	5*16(%rax), %xmm3
	paddd	6*16(%rax), %xmm7
	movdqa	%xmm3, 12*16(%rax)
	movdqa	%xmm7, 13*16(%rax)
	
	movdqa	sha256d_4preext2_30(%rip), %xmm0
	movdqa	0*16(%rax), %xmm4
	movdqa	%xmm4, %xmm6
	psrld	$3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$14, %xmm6
	psrld	$4, %xmm5
	pxor	%xmm5, %xmm4
	pxor	%xmm6, %xmm4
	psrld	$11, %xmm5
	pslld	$11, %xmm6
	pxor	%xmm5, %xmm4
	pxor	%xmm6, %xmm4
	paddd	-1*16(%rax), %xmm4
	movdqa	%xmm3, %xmm2
	movdqa	%xmm7, %xmm6
	psrld	$10, %xmm3
	psrld	$10, %xmm7
	movdqa	%xmm3, %xmm1
	movdqa	%xmm7, %xmm5
	paddd	7*16(%rax), %xmm0
	pslld	$13, %xmm2
	pslld	$13, %xmm6
	psrld	$7, %xmm1
	psrld	$7, %xmm5
	paddd	8*16(%rax), %xmm4
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	psrld	$2, %xmm1
	psrld	$2, %xmm5
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	pslld	$2, %xmm2
	pslld	$2, %xmm6
	pxor	%xmm1, %xmm3
	pxor	%xmm5, %xmm7
	pxor	%xmm2, %xmm3
	pxor	%xmm6, %xmm7
	paddd	%xmm0, %xmm3
	paddd	%xmm4, %xmm7
	movdqa	%xmm3, 14*16(%rax)
	movdqa	%xmm7, 15*16(%rax)
	
	jmp sha256d_ms_4way_sse2_extend_loop2
	
sha256d_ms_4way_sse2_extend_coda2:
	movdqa	(44-15)*16(%rax), %xmm0
	movdqa	%xmm0, %xmm2
	psrld	$3, %xmm0
	movdqa	%xmm0, %xmm1
	pslld	$14, %xmm2
	psrld	$4, %xmm1
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	psrld	$11, %xmm1
	pslld	$11, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	paddd	(44-16)*16(%rax), %xmm0
	paddd	(44-7)*16(%rax), %xmm0

	movdqa	%xmm3, %xmm2
	psrld	$10, %xmm3
	pslld	$13, %xmm2
	movdqa	%xmm3, %xmm1
	psrld	$7, %xmm1
	pxor	%xmm1, %xmm3
	pxor	%xmm2, %xmm3
	psrld	$2, %xmm1
	pslld	$2, %xmm2
	pxor	%xmm1, %xmm3
	pxor	%xmm2, %xmm3
	paddd	%xmm0, %xmm3
	movdqa	%xmm3, 44*16(%rax)
	
	movdqa	sha256_4h+0(%rip), %xmm7
	movdqa	sha256_4h+16(%rip), %xmm5
	movdqa	sha256_4h+32(%rip), %xmm4
	movdqa	sha256_4h+48(%rip), %xmm3
	movdqa	sha256_4h+64(%rip), %xmm0
	movdqa	sha256_4h+80(%rip), %xmm1
	movdqa	sha256_4h+96(%rip), %xmm2
	movdqa	sha256_4h+112(%rip), %xmm6
	movdqa	%xmm1, 0(%rsp)
	movdqa	%xmm2, 16(%rsp)
	movdqa	%xmm6, 32(%rsp)
	
	leaq	48(%rsp), %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_sse2_main_loop2


sha256d_ms_4way_sse2_finish:
	movdqa	16*57(%rax), %xmm6
	paddd	16*57(%rcx), %xmm6
	paddd	32(%rsp), %xmm6
	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	paddd	%xmm3, %xmm6
	pandn	%xmm2, %xmm1
	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)
	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)
	paddd	%xmm1, %xmm6
	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm1, %xmm0
	paddd	%xmm6, %xmm0
	movdqa	16*58(%rax), %xmm6
	paddd	16*58(%rcx), %xmm6
	paddd	32(%rsp), %xmm6
	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	paddd	%xmm4, %xmm6
	pandn	%xmm2, %xmm1
	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)
	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)
	paddd	%xmm1, %xmm6
	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm1, %xmm0
	paddd	%xmm6, %xmm0
	movdqa	16*59(%rax), %xmm6
	paddd	16*59(%rcx), %xmm6
	paddd	32(%rsp), %xmm6
	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	paddd	%xmm5, %xmm6
	pandn	%xmm2, %xmm1
	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)
	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)
	paddd	%xmm1, %xmm6
	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm1, %xmm0
	paddd	%xmm6, %xmm0
	movdqa	16*60(%rax), %xmm6
	paddd	16*60(%rcx), %xmm6
	paddd	32(%rsp), %xmm6
	movdqa	%xmm0, %xmm1
	movdqa	16(%rsp), %xmm2
	paddd	%xmm7, %xmm6
	pandn	%xmm2, %xmm1
	movdqa	%xmm2, 32(%rsp)
	movdqa	0(%rsp), %xmm2
	movdqa	%xmm2, 16(%rsp)
	pand	%xmm0, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm0, 0(%rsp)
	paddd	%xmm1, %xmm6
	movdqa	%xmm0, %xmm1
	psrld	$6, %xmm0
	movdqa	%xmm0, %xmm2
	pslld	$7, %xmm1
	psrld	$5, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$14, %xmm1
	psrld	$14, %xmm2
	pxor	%xmm1, %xmm0
	pxor	%xmm2, %xmm0
	pslld	$5, %xmm1
	pxor	%xmm1, %xmm0
	paddd	%xmm6, %xmm0
	
	paddd	sha256_4h+112(%rip), %xmm0
	movdqa	%xmm0, 112(%rdi)
	
	addq	$8+67*16, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	movdqa	0(%rsp), %xmm6
	movdqa	16(%rsp), %xmm7
	addq	$32, %rsp
	popq	%rdi
#endif
	ret
	
	
#if defined(USE_AVX)
	
	.p2align 6
sha256d_ms_4way_avx:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$80, %rsp
	movdqa	%xmm6, 0(%rsp)
	movdqa	%xmm7, 16(%rsp)
	movdqa	%xmm8, 32(%rsp)
	movdqa	%xmm9, 48(%rsp)
	movdqa	%xmm10, 64(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
	movq	%r9, %rcx
#endif
	subq	$1032, %rsp
	
	leaq	256(%rsi), %rax
	
sha256d_ms_4way_avx_extend_loop1:
	vmovdqa	3*16(%rsi), %xmm0
	vmovdqa	2*16(%rax), %xmm3
	vmovdqa	3*16(%rax), %xmm7
	vmovdqa	%xmm3, 2*16(%rsp)
	vmovdqa	%xmm7, 3*16(%rsp)
	vpaddd	%xmm0, %xmm7, %xmm7
	vpslld	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$4, %xmm0, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpsrld	$11, %xmm1, %xmm1
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, 3*16(%rax)
	
	vmovdqa	4*16(%rax), %xmm0
	vmovdqa	%xmm0, 4*16(%rsp)
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, 5*16(%rax)
	
	vmovdqa	6*16(%rax), %xmm0
	vmovdqa	7*16(%rax), %xmm4
	vmovdqa	%xmm0, 6*16(%rsp)
	vmovdqa	%xmm4, 7*16(%rsp)
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, 7*16(%rax)
	
	vmovdqa	8*16(%rax), %xmm0
	vmovdqa	2*16(%rax), %xmm4
	vmovdqa	%xmm0, 8*16(%rsp)
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, 9*16(%rax)
	
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	3*16(%rax), %xmm3, %xmm3
	vpaddd	4*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, 11*16(%rax)
	
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	5*16(%rax), %xmm3, %xmm3
	vpaddd	6*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, 13*16(%rax)
	
	vmovdqa	14*16(%rax), %xmm0
	vmovdqa	15*16(%rax), %xmm4
	vmovdqa	%xmm0, 14*16(%rsp)
	vmovdqa	%xmm4, 15*16(%rsp)
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpaddd	7*16(%rax), %xmm0, %xmm0
	vpaddd	8*16(%rax), %xmm4, %xmm4
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, 15*16(%rax)
	
sha256d_ms_4way_avx_extend_loop2:
	vmovdqa	(16-15)*16(%rax), %xmm0
	vmovdqa	(16-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(16-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(16-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 16*16(%rax)
	vmovdqa	%xmm7, (16+1)*16(%rax)
	vmovdqa	(18-15)*16(%rax), %xmm0
	vmovdqa	(18-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(18-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(18-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 18*16(%rax)
	vmovdqa	%xmm7, (18+1)*16(%rax)
	vmovdqa	(20-15)*16(%rax), %xmm0
	vmovdqa	(20-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(20-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(20-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 20*16(%rax)
	vmovdqa	%xmm7, (20+1)*16(%rax)
	vmovdqa	(22-15)*16(%rax), %xmm0
	vmovdqa	(22-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(22-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(22-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 22*16(%rax)
	vmovdqa	%xmm7, (22+1)*16(%rax)
	vmovdqa	(24-15)*16(%rax), %xmm0
	vmovdqa	(24-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(24-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(24-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 24*16(%rax)
	vmovdqa	%xmm7, (24+1)*16(%rax)
	vmovdqa	(26-15)*16(%rax), %xmm0
	vmovdqa	(26-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(26-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(26-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 26*16(%rax)
	vmovdqa	%xmm7, (26+1)*16(%rax)
	vmovdqa	(28-15)*16(%rax), %xmm0
	vmovdqa	(28-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(28-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(28-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 28*16(%rax)
	vmovdqa	%xmm7, (28+1)*16(%rax)
	vmovdqa	(30-15)*16(%rax), %xmm0
	vmovdqa	(30-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(30-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(30-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 30*16(%rax)
	vmovdqa	%xmm7, (30+1)*16(%rax)
	vmovdqa	(32-15)*16(%rax), %xmm0
	vmovdqa	(32-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(32-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(32-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 32*16(%rax)
	vmovdqa	%xmm7, (32+1)*16(%rax)
	vmovdqa	(34-15)*16(%rax), %xmm0
	vmovdqa	(34-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(34-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(34-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 34*16(%rax)
	vmovdqa	%xmm7, (34+1)*16(%rax)
	vmovdqa	(36-15)*16(%rax), %xmm0
	vmovdqa	(36-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(36-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(36-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 36*16(%rax)
	vmovdqa	%xmm7, (36+1)*16(%rax)
	vmovdqa	(38-15)*16(%rax), %xmm0
	vmovdqa	(38-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(38-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(38-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 38*16(%rax)
	vmovdqa	%xmm7, (38+1)*16(%rax)
	vmovdqa	(40-15)*16(%rax), %xmm0
	vmovdqa	(40-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(40-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(40-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 40*16(%rax)
	vmovdqa	%xmm7, (40+1)*16(%rax)
	vmovdqa	(42-15)*16(%rax), %xmm0
	vmovdqa	(42-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(42-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(42-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 42*16(%rax)
	vmovdqa	%xmm7, (42+1)*16(%rax)
	jz sha256d_ms_4way_avx_extend_coda2
	vmovdqa	(44-15)*16(%rax), %xmm0
	vmovdqa	(44-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(44-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 44*16(%rax)
	vmovdqa	%xmm7, (44+1)*16(%rax)
	vmovdqa	(46-15)*16(%rax), %xmm0
	vmovdqa	(46-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(46-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(46-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 46*16(%rax)
	vmovdqa	%xmm7, (46+1)*16(%rax)
	
	movdqa	0(%rcx), %xmm7
	movdqa	16(%rcx), %xmm8
	movdqa	32(%rcx), %xmm9
	movdqa	48(%rcx), %xmm10
	movdqa	64(%rcx), %xmm0
	movdqa	80(%rcx), %xmm5
	movdqa	96(%rcx), %xmm4
	movdqa	112(%rcx), %xmm3
	
	movq	%rsi, %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_avx_main_loop1
	
sha256d_ms_4way_avx_main_loop2:
	vpaddd	16*(0)(%rax), %xmm10, %xmm6
	vpaddd	16*(0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(1)(%rax), %xmm9, %xmm6
	vpaddd	16*(1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(2)(%rax), %xmm8, %xmm6
	vpaddd	16*(2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
sha256d_ms_4way_avx_main_loop1:
	vpaddd	16*(3)(%rax), %xmm0, %xmm6
	vpaddd	16*(3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(4+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(4+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(4+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(4+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(4+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(4+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(4+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(4+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(8+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(8+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(8+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(8+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(8+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(8+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(8+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(8+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(12+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(12+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(12+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(12+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(12+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(12+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(12+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(12+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(16+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(16+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(16+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(16+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(16+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(16+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(16+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(16+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(20+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(20+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(20+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(20+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(20+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(20+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(20+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(20+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(24+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(24+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(24+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(24+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(24+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(24+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(24+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(24+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(28+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(28+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(28+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(28+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(28+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(28+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(28+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(28+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(32+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(32+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(32+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(32+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(32+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(32+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(32+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(32+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(36+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(36+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(36+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(36+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(36+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(36+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(36+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(36+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(40+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(40+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(40+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(40+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(40+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(40+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(40+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(40+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(44+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(44+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(44+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(44+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(44+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(44+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(44+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(44+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(48+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(48+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(48+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(48+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(48+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(48+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(48+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(48+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(52+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(52+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(52+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(52+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(52+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(52+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(52+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(52+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(56)(%rax), %xmm10, %xmm6
	vpaddd	16*(56)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	jz sha256d_ms_4way_avx_finish
	vpaddd	16*(57)(%rax), %xmm9, %xmm6
	vpaddd	16*(57)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(58)(%rax), %xmm8, %xmm6
	vpaddd	16*(58)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(59)(%rax), %xmm0, %xmm6
	vpaddd	16*(59)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(60+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(60+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm7, %xmm2
	vpsrld	$2, %xmm7, %xmm3
	vpsrld	$11, %xmm3, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm1, %xmm3, %xmm3
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(60+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(60+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm3, %xmm2
	vpsrld	$2, %xmm3, %xmm4
	vpsrld	$11, %xmm4, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm4, %xmm4
	vpxor	%xmm1, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(60+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(60+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm4, %xmm2
	vpsrld	$2, %xmm4, %xmm5
	vpsrld	$11, %xmm5, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm5
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(60+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(60+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vpslld	$10, %xmm5, %xmm2
	vpsrld	$2, %xmm5, %xmm7
	vpsrld	$11, %xmm7, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$9, %xmm2, %xmm2
	vpsrld	$9, %xmm1, %xmm1
	vpxor	%xmm2, %xmm7, %xmm7
	vpxor	%xmm1, %xmm7, %xmm7
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	
	movdqa	2*16(%rsp), %xmm1
	movdqa	3*16(%rsp), %xmm2
	movdqa	4*16(%rsp), %xmm6
	movdqa	%xmm1, 18*16(%rsi)
	movdqa	%xmm2, 19*16(%rsi)
	movdqa	%xmm6, 20*16(%rsi)
	movdqa	6*16(%rsp), %xmm1
	movdqa	7*16(%rsp), %xmm2
	movdqa	8*16(%rsp), %xmm6
	movdqa	%xmm1, 22*16(%rsi)
	movdqa	%xmm2, 23*16(%rsi)
	movdqa	%xmm6, 24*16(%rsi)
	movdqa	14*16(%rsp), %xmm1
	movdqa	15*16(%rsp), %xmm2
	movdqa	%xmm1, 30*16(%rsi)
	movdqa	%xmm2, 31*16(%rsi)
	
	paddd	0(%rdx), %xmm7
	paddd	16(%rdx), %xmm5
	paddd	32(%rdx), %xmm4
	paddd	48(%rdx), %xmm3
	paddd	64(%rdx), %xmm0
	paddd	80(%rdx), %xmm8
	paddd	96(%rdx), %xmm9
	paddd	112(%rdx), %xmm10
	
	movdqa	%xmm7, 0(%rsp)
	movdqa	%xmm5, 16(%rsp)
	movdqa	%xmm4, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm8, 80(%rsp)
	movdqa	%xmm9, 96(%rsp)
	movdqa	%xmm10, 112(%rsp)
	
	pxor	%xmm0, %xmm0
	movq	$0x8000000000000100, %rax
	movd	%rax, %xmm1
	pshufd	$0x55, %xmm1, %xmm2
	pshufd	$0x00, %xmm1, %xmm1
	movdqa	%xmm2, 128(%rsp)
	movdqa	%xmm0, 144(%rsp)
	movdqa	%xmm0, 160(%rsp)
	movdqa	%xmm0, 176(%rsp)
	movdqa	%xmm0, 192(%rsp)
	movdqa	%xmm0, 208(%rsp)
	movdqa	%xmm0, 224(%rsp)
	movdqa	%xmm1, 240(%rsp)
	
	leaq	256(%rsp), %rax
	cmpq	%rax, %rax
	
	vmovdqa	-15*16(%rax), %xmm0
	vmovdqa	-14*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	-16*16(%rax), %xmm8, %xmm3
	vpaddd	sha256d_4preext2_17(%rip), %xmm4, %xmm7
	vmovdqa	%xmm3, 0*16(%rax)
	vmovdqa	%xmm7, 1*16(%rax)
	
	vmovdqa	(2-15)*16(%rax), %xmm0
	vmovdqa	(2-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(2-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(2-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, (2+1)*16(%rax)
	vmovdqa	(4-15)*16(%rax), %xmm0
	vmovdqa	(4-14)*16(%rax), %xmm4
	vpslld	$14, %xmm0, %xmm2
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$7, %xmm0, %xmm1
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrld	$11, %xmm1, %xmm1
	vpsrld	$11, %xmm5, %xmm5
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpslld	$11, %xmm2, %xmm2
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	(4-16)*16(%rax), %xmm8, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7

	vpaddd	(4-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, (4+1)*16(%rax)
	
	vmovdqa	-9*16(%rax), %xmm0
	vpslld	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$7, %xmm0, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpsrld	$11, %xmm1, %xmm1
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	sha256d_4preext2_23(%rip), %xmm0, %xmm4
	vpaddd	-10*16(%rax), %xmm8, %xmm0
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpaddd	-1*16(%rax), %xmm0, %xmm0
	vpaddd	0*16(%rax), %xmm4, %xmm4
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, 7*16(%rax)
	
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	sha256d_4preext2_24(%rip), %xmm3, %xmm3
	vpaddd	1*16(%rax), %xmm3, %xmm3
	vpaddd	2*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, 9*16(%rax)
	
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	3*16(%rax), %xmm3, %xmm3
	vpaddd	4*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, 11*16(%rax)
	
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	5*16(%rax), %xmm3, %xmm3
	vpaddd	6*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, 13*16(%rax)
	
	vmovdqa	sha256d_4preext2_30(%rip), %xmm0
	vmovdqa	0*16(%rax), %xmm4
	vpslld	$14, %xmm4, %xmm6
	vpsrld	$3, %xmm4, %xmm4
	vpsrld	$4, %xmm4, %xmm5
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm6, %xmm4, %xmm4
	vpsrld	$11, %xmm5, %xmm5
	vpslld	$11, %xmm6, %xmm6
	vpxor	%xmm5, %xmm4, %xmm4
	vpxor	%xmm6, %xmm4, %xmm4
	vpaddd	-1*16(%rax), %xmm4, %xmm4
	vpslld	$13, %xmm3, %xmm2
	vpslld	$13, %xmm7, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpaddd	7*16(%rax), %xmm0, %xmm0
	vpaddd	8*16(%rax), %xmm4, %xmm4
	vpsrld	$7, %xmm3, %xmm1
	vpsrld	$7, %xmm7, %xmm5
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpsrld	$2, %xmm1, %xmm1
	vpsrld	$2, %xmm5, %xmm5
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpslld	$2, %xmm2, %xmm2
	vpslld	$2, %xmm6, %xmm6
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm5, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, 15*16(%rax)
	
	jmp sha256d_ms_4way_avx_extend_loop2
	
sha256d_ms_4way_avx_extend_coda2:
	vmovdqa	(44-15)*16(%rax), %xmm0
	vpslld	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$4, %xmm0, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpsrld	$11, %xmm1, %xmm1
	vpslld	$11, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	(44-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0

	vpslld	$13, %xmm3, %xmm2
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$7, %xmm3, %xmm1
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpsrld	$2, %xmm1, %xmm1
	vpslld	$2, %xmm2, %xmm2
	vpxor	%xmm1, %xmm3, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 44*16(%rax)
	
	movdqa	sha256_4h+0(%rip), %xmm7
	movdqa	sha256_4h+16(%rip), %xmm5
	movdqa	sha256_4h+32(%rip), %xmm4
	movdqa	sha256_4h+48(%rip), %xmm3
	movdqa	sha256_4h+64(%rip), %xmm0
	movdqa	sha256_4h+80(%rip), %xmm8
	movdqa	sha256_4h+96(%rip), %xmm9
	movdqa	sha256_4h+112(%rip), %xmm10
	
	movq	%rsp, %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_avx_main_loop2


sha256d_ms_4way_avx_finish:
	vpaddd	16*57(%rax), %xmm9, %xmm6
	vpaddd	16*57(%rcx), %xmm6, %xmm6
	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vpslld	$7, %xmm10, %xmm1
	vpsrld	$6, %xmm10, %xmm9
	vpsrld	$5, %xmm9, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm9, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9
	vpaddd	16*58(%rax), %xmm8, %xmm6
	vpaddd	16*58(%rcx), %xmm6, %xmm6
	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vpslld	$7, %xmm9, %xmm1
	vpsrld	$6, %xmm9, %xmm8
	vpsrld	$5, %xmm8, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm8, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8
	vpaddd	16*59(%rax), %xmm0, %xmm6
	vpaddd	16*59(%rcx), %xmm6, %xmm6
	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vpslld	$7, %xmm8, %xmm1
	vpsrld	$6, %xmm8, %xmm0
	vpsrld	$5, %xmm0, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0
	vpaddd	16*60(%rax), %xmm10, %xmm6
	vpaddd	16*60(%rcx), %xmm6, %xmm6
	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vpslld	$7, %xmm0, %xmm1
	vpsrld	$6, %xmm0, %xmm10
	vpsrld	$5, %xmm10, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$14, %xmm1, %xmm1
	vpsrld	$14, %xmm2, %xmm2
	vpxor	%xmm1, %xmm10, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpslld	$5, %xmm1, %xmm1
	vpxor	%xmm1, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10
	
	paddd	sha256_4h+112(%rip), %xmm10
	movdqa	%xmm10, 112(%rdi)
	
	addq	$1032, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	movdqa	0(%rsp), %xmm6
	movdqa	16(%rsp), %xmm7
	movdqa	32(%rsp), %xmm8
	movdqa	48(%rsp), %xmm9
	movdqa	64(%rsp), %xmm10
	addq	$80, %rsp
	popq	%rdi
#endif
	ret
	
#endif /* USE_AVX */
	
	
#if defined(USE_XOP)
	
	.p2align 6
sha256d_ms_4way_xop:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$80, %rsp
	movdqa	%xmm6, 0(%rsp)
	movdqa	%xmm7, 16(%rsp)
	movdqa	%xmm8, 32(%rsp)
	movdqa	%xmm9, 48(%rsp)
	movdqa	%xmm10, 64(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
	movq	%r9, %rcx
#endif
	subq	$1032, %rsp
	
	leaq	256(%rsi), %rax
	
sha256d_ms_4way_xop_extend_loop1:
	vmovdqa	3*16(%rsi), %xmm0
	vmovdqa	2*16(%rax), %xmm3
	vmovdqa	3*16(%rax), %xmm7
	vmovdqa	%xmm3, 2*16(%rsp)
	vmovdqa	%xmm7, 3*16(%rsp)
	vpaddd	%xmm0, %xmm7, %xmm7
	vprotd	$25, %xmm0, %xmm1
	vprotd	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm0
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, 3*16(%rax)
	
	vmovdqa	4*16(%rax), %xmm0
	vmovdqa	%xmm0, 4*16(%rsp)
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, 5*16(%rax)
	
	vmovdqa	6*16(%rax), %xmm0
	vmovdqa	7*16(%rax), %xmm4
	vmovdqa	%xmm0, 6*16(%rsp)
	vmovdqa	%xmm4, 7*16(%rsp)
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, 7*16(%rax)
	
	vmovdqa	8*16(%rax), %xmm0
	vmovdqa	2*16(%rax), %xmm4
	vmovdqa	%xmm0, 8*16(%rsp)
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, 9*16(%rax)
	
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	3*16(%rax), %xmm3, %xmm3
	vpaddd	4*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, 11*16(%rax)
	
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	5*16(%rax), %xmm3, %xmm3
	vpaddd	6*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, 13*16(%rax)
	
	vmovdqa	14*16(%rax), %xmm0
	vmovdqa	15*16(%rax), %xmm4
	vmovdqa	%xmm0, 14*16(%rsp)
	vmovdqa	%xmm4, 15*16(%rsp)
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpaddd	7*16(%rax), %xmm0, %xmm0
	vpaddd	8*16(%rax), %xmm4, %xmm4
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, 15*16(%rax)
	
sha256d_ms_4way_xop_extend_loop2:
	vmovdqa	(16-15)*16(%rax), %xmm0
	vmovdqa	(16-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(16-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(16-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(16-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 16*16(%rax)
	vmovdqa	%xmm7, (16+1)*16(%rax)
	vmovdqa	(18-15)*16(%rax), %xmm0
	vmovdqa	(18-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(18-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(18-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(18-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 18*16(%rax)
	vmovdqa	%xmm7, (18+1)*16(%rax)
	vmovdqa	(20-15)*16(%rax), %xmm0
	vmovdqa	(20-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(20-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(20-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(20-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 20*16(%rax)
	vmovdqa	%xmm7, (20+1)*16(%rax)
	vmovdqa	(22-15)*16(%rax), %xmm0
	vmovdqa	(22-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(22-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(22-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(22-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 22*16(%rax)
	vmovdqa	%xmm7, (22+1)*16(%rax)
	vmovdqa	(24-15)*16(%rax), %xmm0
	vmovdqa	(24-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(24-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(24-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(24-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 24*16(%rax)
	vmovdqa	%xmm7, (24+1)*16(%rax)
	vmovdqa	(26-15)*16(%rax), %xmm0
	vmovdqa	(26-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(26-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(26-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(26-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 26*16(%rax)
	vmovdqa	%xmm7, (26+1)*16(%rax)
	vmovdqa	(28-15)*16(%rax), %xmm0
	vmovdqa	(28-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(28-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(28-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(28-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 28*16(%rax)
	vmovdqa	%xmm7, (28+1)*16(%rax)
	vmovdqa	(30-15)*16(%rax), %xmm0
	vmovdqa	(30-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(30-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(30-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(30-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 30*16(%rax)
	vmovdqa	%xmm7, (30+1)*16(%rax)
	vmovdqa	(32-15)*16(%rax), %xmm0
	vmovdqa	(32-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(32-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(32-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(32-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 32*16(%rax)
	vmovdqa	%xmm7, (32+1)*16(%rax)
	vmovdqa	(34-15)*16(%rax), %xmm0
	vmovdqa	(34-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(34-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(34-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(34-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 34*16(%rax)
	vmovdqa	%xmm7, (34+1)*16(%rax)
	vmovdqa	(36-15)*16(%rax), %xmm0
	vmovdqa	(36-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(36-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(36-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(36-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 36*16(%rax)
	vmovdqa	%xmm7, (36+1)*16(%rax)
	vmovdqa	(38-15)*16(%rax), %xmm0
	vmovdqa	(38-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(38-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(38-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(38-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 38*16(%rax)
	vmovdqa	%xmm7, (38+1)*16(%rax)
	vmovdqa	(40-15)*16(%rax), %xmm0
	vmovdqa	(40-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(40-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(40-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(40-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 40*16(%rax)
	vmovdqa	%xmm7, (40+1)*16(%rax)
	vmovdqa	(42-15)*16(%rax), %xmm0
	vmovdqa	(42-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(42-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(42-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(42-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 42*16(%rax)
	vmovdqa	%xmm7, (42+1)*16(%rax)
	jz sha256d_ms_4way_xop_extend_coda2
	vmovdqa	(44-15)*16(%rax), %xmm0
	vmovdqa	(44-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(44-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 44*16(%rax)
	vmovdqa	%xmm7, (44+1)*16(%rax)
	vmovdqa	(46-15)*16(%rax), %xmm0
	vmovdqa	(46-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(46-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(46-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(46-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 46*16(%rax)
	vmovdqa	%xmm7, (46+1)*16(%rax)
	
	movdqa	0(%rcx), %xmm7
	movdqa	16(%rcx), %xmm8
	movdqa	32(%rcx), %xmm9
	movdqa	48(%rcx), %xmm10
	movdqa	64(%rcx), %xmm0
	movdqa	80(%rcx), %xmm5
	movdqa	96(%rcx), %xmm4
	movdqa	112(%rcx), %xmm3
	
	movq	%rsi, %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_xop_main_loop1
	
sha256d_ms_4way_xop_main_loop2:
	vpaddd	16*(0)(%rax), %xmm10, %xmm6
	vpaddd	16*(0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(1)(%rax), %xmm9, %xmm6
	vpaddd	16*(1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(2)(%rax), %xmm8, %xmm6
	vpaddd	16*(2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
sha256d_ms_4way_xop_main_loop1:
	vpaddd	16*(3)(%rax), %xmm0, %xmm6
	vpaddd	16*(3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(4+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(4+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(4+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(4+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(4+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(4+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(4+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(4+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(8+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(8+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(8+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(8+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(8+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(8+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(8+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(8+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(12+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(12+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(12+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(12+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(12+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(12+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(12+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(12+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(16+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(16+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(16+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(16+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(16+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(16+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(16+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(16+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(20+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(20+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(20+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(20+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(20+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(20+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(20+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(20+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(24+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(24+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(24+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(24+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(24+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(24+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(24+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(24+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(28+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(28+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(28+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(28+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(28+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(28+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(28+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(28+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(32+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(32+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(32+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(32+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(32+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(32+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(32+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(32+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(36+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(36+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(36+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(36+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(36+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(36+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(36+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(36+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(40+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(40+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(40+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(40+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(40+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(40+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(40+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(40+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(44+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(44+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(44+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(44+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(44+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(44+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(44+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(44+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(48+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(48+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(48+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(48+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(48+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(48+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(48+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(48+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(52+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(52+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(52+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(52+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(52+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(52+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(52+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(52+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(56)(%rax), %xmm10, %xmm6
	vpaddd	16*(56)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	jz sha256d_ms_4way_xop_finish
	vpaddd	16*(57)(%rax), %xmm9, %xmm6
	vpaddd	16*(57)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(58)(%rax), %xmm8, %xmm6
	vpaddd	16*(58)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(59)(%rax), %xmm0, %xmm6
	vpaddd	16*(59)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	vpaddd	16*(60+0)(%rax), %xmm10, %xmm6
	vpaddd	16*(60+0)(%rcx), %xmm6, %xmm6

	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10

	vpand	%xmm5, %xmm4, %xmm2
	vpand	%xmm7, %xmm4, %xmm3
	vpand	%xmm7, %xmm5, %xmm1
	vpxor	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm7, %xmm1
	vprotd	$19, %xmm7, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm7, %xmm3
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm6, %xmm3, %xmm3
	vpaddd	16*(60+1)(%rax), %xmm9, %xmm6
	vpaddd	16*(60+1)(%rcx), %xmm6, %xmm6

	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9

	vpand	%xmm7, %xmm5, %xmm2
	vpand	%xmm3, %xmm5, %xmm4
	vpand	%xmm3, %xmm7, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm3, %xmm1
	vprotd	$19, %xmm3, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm3, %xmm4
	vpxor	%xmm2, %xmm4, %xmm4
	vpaddd	%xmm6, %xmm4, %xmm4
	vpaddd	16*(60+2)(%rax), %xmm8, %xmm6
	vpaddd	16*(60+2)(%rcx), %xmm6, %xmm6

	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8

	vpand	%xmm3, %xmm7, %xmm2
	vpand	%xmm4, %xmm7, %xmm5
	vpand	%xmm4, %xmm3, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm4, %xmm1
	vprotd	$19, %xmm4, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm4, %xmm5
	vpxor	%xmm2, %xmm5, %xmm5
	vpaddd	%xmm6, %xmm5, %xmm5
	vpaddd	16*(60+3)(%rax), %xmm0, %xmm6
	vpaddd	16*(60+3)(%rcx), %xmm6, %xmm6

	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0

	vpand	%xmm4, %xmm3, %xmm2
	vpand	%xmm5, %xmm3, %xmm7
	vpand	%xmm5, %xmm4, %xmm1
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6

	vprotd	$30, %xmm5, %xmm1
	vprotd	$19, %xmm5, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$10, %xmm5, %xmm7
	vpxor	%xmm2, %xmm7, %xmm7
	vpaddd	%xmm6, %xmm7, %xmm7
	
	movdqa	2*16(%rsp), %xmm1
	movdqa	3*16(%rsp), %xmm2
	movdqa	4*16(%rsp), %xmm6
	movdqa	%xmm1, 18*16(%rsi)
	movdqa	%xmm2, 19*16(%rsi)
	movdqa	%xmm6, 20*16(%rsi)
	movdqa	6*16(%rsp), %xmm1
	movdqa	7*16(%rsp), %xmm2
	movdqa	8*16(%rsp), %xmm6
	movdqa	%xmm1, 22*16(%rsi)
	movdqa	%xmm2, 23*16(%rsi)
	movdqa	%xmm6, 24*16(%rsi)
	movdqa	14*16(%rsp), %xmm1
	movdqa	15*16(%rsp), %xmm2
	movdqa	%xmm1, 30*16(%rsi)
	movdqa	%xmm2, 31*16(%rsi)
	
	paddd	0(%rdx), %xmm7
	paddd	16(%rdx), %xmm5
	paddd	32(%rdx), %xmm4
	paddd	48(%rdx), %xmm3
	paddd	64(%rdx), %xmm0
	paddd	80(%rdx), %xmm8
	paddd	96(%rdx), %xmm9
	paddd	112(%rdx), %xmm10
	
	movdqa	%xmm7, 0(%rsp)
	movdqa	%xmm5, 16(%rsp)
	movdqa	%xmm4, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm8, 80(%rsp)
	movdqa	%xmm9, 96(%rsp)
	movdqa	%xmm10, 112(%rsp)
	
	pxor	%xmm0, %xmm0
	movq	$0x8000000000000100, %rax
	movd	%rax, %xmm1
	pshufd	$0x55, %xmm1, %xmm2
	pshufd	$0x00, %xmm1, %xmm1
	movdqa	%xmm2, 128(%rsp)
	movdqa	%xmm0, 144(%rsp)
	movdqa	%xmm0, 160(%rsp)
	movdqa	%xmm0, 176(%rsp)
	movdqa	%xmm0, 192(%rsp)
	movdqa	%xmm0, 208(%rsp)
	movdqa	%xmm0, 224(%rsp)
	movdqa	%xmm1, 240(%rsp)
	
	leaq	256(%rsp), %rax
	cmpq	%rax, %rax
	
	vmovdqa	-15*16(%rax), %xmm0
	vmovdqa	-14*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm8
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm8, %xmm8
	vpxor	%xmm6, %xmm4, %xmm4
	vpaddd	%xmm0, %xmm4, %xmm4
	vpaddd	-16*16(%rax), %xmm8, %xmm3
	vpaddd	sha256d_4preext2_17(%rip), %xmm4, %xmm7
	vmovdqa	%xmm3, 0*16(%rax)
	vmovdqa	%xmm7, 1*16(%rax)
	
	vmovdqa	(2-15)*16(%rax), %xmm0
	vmovdqa	(2-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(2-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(2-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(2-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 2*16(%rax)
	vmovdqa	%xmm7, (2+1)*16(%rax)
	vmovdqa	(4-15)*16(%rax), %xmm0
	vmovdqa	(4-14)*16(%rax), %xmm4
	vprotd	$25, %xmm0, %xmm1
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm0, %xmm2
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm0, %xmm0
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm6, %xmm4, %xmm4

	vpaddd	(4-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-15)*16(%rax), %xmm4, %xmm4

	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6

	vpaddd	(4-7)*16(%rax), %xmm0, %xmm0
	vpaddd	(4-6)*16(%rax), %xmm4, %xmm4

	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7

	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 4*16(%rax)
	vmovdqa	%xmm7, (4+1)*16(%rax)
	
	vmovdqa	-9*16(%rax), %xmm0
	vprotd	$25, %xmm0, %xmm1
	vprotd	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm8
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	sha256d_4preext2_23(%rip), %xmm0, %xmm4
	vpaddd	-10*16(%rax), %xmm8, %xmm0
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpaddd	-1*16(%rax), %xmm0, %xmm0
	vpaddd	0*16(%rax), %xmm4, %xmm4
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 6*16(%rax)
	vmovdqa	%xmm7, 7*16(%rax)
	
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	sha256d_4preext2_24(%rip), %xmm3, %xmm3
	vpaddd	1*16(%rax), %xmm3, %xmm3
	vpaddd	2*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 8*16(%rax)
	vmovdqa	%xmm7, 9*16(%rax)
	
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	3*16(%rax), %xmm3, %xmm3
	vpaddd	4*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 10*16(%rax)
	vmovdqa	%xmm7, 11*16(%rax)
	
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	5*16(%rax), %xmm3, %xmm3
	vpaddd	6*16(%rax), %xmm7, %xmm7
	vmovdqa	%xmm3, 12*16(%rax)
	vmovdqa	%xmm7, 13*16(%rax)
	
	vmovdqa	sha256d_4preext2_30(%rip), %xmm0
	vmovdqa	0*16(%rax), %xmm4
	vprotd	$25, %xmm4, %xmm5
	vprotd	$14, %xmm4, %xmm6
	vpxor	%xmm5, %xmm6, %xmm6
	vpsrld	$3, %xmm4, %xmm4
	vpxor	%xmm6, %xmm4, %xmm4
	vpaddd	-1*16(%rax), %xmm4, %xmm4
	vprotd	$15, %xmm3, %xmm1
	vprotd	$15, %xmm7, %xmm5
	vprotd	$13, %xmm3, %xmm2
	vprotd	$13, %xmm7, %xmm6
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm5, %xmm6, %xmm6
	vpaddd	7*16(%rax), %xmm0, %xmm0
	vpaddd	8*16(%rax), %xmm4, %xmm4
	vpsrld	$10, %xmm3, %xmm3
	vpsrld	$10, %xmm7, %xmm7
	vpxor	%xmm2, %xmm3, %xmm3
	vpxor	%xmm6, %xmm7, %xmm7
	vpaddd	%xmm0, %xmm3, %xmm3
	vpaddd	%xmm4, %xmm7, %xmm7
	vmovdqa	%xmm3, 14*16(%rax)
	vmovdqa	%xmm7, 15*16(%rax)
	
	jmp sha256d_ms_4way_xop_extend_loop2
	
sha256d_ms_4way_xop_extend_coda2:
	vmovdqa	(44-15)*16(%rax), %xmm0
	vprotd	$25, %xmm0, %xmm1
	vprotd	$14, %xmm0, %xmm2
	vpsrld	$3, %xmm0, %xmm0
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0

	vpaddd	(44-16)*16(%rax), %xmm0, %xmm0
	vpaddd	(44-7)*16(%rax), %xmm0, %xmm0

	vprotd	$15, %xmm3, %xmm1
	vprotd	$13, %xmm3, %xmm2
	vpsrld	$10, %xmm3, %xmm3
	vpxor	%xmm1, %xmm2, %xmm2
	vpxor	%xmm2, %xmm3, %xmm3
	vpaddd	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm3, 44*16(%rax)
	
	movdqa	sha256_4h+0(%rip), %xmm7
	movdqa	sha256_4h+16(%rip), %xmm5
	movdqa	sha256_4h+32(%rip), %xmm4
	movdqa	sha256_4h+48(%rip), %xmm3
	movdqa	sha256_4h+64(%rip), %xmm0
	movdqa	sha256_4h+80(%rip), %xmm8
	movdqa	sha256_4h+96(%rip), %xmm9
	movdqa	sha256_4h+112(%rip), %xmm10
	
	movq	%rsp, %rax
	leaq	sha256_4k(%rip), %rcx
	jmp sha256d_ms_4way_xop_main_loop2


sha256d_ms_4way_xop_finish:
	vpaddd	16*57(%rax), %xmm9, %xmm6
	vpaddd	16*57(%rcx), %xmm6, %xmm6
	vpandn	%xmm8, %xmm10, %xmm1
	vpand	%xmm10, %xmm0, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vprotd	$26, %xmm10, %xmm1
	vprotd	$21, %xmm10, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm10, %xmm9
	vpxor	%xmm2, %xmm9, %xmm9
	vpaddd	%xmm9, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm4, %xmm9
	vpaddd	16*58(%rax), %xmm8, %xmm6
	vpaddd	16*58(%rcx), %xmm6, %xmm6
	vpandn	%xmm0, %xmm9, %xmm1
	vpand	%xmm9, %xmm10, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vprotd	$26, %xmm9, %xmm1
	vprotd	$21, %xmm9, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm9, %xmm8
	vpxor	%xmm2, %xmm8, %xmm8
	vpaddd	%xmm8, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm5, %xmm8
	vpaddd	16*59(%rax), %xmm0, %xmm6
	vpaddd	16*59(%rcx), %xmm6, %xmm6
	vpandn	%xmm10, %xmm8, %xmm1
	vpand	%xmm8, %xmm9, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vprotd	$26, %xmm8, %xmm1
	vprotd	$21, %xmm8, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm8, %xmm0
	vpxor	%xmm2, %xmm0, %xmm0
	vpaddd	%xmm0, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm7, %xmm0
	vpaddd	16*60(%rax), %xmm10, %xmm6
	vpaddd	16*60(%rcx), %xmm6, %xmm6
	vpandn	%xmm9, %xmm0, %xmm1
	vpand	%xmm0, %xmm8, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpaddd	%xmm1, %xmm6, %xmm6
	vprotd	$26, %xmm0, %xmm1
	vprotd	$21, %xmm0, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vprotd	$7, %xmm0, %xmm10
	vpxor	%xmm2, %xmm10, %xmm10
	vpaddd	%xmm10, %xmm6, %xmm6
	vpaddd	%xmm6, %xmm3, %xmm10
	
	paddd	sha256_4h+112(%rip), %xmm10
	movdqa	%xmm10, 112(%rdi)
	
	addq	$1032, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	movdqa	0(%rsp), %xmm6
	movdqa	16(%rsp), %xmm7
	movdqa	32(%rsp), %xmm8
	movdqa	48(%rsp), %xmm9
	movdqa	64(%rsp), %xmm10
	addq	$80, %rsp
	popq	%rdi
#endif
	ret
	
#endif /* USE_XOP */


	.text
	.p2align 6
	.globl sha256_use_4way
	.globl _sha256_use_4way
sha256_use_4way:
_sha256_use_4way:
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	
	/* Check for VIA PadLock Hash Engine */
	movl	$0xc0000000, %eax
	cpuid
	cmpl	$0xc0000001, %eax
	jb	sha256_use_4way_no_phe
	movl	$0xc0000001, %eax
	cpuid
	andl	$0x00000c00, %edx
	cmpl	$0x00000c00, %edx
	jne	sha256_use_4way_no_phe
	leaq	sha256_transform_phe(%rip), %rdx
	movq	%rdx, sha256_transform_addr(%rip)
	xorl	%eax, %eax
	jmp	sha256_use_4way_exit
sha256_use_4way_no_phe:
#if defined(USE_AVX)
	/* Check for AVX and OSXSAVE support */
	movl	$1, %eax
	cpuid
	andl	$0x18000000, %ecx
	cmpl	$0x18000000, %ecx
	jne sha256_use_4way_base
	/* Check for XMM and YMM state support */
	xorl	%ecx, %ecx
	xgetbv
	andl	$0x00000006, %eax
	cmpl	$0x00000006, %eax
	jne sha256_use_4way_base
#if defined(USE_XOP)
	/* Check for XOP support */
	movl	$0x80000001, %eax
	cpuid
	andl	$0x00000800, %ecx
	jz sha256_use_4way_avx
	
sha256_use_4way_xop:
	leaq	sha256d_ms_4way_xop(%rip), %rcx
	leaq	sha256_transform_4way_core_xop(%rip), %rdx
	jmp sha256_use_4way_done
#endif /* USE_XOP */
	
sha256_use_4way_avx:
	leaq	sha256d_ms_4way_avx(%rip), %rcx
	leaq	sha256_transform_4way_core_avx(%rip), %rdx
	jmp sha256_use_4way_done
#endif /* USE_AVX */
	
sha256_use_4way_base:
	leaq	sha256d_ms_4way_sse2(%rip), %rcx
	leaq	sha256_transform_4way_core_sse2(%rip), %rdx
	
sha256_use_4way_done:
	movq	%rcx, sha256d_ms_4way_addr(%rip)
	movq	%rdx, sha256_transform_4way_core_addr(%rip)
	movl	$1, %eax
sha256_use_4way_exit:
	popq	%rdx
	popq	%rcx
	popq	%rbx
	ret


#if defined(USE_AVX2)

	.text
	.p2align 6
	.globl sha256d_ms_8way
	.globl _sha256d_ms_8way
sha256d_ms_8way:
_sha256d_ms_8way:
sha256d_ms_8way_avx2:
#if defined(_WIN64) || defined(__CYGWIN__)
	pushq	%rdi
	subq	$80, %rsp
	vmovdqa	%xmm6, 0(%rsp)
	vmovdqa	%xmm7, 16(%rsp)
	vmovdqa	%xmm8, 32(%rsp)
	vmovdqa	%xmm9, 48(%rsp)
	vmovdqa	%xmm10, 64(%rsp)
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
	movq	%r9, %rcx
#endif
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$64*32, %rsp
	andq	$-128, %rsp
	
	leaq	16*32(%rsi), %rax
	
sha256d_ms_8way_avx2_extend_loop1:
	vmovdqa	3*32(%rsi), %ymm0
	vmovdqa	2*32(%rax), %ymm3
	vmovdqa	3*32(%rax), %ymm7
	vmovdqa	%ymm3, 2*32(%rsp)
	vmovdqa	%ymm7, 3*32(%rsp)
	vpaddd	%ymm0, %ymm7, %ymm7
	vpslld	$14, %ymm0, %ymm2
	vpsrld	$3, %ymm0, %ymm0
	vpsrld	$4, %ymm0, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrld	$11, %ymm1, %ymm1
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, 2*32(%rax)
	vmovdqa	%ymm7, 3*32(%rax)
	
	vmovdqa	4*32(%rax), %ymm0
	vmovdqa	%ymm0, 4*32(%rsp)
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, 4*32(%rax)
	vmovdqa	%ymm7, 5*32(%rax)
	
	vmovdqa	6*32(%rax), %ymm0
	vmovdqa	7*32(%rax), %ymm4
	vmovdqa	%ymm0, 6*32(%rsp)
	vmovdqa	%ymm4, 7*32(%rsp)
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 6*32(%rax)
	vmovdqa	%ymm7, 7*32(%rax)
	
	vmovdqa	8*32(%rax), %ymm0
	vmovdqa	2*32(%rax), %ymm4
	vmovdqa	%ymm0, 8*32(%rsp)
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 8*32(%rax)
	vmovdqa	%ymm7, 9*32(%rax)
	
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	3*32(%rax), %ymm3, %ymm3
	vpaddd	4*32(%rax), %ymm7, %ymm7
	vmovdqa	%ymm3, 10*32(%rax)
	vmovdqa	%ymm7, 11*32(%rax)
	
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	5*32(%rax), %ymm3, %ymm3
	vpaddd	6*32(%rax), %ymm7, %ymm7
	vmovdqa	%ymm3, 12*32(%rax)
	vmovdqa	%ymm7, 13*32(%rax)
	
	vmovdqa	14*32(%rax), %ymm0
	vmovdqa	15*32(%rax), %ymm4
	vmovdqa	%ymm0, 14*32(%rsp)
	vmovdqa	%ymm4, 15*32(%rsp)
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpaddd	7*32(%rax), %ymm0, %ymm0
	vpaddd	8*32(%rax), %ymm4, %ymm4
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 14*32(%rax)
	vmovdqa	%ymm7, 15*32(%rax)
	
sha256d_ms_8way_avx2_extend_loop2:
	vmovdqa	(16-15)*32(%rax), %ymm0
	vmovdqa	(16-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(16-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(16-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(16-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 16*32(%rax)
	vmovdqa	%ymm7, (16+1)*32(%rax)
	vmovdqa	(18-15)*32(%rax), %ymm0
	vmovdqa	(18-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(18-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(18-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(18-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 18*32(%rax)
	vmovdqa	%ymm7, (18+1)*32(%rax)
	vmovdqa	(20-15)*32(%rax), %ymm0
	vmovdqa	(20-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(20-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(20-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(20-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 20*32(%rax)
	vmovdqa	%ymm7, (20+1)*32(%rax)
	vmovdqa	(22-15)*32(%rax), %ymm0
	vmovdqa	(22-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(22-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(22-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(22-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 22*32(%rax)
	vmovdqa	%ymm7, (22+1)*32(%rax)
	vmovdqa	(24-15)*32(%rax), %ymm0
	vmovdqa	(24-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(24-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(24-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(24-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 24*32(%rax)
	vmovdqa	%ymm7, (24+1)*32(%rax)
	vmovdqa	(26-15)*32(%rax), %ymm0
	vmovdqa	(26-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(26-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(26-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(26-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 26*32(%rax)
	vmovdqa	%ymm7, (26+1)*32(%rax)
	vmovdqa	(28-15)*32(%rax), %ymm0
	vmovdqa	(28-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(28-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(28-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(28-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 28*32(%rax)
	vmovdqa	%ymm7, (28+1)*32(%rax)
	vmovdqa	(30-15)*32(%rax), %ymm0
	vmovdqa	(30-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(30-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(30-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(30-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 30*32(%rax)
	vmovdqa	%ymm7, (30+1)*32(%rax)
	vmovdqa	(32-15)*32(%rax), %ymm0
	vmovdqa	(32-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(32-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(32-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(32-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 32*32(%rax)
	vmovdqa	%ymm7, (32+1)*32(%rax)
	vmovdqa	(34-15)*32(%rax), %ymm0
	vmovdqa	(34-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(34-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(34-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(34-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 34*32(%rax)
	vmovdqa	%ymm7, (34+1)*32(%rax)
	vmovdqa	(36-15)*32(%rax), %ymm0
	vmovdqa	(36-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(36-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(36-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(36-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 36*32(%rax)
	vmovdqa	%ymm7, (36+1)*32(%rax)
	vmovdqa	(38-15)*32(%rax), %ymm0
	vmovdqa	(38-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(38-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(38-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(38-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 38*32(%rax)
	vmovdqa	%ymm7, (38+1)*32(%rax)
	vmovdqa	(40-15)*32(%rax), %ymm0
	vmovdqa	(40-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(40-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(40-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(40-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 40*32(%rax)
	vmovdqa	%ymm7, (40+1)*32(%rax)
	vmovdqa	(42-15)*32(%rax), %ymm0
	vmovdqa	(42-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(42-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(42-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(42-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 42*32(%rax)
	vmovdqa	%ymm7, (42+1)*32(%rax)
	jz sha256d_ms_8way_avx2_extend_coda2
	vmovdqa	(44-15)*32(%rax), %ymm0
	vmovdqa	(44-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(44-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(44-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(44-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 44*32(%rax)
	vmovdqa	%ymm7, (44+1)*32(%rax)
	vmovdqa	(46-15)*32(%rax), %ymm0
	vmovdqa	(46-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(46-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(46-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(46-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 46*32(%rax)
	vmovdqa	%ymm7, (46+1)*32(%rax)
	
	vmovdqa	0(%rcx), %ymm7
	vmovdqa	32(%rcx), %ymm8
	vmovdqa	64(%rcx), %ymm9
	vmovdqa	96(%rcx), %ymm10
	vmovdqa	128(%rcx), %ymm0
	vmovdqa	160(%rcx), %ymm5
	vmovdqa	192(%rcx), %ymm4
	vmovdqa	224(%rcx), %ymm3
	
	movq	%rsi, %rax
	leaq	sha256_8k(%rip), %rcx
	jmp sha256d_ms_8way_avx2_main_loop1
	
sha256d_ms_8way_avx2_main_loop2:
	vpaddd	32*(0)(%rax), %ymm10, %ymm6
	vpaddd	32*(0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(1)(%rax), %ymm9, %ymm6
	vpaddd	32*(1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(2)(%rax), %ymm8, %ymm6
	vpaddd	32*(2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
sha256d_ms_8way_avx2_main_loop1:
	vpaddd	32*(3)(%rax), %ymm0, %ymm6
	vpaddd	32*(3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(4+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(4+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(4+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(4+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(4+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(4+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(4+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(4+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(8+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(8+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(8+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(8+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(8+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(8+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(8+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(8+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(12+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(12+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(12+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(12+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(12+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(12+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(12+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(12+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(16+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(16+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(16+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(16+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(16+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(16+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(16+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(16+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(20+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(20+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(20+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(20+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(20+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(20+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(20+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(20+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(24+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(24+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(24+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(24+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(24+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(24+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(24+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(24+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(28+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(28+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(28+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(28+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(28+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(28+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(28+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(28+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(32+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(32+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(32+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(32+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(32+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(32+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(32+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(32+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(36+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(36+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(36+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(36+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(36+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(36+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(36+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(36+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(40+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(40+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(40+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(40+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(40+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(40+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(40+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(40+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(44+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(44+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(44+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(44+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(44+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(44+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(44+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(44+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(48+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(48+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(48+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(48+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(48+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(48+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(48+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(48+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(52+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(52+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(52+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(52+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(52+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(52+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(52+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(52+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(56)(%rax), %ymm10, %ymm6
	vpaddd	32*(56)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	jz sha256d_ms_8way_avx2_finish
	vpaddd	32*(57)(%rax), %ymm9, %ymm6
	vpaddd	32*(57)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(58)(%rax), %ymm8, %ymm6
	vpaddd	32*(58)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(59)(%rax), %ymm0, %ymm6
	vpaddd	32*(59)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	32*(60+0)(%rax), %ymm10, %ymm6
	vpaddd	32*(60+0)(%rcx), %ymm6, %ymm6

	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10

	vpand	%ymm5, %ymm4, %ymm2
	vpand	%ymm7, %ymm4, %ymm3
	vpand	%ymm7, %ymm5, %ymm1
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm7, %ymm2
	vpsrld	$2, %ymm7, %ymm3
	vpsrld	$11, %ymm3, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm1, %ymm3, %ymm3
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm6, %ymm3, %ymm3
	vpaddd	32*(60+1)(%rax), %ymm9, %ymm6
	vpaddd	32*(60+1)(%rcx), %ymm6, %ymm6

	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9

	vpand	%ymm7, %ymm5, %ymm2
	vpand	%ymm3, %ymm5, %ymm4
	vpand	%ymm3, %ymm7, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm3, %ymm2
	vpsrld	$2, %ymm3, %ymm4
	vpsrld	$11, %ymm4, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm4, %ymm4
	vpxor	%ymm1, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpaddd	32*(60+2)(%rax), %ymm8, %ymm6
	vpaddd	32*(60+2)(%rcx), %ymm6, %ymm6

	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8

	vpand	%ymm3, %ymm7, %ymm2
	vpand	%ymm4, %ymm7, %ymm5
	vpand	%ymm4, %ymm3, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm4, %ymm2
	vpsrld	$2, %ymm4, %ymm5
	vpsrld	$11, %ymm5, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm5, %ymm5
	vpxor	%ymm1, %ymm5, %ymm5
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm5
	vpaddd	%ymm6, %ymm5, %ymm5
	vpaddd	32*(60+3)(%rax), %ymm0, %ymm6
	vpaddd	32*(60+3)(%rcx), %ymm6, %ymm6

	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0

	vpand	%ymm4, %ymm3, %ymm2
	vpand	%ymm5, %ymm3, %ymm7
	vpand	%ymm5, %ymm4, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6

	vpslld	$10, %ymm5, %ymm2
	vpsrld	$2, %ymm5, %ymm7
	vpsrld	$11, %ymm7, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$9, %ymm2, %ymm2
	vpsrld	$9, %ymm1, %ymm1
	vpxor	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm2, %ymm7, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	
	vmovdqa	2*32(%rsp), %ymm1
	vmovdqa	3*32(%rsp), %ymm2
	vmovdqa	4*32(%rsp), %ymm6
	vmovdqa	%ymm1, 18*32(%rsi)
	vmovdqa	%ymm2, 19*32(%rsi)
	vmovdqa	%ymm6, 20*32(%rsi)
	vmovdqa	6*32(%rsp), %ymm1
	vmovdqa	7*32(%rsp), %ymm2
	vmovdqa	8*32(%rsp), %ymm6
	vmovdqa	%ymm1, 22*32(%rsi)
	vmovdqa	%ymm2, 23*32(%rsi)
	vmovdqa	%ymm6, 24*32(%rsi)
	vmovdqa	14*32(%rsp), %ymm1
	vmovdqa	15*32(%rsp), %ymm2
	vmovdqa	%ymm1, 30*32(%rsi)
	vmovdqa	%ymm2, 31*32(%rsi)
	
	vpaddd	0(%rdx), %ymm7, %ymm7
	vpaddd	32(%rdx), %ymm5, %ymm5
	vpaddd	64(%rdx), %ymm4, %ymm4
	vpaddd	96(%rdx), %ymm3, %ymm3
	vpaddd	128(%rdx), %ymm0, %ymm0
	vpaddd	160(%rdx), %ymm8, %ymm8
	vpaddd	192(%rdx), %ymm9, %ymm9
	vpaddd	224(%rdx), %ymm10, %ymm10
	
	vmovdqa	%ymm7, 0(%rsp)
	vmovdqa	%ymm5, 32(%rsp)
	vmovdqa	%ymm4, 64(%rsp)
	vmovdqa	%ymm3, 96(%rsp)
	vmovdqa	%ymm0, 128(%rsp)
	vmovdqa	%ymm8, 160(%rsp)
	vmovdqa	%ymm9, 192(%rsp)
	vmovdqa	%ymm10, 224(%rsp)
	
	vpxor	%ymm0, %ymm0, %ymm0
	movq	$0x8000000000000100, %rax
	vmovd	%rax, %xmm1
	vinserti128	$1, %xmm1, %ymm1, %ymm1
	vpshufd	$0x55, %ymm1, %ymm2
	vpshufd	$0x00, %ymm1, %ymm1
	vmovdqa	%ymm2, 8*32(%rsp)
	vmovdqa	%ymm0, 9*32(%rsp)
	vmovdqa	%ymm0, 10*32(%rsp)
	vmovdqa	%ymm0, 11*32(%rsp)
	vmovdqa	%ymm0, 12*32(%rsp)
	vmovdqa	%ymm0, 13*32(%rsp)
	vmovdqa	%ymm0, 14*32(%rsp)
	vmovdqa	%ymm1, 15*32(%rsp)
	
	leaq	16*32(%rsp), %rax
	cmpq	%rax, %rax
	
	vmovdqa	-15*32(%rax), %ymm0
	vmovdqa	-14*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	-16*32(%rax), %ymm8, %ymm3
	vpaddd	sha256d_8preext2_17(%rip), %ymm4, %ymm7
	vmovdqa	%ymm3, 0*32(%rax)
	vmovdqa	%ymm7, 1*32(%rax)
	
	vmovdqa	(2-15)*32(%rax), %ymm0
	vmovdqa	(2-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(2-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(2-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(2-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 2*32(%rax)
	vmovdqa	%ymm7, (2+1)*32(%rax)
	vmovdqa	(4-15)*32(%rax), %ymm0
	vmovdqa	(4-14)*32(%rax), %ymm4
	vpslld	$14, %ymm0, %ymm2
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$7, %ymm0, %ymm1
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrld	$11, %ymm1, %ymm1
	vpsrld	$11, %ymm5, %ymm5
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4
	vpslld	$11, %ymm2, %ymm2
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm4, %ymm4

	vpaddd	%ymm0, %ymm4, %ymm4
	vpaddd	(4-16)*32(%rax), %ymm8, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7

	vpaddd	(4-7)*32(%rax), %ymm0, %ymm0
	vpaddd	(4-6)*32(%rax), %ymm4, %ymm4

	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7

	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 4*32(%rax)
	vmovdqa	%ymm7, (4+1)*32(%rax)
	
	vmovdqa	-9*32(%rax), %ymm0
	vpslld	$14, %ymm0, %ymm2
	vpsrld	$3, %ymm0, %ymm8
	vpsrld	$7, %ymm0, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpsrld	$11, %ymm1, %ymm1
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpaddd	sha256d_8preext2_23(%rip), %ymm0, %ymm4
	vpaddd	-10*32(%rax), %ymm8, %ymm0
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpaddd	-1*32(%rax), %ymm0, %ymm0
	vpaddd	0*32(%rax), %ymm4, %ymm4
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 6*32(%rax)
	vmovdqa	%ymm7, 7*32(%rax)
	
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	sha256d_8preext2_24(%rip), %ymm3, %ymm3
	vpaddd	1*32(%rax), %ymm3, %ymm3
	vpaddd	2*32(%rax), %ymm7, %ymm7
	vmovdqa	%ymm3, 8*32(%rax)
	vmovdqa	%ymm7, 9*32(%rax)
	
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	3*32(%rax), %ymm3, %ymm3
	vpaddd	4*32(%rax), %ymm7, %ymm7
	vmovdqa	%ymm3, 10*32(%rax)
	vmovdqa	%ymm7, 11*32(%rax)
	
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	5*32(%rax), %ymm3, %ymm3
	vpaddd	6*32(%rax), %ymm7, %ymm7
	vmovdqa	%ymm3, 12*32(%rax)
	vmovdqa	%ymm7, 13*32(%rax)
	
	vmovdqa	sha256d_8preext2_30(%rip), %ymm0
	vmovdqa	0*32(%rax), %ymm4
	vpslld	$14, %ymm4, %ymm6
	vpsrld	$3, %ymm4, %ymm4
	vpsrld	$4, %ymm4, %ymm5
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm6, %ymm4, %ymm4
	vpsrld	$11, %ymm5, %ymm5
	vpslld	$11, %ymm6, %ymm6
	vpxor	%ymm5, %ymm4, %ymm4
	vpxor	%ymm6, %ymm4, %ymm4
	vpaddd	-1*32(%rax), %ymm4, %ymm4
	vpslld	$13, %ymm3, %ymm2
	vpslld	$13, %ymm7, %ymm6
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$10, %ymm7, %ymm7
	vpaddd	7*32(%rax), %ymm0, %ymm0
	vpaddd	8*32(%rax), %ymm4, %ymm4
	vpsrld	$7, %ymm3, %ymm1
	vpsrld	$7, %ymm7, %ymm5
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrld	$2, %ymm1, %ymm1
	vpsrld	$2, %ymm5, %ymm5
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpslld	$2, %ymm2, %ymm2
	vpslld	$2, %ymm6, %ymm6
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm5, %ymm7, %ymm7
	vpxor	%ymm2, %ymm3, %ymm3
	vpxor	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm0, %ymm3, %ymm3
	vpaddd	%ymm4, %ymm7, %ymm7
	vmovdqa	%ymm3, 14*32(%rax)
	vmovdqa	%ymm7, 15*32(%rax)
	
	jmp sha256d_ms_8way_avx2_extend_loop2
	
sha256d_ms_8way_avx2_extend_coda2:
	vmovdqa	(44-15)*32(%rax), %ymm0
	vpslld	$14, %ymm0, %ymm2
	vpsrld	$3, %ymm0, %ymm0
	vpsrld	$4, %ymm0, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrld	$11, %ymm1, %ymm1
	vpslld	$11, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpaddd	(44-16)*32(%rax), %ymm0, %ymm0
	vpaddd	(44-7)*32(%rax), %ymm0, %ymm0

	vpslld	$13, %ymm3, %ymm2
	vpsrld	$10, %ymm3, %ymm3
	vpsrld	$7, %ymm3, %ymm1
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm2, %ymm3, %ymm3
	vpsrld	$2, %ymm1, %ymm1
	vpslld	$2, %ymm2, %ymm2
	vpxor	%ymm1, %ymm3, %ymm3
	vpxor	%ymm2, %ymm3, %ymm3
	vpaddd	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, 44*32(%rax)
	
	vmovdqa	sha256_8h+0(%rip), %ymm7
	vmovdqa	sha256_8h+32(%rip), %ymm5
	vmovdqa	sha256_8h+64(%rip), %ymm4
	vmovdqa	sha256_8h+96(%rip), %ymm3
	vmovdqa	sha256_8h+128(%rip), %ymm0
	vmovdqa	sha256_8h+160(%rip), %ymm8
	vmovdqa	sha256_8h+192(%rip), %ymm9
	vmovdqa	sha256_8h+224(%rip), %ymm10
	
	movq	%rsp, %rax
	leaq	sha256_8k(%rip), %rcx
	jmp sha256d_ms_8way_avx2_main_loop2


sha256d_ms_8way_avx2_finish:
	vpaddd	32*57(%rax), %ymm9, %ymm6
	vpaddd	32*57(%rcx), %ymm6, %ymm6
	vpandn	%ymm8, %ymm10, %ymm1
	vpand	%ymm10, %ymm0, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6
	vpslld	$7, %ymm10, %ymm1
	vpsrld	$6, %ymm10, %ymm9
	vpsrld	$5, %ymm9, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm9
	vpaddd	%ymm9, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm4, %ymm9
	vpaddd	32*58(%rax), %ymm8, %ymm6
	vpaddd	32*58(%rcx), %ymm6, %ymm6
	vpandn	%ymm0, %ymm9, %ymm1
	vpand	%ymm9, %ymm10, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6
	vpslld	$7, %ymm9, %ymm1
	vpsrld	$6, %ymm9, %ymm8
	vpsrld	$5, %ymm8, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm8
	vpxor	%ymm2, %ymm8, %ymm8
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm8, %ymm8
	vpaddd	%ymm8, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm5, %ymm8
	vpaddd	32*59(%rax), %ymm0, %ymm6
	vpaddd	32*59(%rcx), %ymm6, %ymm6
	vpandn	%ymm10, %ymm8, %ymm1
	vpand	%ymm8, %ymm9, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6
	vpslld	$7, %ymm8, %ymm1
	vpsrld	$6, %ymm8, %ymm0
	vpsrld	$5, %ymm0, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpaddd	%ymm0, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm7, %ymm0
	vpaddd	32*60(%rax), %ymm10, %ymm6
	vpaddd	32*60(%rcx), %ymm6, %ymm6
	vpandn	%ymm9, %ymm0, %ymm1
	vpand	%ymm0, %ymm8, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpaddd	%ymm1, %ymm6, %ymm6
	vpslld	$7, %ymm0, %ymm1
	vpsrld	$6, %ymm0, %ymm10
	vpsrld	$5, %ymm10, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$14, %ymm1, %ymm1
	vpsrld	$14, %ymm2, %ymm2
	vpxor	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm10
	vpslld	$5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm10, %ymm10
	vpaddd	%ymm10, %ymm6, %ymm6
	vpaddd	%ymm6, %ymm3, %ymm10
	
	vpaddd	sha256_8h+224(%rip), %ymm10, %ymm10
	vmovdqa	%ymm10, 224(%rdi)
	
	movq	%rbp, %rsp
	popq	%rbp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	vmovdqa	0(%rsp), %xmm6
	vmovdqa	16(%rsp), %xmm7
	vmovdqa	32(%rsp), %xmm8
	vmovdqa	48(%rsp), %xmm9
	vmovdqa	64(%rsp), %xmm10
	addq	$80, %rsp
	popq	%rdi
#endif
	ret


	.text
	.p2align 6
	.globl sha256_use_8way
	.globl _sha256_use_8way
sha256_use_8way:
_sha256_use_8way:
	pushq	%rbx
	
	/* Check for AVX and OSXSAVE support */
	movl	$1, %eax
	cpuid
	andl	$0x18000000, %ecx
	cmpl	$0x18000000, %ecx
	jne sha256_use_8way_no
	/* Check for AVX2 support */
	movl	$7, %eax
	xorl	%ecx, %ecx
	cpuid
	andl	$0x00000020, %ebx
	cmpl	$0x00000020, %ebx
	jne sha256_use_8way_no
	/* Check for XMM and YMM state support */
	xorl	%ecx, %ecx
	xgetbv
	andl	$0x00000006, %eax
	cmpl	$0x00000006, %eax
	jne sha256_use_8way_no
	
sha256_use_8way_yes:
	movl	$1, %eax
	jmp sha256_use_8way_done
	
sha256_use_8way_no:
	xorl	%eax, %eax
	
sha256_use_8way_done:
	popq	%rbx
	ret

#endif /* USE_AVX2 */

#endif
