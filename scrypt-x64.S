/*
 * Copyright 2011-2014 pooler@litecoinpool.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include "cpuminer-config.h"

#if defined(__linux__) && defined(__ELF__)
	.section .note.GNU-stack,"",%progbits
#endif

#if defined(USE_ASM) && defined(__x86_64__)

	.text
	.p2align 6
	.globl scrypt_best_throughput
	.globl _scrypt_best_throughput
scrypt_best_throughput:
_scrypt_best_throughput:
	pushq	%rbx
#if defined(USE_AVX2)
	/* Check for AVX and OSXSAVE support */
	movl	$1, %eax
	cpuid
	andl	$0x18000000, %ecx
	cmpl	$0x18000000, %ecx
	jne scrypt_best_throughput_no_avx2
	/* Check for AVX2 support */
	movl	$7, %eax
	xorl	%ecx, %ecx
	cpuid
	andl	$0x00000020, %ebx
	cmpl	$0x00000020, %ebx
	jne scrypt_best_throughput_no_avx2
	/* Check for XMM and YMM state support */
	xorl	%ecx, %ecx
	xgetbv
	andl	$0x00000006, %eax
	cmpl	$0x00000006, %eax
	jne scrypt_best_throughput_no_avx2
	movl	$6, %eax
	jmp scrypt_best_throughput_exit
scrypt_best_throughput_no_avx2:
#endif
	/* Check for AuthenticAMD */
	xorq	%rax, %rax
	cpuid
	movl	$3, %eax
	cmpl	$0x444d4163, %ecx
	jne scrypt_best_throughput_not_amd
	cmpl	$0x69746e65, %edx
	jne scrypt_best_throughput_not_amd
	cmpl	$0x68747541, %ebx
	jne scrypt_best_throughput_not_amd
	/* Check for AMD K8 or Bobcat */
	movl	$1, %eax
	cpuid
	andl	$0x0ff00000, %eax
	jz scrypt_best_throughput_one
	cmpl	$0x00500000, %eax
	je scrypt_best_throughput_one
	movl	$3, %eax
	jmp scrypt_best_throughput_exit
scrypt_best_throughput_not_amd:
	/* Check for GenuineIntel */
	cmpl	$0x6c65746e, %ecx
	jne scrypt_best_throughput_exit
	cmpl	$0x49656e69, %edx
	jne scrypt_best_throughput_exit
	cmpl	$0x756e6547, %ebx
	jne scrypt_best_throughput_exit
	/* Check for Intel Atom */
	movl	$1, %eax
	cpuid
	movl	%eax, %edx
	andl	$0x0ff00f00, %eax
	cmpl	$0x00000600, %eax
	movl	$3, %eax
	jnz scrypt_best_throughput_exit
	andl	$0x000f00f0, %edx
	cmpl	$0x000100c0, %edx
	je scrypt_best_throughput_one
	cmpl	$0x00020060, %edx
	je scrypt_best_throughput_one
	cmpl	$0x00030060, %edx
	jne scrypt_best_throughput_exit
scrypt_best_throughput_one:
	movl	$1, %eax
scrypt_best_throughput_exit:
	popq	%rbx
	ret
	
	



	.text
	.p2align 6
salsa8_core_gen:
	/* 0: %rdx, %rdi, %rcx, %rsi */
	movq	8(%rsp), %rdi
	movq	%rdi, %rdx
	shrq	$32, %rdi
	movq	16(%rsp), %rsi
	movq	%rsi, %rcx
	shrq	$32, %rsi
	/* 1: %r9, 72(%rsp), %rax, %r8 */
	movq	24(%rsp), %r8
	movq	%r8, %r9
	shrq	$32, %r8
	movq	%r8, 72(%rsp)
	movq	32(%rsp), %r8
	movq	%r8, %rax
	shrq	$32, %r8
	/* 2: %r11, %r10, 48(%rsp), %r12 */
	movq	40(%rsp), %r10
	movq	%r10, %r11
	shrq	$32, %r10
	movq	48(%rsp), %r12
	/* movq	%r12, %r13 */
	/* movq	%r13, 48(%rsp) */
	shrq	$32, %r12
	/* 3: %r14, %r13, %rbx, 88(%rsp) */
	movq	56(%rsp), %r13
	movq	%r13, %r14
	shrq	$32, %r13
	movq	64(%rsp), %r15
	movq	%r15, %rbx
	shrq	$32, %r15
	movq	%r15, 88(%rsp)
	
	movq	72(%rsp), %r15
	
	leaq	(%r14, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r9d
	leaq	(%rdi, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r10d
	leaq	(%rdx, %r9), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r11d
	leaq	(%r15, %r10), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	
	leaq	(%r9, %r11), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r14d
	leaq	(%r10, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %edi
	leaq	(%r11, %r14), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r13, %rdi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%rax, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %ebx
	leaq	(%rbp, %rbx), %r15
	roll	$9, %r15d
	xorl	%r15d, %ecx
	leaq	(%rbx, %rcx), %r15
	roll	$13, %r15d
	xorl	%r15d, %eax
	leaq	(%rcx, %rax), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%r12, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %esi
	leaq	(%r15, %rsi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	leaq	(%rsi, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r12d
	leaq	(%r8, %r12), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%rsi, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %edi
	leaq	(%r9, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %eax
	leaq	(%rdx, %rdi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %ecx
	leaq	(%r15, %rax), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	
	leaq	(%rdi, %rcx), %rbp
	roll	$13, %ebp
	xorl	%ebp, %esi
	leaq	(%rax, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r9d
	leaq	(%rcx, %rsi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r8, %r9), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%r10, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %r12d
	leaq	(%rbp, %r12), %r15
	roll	$9, %r15d
	xorl	%r15d, %r11d
	leaq	(%r12, %r11), %r15
	roll	$13, %r15d
	xorl	%r15d, %r10d
	leaq	(%r11, %r10), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%rbx, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r14d
	leaq	(%r15, %r14), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	leaq	(%r14, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %ebx
	leaq	(%r13, %rbx), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%r14, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r9d
	leaq	(%rdi, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r10d
	leaq	(%rdx, %r9), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r11d
	leaq	(%r15, %r10), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	
	leaq	(%r9, %r11), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r14d
	leaq	(%r10, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %edi
	leaq	(%r11, %r14), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r13, %rdi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%rax, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %ebx
	leaq	(%rbp, %rbx), %r15
	roll	$9, %r15d
	xorl	%r15d, %ecx
	leaq	(%rbx, %rcx), %r15
	roll	$13, %r15d
	xorl	%r15d, %eax
	leaq	(%rcx, %rax), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%r12, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %esi
	leaq	(%r15, %rsi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	leaq	(%rsi, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r12d
	leaq	(%r8, %r12), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%rsi, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %edi
	leaq	(%r9, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %eax
	leaq	(%rdx, %rdi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %ecx
	leaq	(%r15, %rax), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	
	leaq	(%rdi, %rcx), %rbp
	roll	$13, %ebp
	xorl	%ebp, %esi
	leaq	(%rax, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r9d
	leaq	(%rcx, %rsi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r8, %r9), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%r10, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %r12d
	leaq	(%rbp, %r12), %r15
	roll	$9, %r15d
	xorl	%r15d, %r11d
	leaq	(%r12, %r11), %r15
	roll	$13, %r15d
	xorl	%r15d, %r10d
	leaq	(%r11, %r10), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%rbx, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r14d
	leaq	(%r15, %r14), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	leaq	(%r14, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %ebx
	leaq	(%r13, %rbx), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%r14, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r9d
	leaq	(%rdi, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r10d
	leaq	(%rdx, %r9), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r11d
	leaq	(%r15, %r10), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	
	leaq	(%r9, %r11), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r14d
	leaq	(%r10, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %edi
	leaq	(%r11, %r14), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r13, %rdi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%rax, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %ebx
	leaq	(%rbp, %rbx), %r15
	roll	$9, %r15d
	xorl	%r15d, %ecx
	leaq	(%rbx, %rcx), %r15
	roll	$13, %r15d
	xorl	%r15d, %eax
	leaq	(%rcx, %rax), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%r12, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %esi
	leaq	(%r15, %rsi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	leaq	(%rsi, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r12d
	leaq	(%r8, %r12), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%rsi, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %edi
	leaq	(%r9, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %eax
	leaq	(%rdx, %rdi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %ecx
	leaq	(%r15, %rax), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	
	leaq	(%rdi, %rcx), %rbp
	roll	$13, %ebp
	xorl	%ebp, %esi
	leaq	(%rax, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r9d
	leaq	(%rcx, %rsi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r8, %r9), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%r10, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %r12d
	leaq	(%rbp, %r12), %r15
	roll	$9, %r15d
	xorl	%r15d, %r11d
	leaq	(%r12, %r11), %r15
	roll	$13, %r15d
	xorl	%r15d, %r10d
	leaq	(%r11, %r10), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%rbx, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r14d
	leaq	(%r15, %r14), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	leaq	(%r14, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %ebx
	leaq	(%r13, %rbx), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%r14, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r9d
	leaq	(%rdi, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r10d
	leaq	(%rdx, %r9), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r11d
	leaq	(%r15, %r10), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	
	leaq	(%r9, %r11), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r14d
	leaq	(%r10, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %edi
	leaq	(%r11, %r14), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r13, %rdi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%rax, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %ebx
	leaq	(%rbp, %rbx), %r15
	roll	$9, %r15d
	xorl	%r15d, %ecx
	leaq	(%rbx, %rcx), %r15
	roll	$13, %r15d
	xorl	%r15d, %eax
	leaq	(%rcx, %rax), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%r12, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %esi
	leaq	(%r15, %rsi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	leaq	(%rsi, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r12d
	leaq	(%r8, %r12), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	movq	72(%rsp), %r15
	
	leaq	(%rsi, %rdx), %rbp
	roll	$7, %ebp
	xorl	%ebp, %edi
	leaq	(%r9, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %eax
	leaq	(%rdx, %rdi), %rbp
	roll	$9, %ebp
	xorl	%ebp, %ecx
	leaq	(%r15, %rax), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r8d
	
	leaq	(%rdi, %rcx), %rbp
	roll	$13, %ebp
	xorl	%ebp, %esi
	leaq	(%rax, %r8), %rbp
	roll	$13, %ebp
	xorl	%ebp, %r9d
	leaq	(%rcx, %rsi), %rbp
	roll	$18, %ebp
	xorl	%ebp, %edx
	leaq	(%r8, %r9), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	48(%rsp), %rbp
	movq	%r15, 72(%rsp)
	
	leaq	(%r10, %rbp), %r15
	roll	$7, %r15d
	xorl	%r15d, %r12d
	leaq	(%rbp, %r12), %r15
	roll	$9, %r15d
	xorl	%r15d, %r11d
	leaq	(%r12, %r11), %r15
	roll	$13, %r15d
	xorl	%r15d, %r10d
	leaq	(%r11, %r10), %r15
	roll	$18, %r15d
	xorl	%r15d, %ebp
	
	movq	88(%rsp), %r15
	movq	%rbp, 48(%rsp)
	
	leaq	(%rbx, %r15), %rbp
	roll	$7, %ebp
	xorl	%ebp, %r14d
	leaq	(%r15, %r14), %rbp
	roll	$9, %ebp
	xorl	%ebp, %r13d
	leaq	(%r14, %r13), %rbp
	roll	$13, %ebp
	xorl	%ebp, %ebx
	leaq	(%r13, %rbx), %rbp
	roll	$18, %ebp
	xorl	%ebp, %r15d
	
	movq	%r15, 88(%rsp)
	
	shlq	$32, %rdi
	xorq	%rdi, %rdx
	movq	%rdx, 24(%rsp)
	
	shlq	$32, %rsi
	xorq	%rsi, %rcx
	movq	%rcx, 32(%rsp)
	
	movl	72(%rsp), %edi
	shlq	$32, %rdi
	xorq	%rdi, %r9
	movq	%r9, 40(%rsp)
	
	movl	48(%rsp), %ebp
	shlq	$32, %r8
	xorq	%r8, %rax
	movq	%rax, 48(%rsp)
	
	shlq	$32, %r10
	xorq	%r10, %r11
	movq	%r11, 56(%rsp)
	
	shlq	$32, %r12
	xorq	%r12, %rbp
	movq	%rbp, 64(%rsp)
	
	shlq	$32, %r13
	xorq	%r13, %r14
	movq	%r14, 72(%rsp)
	
	movdqa	24(%rsp), %xmm0
	
	shlq	$32, %r15
	xorq	%r15, %rbx
	movq	%rbx, 80(%rsp)
	
	movdqa	40(%rsp), %xmm1
	movdqa	56(%rsp), %xmm2
	movdqa	72(%rsp), %xmm3
	
	ret
	
	
	.text
	.p2align 6
	.globl scrypt_core
	.globl _scrypt_core
scrypt_core:
_scrypt_core:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
#if defined(_WIN64) || defined(__CYGWIN__)
	subq	$176, %rsp
	movdqa	%xmm6, 8(%rsp)
	movdqa	%xmm7, 24(%rsp)
	movdqa	%xmm8, 40(%rsp)
	movdqa	%xmm9, 56(%rsp)
	movdqa	%xmm10, 72(%rsp)
	movdqa	%xmm11, 88(%rsp)
	movdqa	%xmm12, 104(%rsp)
	movdqa	%xmm13, 120(%rsp)
	movdqa	%xmm14, 136(%rsp)
	movdqa	%xmm15, 152(%rsp)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
#else
	movq	%rdx, %r8
#endif

	
	/* GenuineIntel processors have fast SIMD */
	xorl	%eax, %eax
	cpuid
	cmpl	$0x6c65746e, %ecx
	jne scrypt_core_gen
	cmpl	$0x49656e69, %edx
	jne scrypt_core_gen
	cmpl	$0x756e6547, %ebx
	je scrypt_core_xmm
	
	.p2align 6
scrypt_core_gen:
	subq	$136, %rsp
	movdqa	0(%rdi), %xmm8
	movdqa	16(%rdi), %xmm9
	movdqa	32(%rdi), %xmm10
	movdqa	48(%rdi), %xmm11
	movdqa	64(%rdi), %xmm12
	movdqa	80(%rdi), %xmm13
	movdqa	96(%rdi), %xmm14
	movdqa	112(%rdi), %xmm15
	
	movq	%r8, %rcx
	shlq	$7, %rcx
	addq	%rsi, %rcx
	movq	%r8, 96(%rsp)
	movq	%rdi, 104(%rsp)
	movq	%rsi, 112(%rsp)
	movq	%rcx, 120(%rsp)
scrypt_core_gen_loop1:
	movdqa	%xmm8, 0(%rsi)
	movdqa	%xmm9, 16(%rsi)
	movdqa	%xmm10, 32(%rsi)
	movdqa	%xmm11, 48(%rsi)
	movdqa	%xmm12, 64(%rsi)
	movdqa	%xmm13, 80(%rsi)
	movdqa	%xmm14, 96(%rsi)
	movdqa	%xmm15, 112(%rsi)
	
	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, 0(%rsp)
	movdqa	%xmm9, 16(%rsp)
	movdqa	%xmm10, 32(%rsp)
	movdqa	%xmm11, 48(%rsp)
	movq	%rsi, 128(%rsp)
	call salsa8_core_gen
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11
	
	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, 0(%rsp)
	movdqa	%xmm13, 16(%rsp)
	movdqa	%xmm14, 32(%rsp)
	movdqa	%xmm15, 48(%rsp)
	call salsa8_core_gen
	movq	128(%rsp), %rsi
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15
	
	addq	$128, %rsi
	movq	120(%rsp), %rcx
	cmpq	%rcx, %rsi
	jne scrypt_core_gen_loop1
	
	movq	96(%rsp), %r8
	movq	%r8, %rcx
	subl	$1, %r8d
	movq	%r8, 96(%rsp)
	movd	%xmm12, %edx
scrypt_core_gen_loop2:
	movq	112(%rsp), %rsi
	andl	%r8d, %edx
	shll	$7, %edx
	addq	%rsi, %rdx
	movdqa	0(%rdx), %xmm0
	movdqa	16(%rdx), %xmm1
	movdqa	32(%rdx), %xmm2
	movdqa	48(%rdx), %xmm3
	movdqa	64(%rdx), %xmm4
	movdqa	80(%rdx), %xmm5
	movdqa	96(%rdx), %xmm6
	movdqa	112(%rdx), %xmm7
	pxor	%xmm0, %xmm8
	pxor	%xmm1, %xmm9
	pxor	%xmm2, %xmm10
	pxor	%xmm3, %xmm11
	pxor	%xmm4, %xmm12
	pxor	%xmm5, %xmm13
	pxor	%xmm6, %xmm14
	pxor	%xmm7, %xmm15
	
	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, 0(%rsp)
	movdqa	%xmm9, 16(%rsp)
	movdqa	%xmm10, 32(%rsp)
	movdqa	%xmm11, 48(%rsp)
	movq	%rcx, 128(%rsp)
	call salsa8_core_gen
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11
	
	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, 0(%rsp)
	movdqa	%xmm13, 16(%rsp)
	movdqa	%xmm14, 32(%rsp)
	movdqa	%xmm15, 48(%rsp)
	call salsa8_core_gen
	movq	96(%rsp), %r8
	movq	128(%rsp), %rcx
	addl	0(%rsp), %edx
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15
	
	subq	$1, %rcx
	ja scrypt_core_gen_loop2
	
	movq	104(%rsp), %rdi
	movdqa	%xmm8, 0(%rdi)
	movdqa	%xmm9, 16(%rdi)
	movdqa	%xmm10, 32(%rdi)
	movdqa	%xmm11, 48(%rdi)
	movdqa	%xmm12, 64(%rdi)
	movdqa	%xmm13, 80(%rdi)
	movdqa	%xmm14, 96(%rdi)
	movdqa	%xmm15, 112(%rdi)
	
	addq	$136, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret



	
	.p2align 6
scrypt_core_xmm:
	pcmpeqw	%xmm1, %xmm1
	psrlq	$32, %xmm1
	
	movdqa	0(%rdi), %xmm8
	movdqa	16(%rdi), %xmm11
	movdqa	32(%rdi), %xmm10
	movdqa	48(%rdi), %xmm9
	movdqa	%xmm8, %xmm0
	pxor	%xmm11, %xmm8
	pand	%xmm1, %xmm8
	pxor	%xmm11, %xmm8
	pxor	%xmm10, %xmm11
	pand	%xmm1, %xmm11
	pxor	%xmm10, %xmm11
	pxor	%xmm9, %xmm10
	pand	%xmm1, %xmm10
	pxor	%xmm9, %xmm10
	pxor	%xmm0, %xmm9
	pand	%xmm1, %xmm9
	pxor	%xmm0, %xmm9
	movdqa	%xmm8, %xmm0
	pshufd	$0x4e, %xmm10, %xmm10
	punpcklqdq	%xmm10, %xmm8
	punpckhqdq	%xmm0, %xmm10
	movdqa	%xmm11, %xmm0
	pshufd	$0x4e, %xmm9, %xmm9
	punpcklqdq	%xmm9, %xmm11
	punpckhqdq	%xmm0, %xmm9
	
	movdqa	64(%rdi), %xmm12
	movdqa	80(%rdi), %xmm15
	movdqa	96(%rdi), %xmm14
	movdqa	112(%rdi), %xmm13
	movdqa	%xmm12, %xmm0
	pxor	%xmm15, %xmm12
	pand	%xmm1, %xmm12
	pxor	%xmm15, %xmm12
	pxor	%xmm14, %xmm15
	pand	%xmm1, %xmm15
	pxor	%xmm14, %xmm15
	pxor	%xmm13, %xmm14
	pand	%xmm1, %xmm14
	pxor	%xmm13, %xmm14
	pxor	%xmm0, %xmm13
	pand	%xmm1, %xmm13
	pxor	%xmm0, %xmm13
	movdqa	%xmm12, %xmm0
	pshufd	$0x4e, %xmm14, %xmm14
	punpcklqdq	%xmm14, %xmm12
	punpckhqdq	%xmm0, %xmm14
	movdqa	%xmm15, %xmm0
	pshufd	$0x4e, %xmm13, %xmm13
	punpcklqdq	%xmm13, %xmm15
	punpckhqdq	%xmm0, %xmm13
	
	movq	%rsi, %rdx
	movq	%r8, %rcx
	shlq	$7, %rcx
	addq	%rsi, %rcx
scrypt_core_xmm_loop1:
	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, 0(%rdx)
	movdqa	%xmm9, 16(%rdx)
	movdqa	%xmm10, 32(%rdx)
	movdqa	%xmm11, 48(%rdx)
	movdqa	%xmm12, 64(%rdx)
	movdqa	%xmm13, 80(%rdx)
	movdqa	%xmm14, 96(%rdx)
	movdqa	%xmm15, 112(%rdx)
	
	movdqa	%xmm8, %xmm0
	movdqa	%xmm9, %xmm1
	movdqa	%xmm10, %xmm2
	movdqa	%xmm11, %xmm3
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11
	
	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, %xmm0
	movdqa	%xmm13, %xmm1
	movdqa	%xmm14, %xmm2
	movdqa	%xmm15, %xmm3
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15
	
	addq	$128, %rdx
	cmpq	%rcx, %rdx
	jne scrypt_core_xmm_loop1
	
	movq	%r8, %rcx
	subl	$1, %r8d
scrypt_core_xmm_loop2:
	movd	%xmm12, %edx
	andl	%r8d, %edx
	shll	$7, %edx
	pxor	0(%rsi, %rdx), %xmm8
	pxor	16(%rsi, %rdx), %xmm9
	pxor	32(%rsi, %rdx), %xmm10
	pxor	48(%rsi, %rdx), %xmm11
	
	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, %xmm0
	movdqa	%xmm9, %xmm1
	movdqa	%xmm10, %xmm2
	movdqa	%xmm11, %xmm3
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11
	
	pxor	64(%rsi, %rdx), %xmm12
	pxor	80(%rsi, %rdx), %xmm13
	pxor	96(%rsi, %rdx), %xmm14
	pxor	112(%rsi, %rdx), %xmm15
	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, %xmm0
	movdqa	%xmm13, %xmm1
	movdqa	%xmm14, %xmm2
	movdqa	%xmm15, %xmm3
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4e, %xmm2, %xmm2
	
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15
	
	subq	$1, %rcx
	ja scrypt_core_xmm_loop2
	
	pcmpeqw	%xmm1, %xmm1
	psrlq	$32, %xmm1
	
	movdqa	%xmm8, %xmm0
	pxor	%xmm9, %xmm8
	pand	%xmm1, %xmm8
	pxor	%xmm9, %xmm8
	pxor	%xmm10, %xmm9
	pand	%xmm1, %xmm9
	pxor	%xmm10, %xmm9
	pxor	%xmm11, %xmm10
	pand	%xmm1, %xmm10
	pxor	%xmm11, %xmm10
	pxor	%xmm0, %xmm11
	pand	%xmm1, %xmm11
	pxor	%xmm0, %xmm11
	movdqa	%xmm8, %xmm0
	pshufd	$0x4e, %xmm10, %xmm10
	punpcklqdq	%xmm10, %xmm8
	punpckhqdq	%xmm0, %xmm10
	movdqa	%xmm9, %xmm0
	pshufd	$0x4e, %xmm11, %xmm11
	punpcklqdq	%xmm11, %xmm9
	punpckhqdq	%xmm0, %xmm11
	movdqa	%xmm8, 0(%rdi)
	movdqa	%xmm11, 16(%rdi)
	movdqa	%xmm10, 32(%rdi)
	movdqa	%xmm9, 48(%rdi)
	
	movdqa	%xmm12, %xmm0
	pxor	%xmm13, %xmm12
	pand	%xmm1, %xmm12
	pxor	%xmm13, %xmm12
	pxor	%xmm14, %xmm13
	pand	%xmm1, %xmm13
	pxor	%xmm14, %xmm13
	pxor	%xmm15, %xmm14
	pand	%xmm1, %xmm14
	pxor	%xmm15, %xmm14
	pxor	%xmm0, %xmm15
	pand	%xmm1, %xmm15
	pxor	%xmm0, %xmm15
	movdqa	%xmm12, %xmm0
	pshufd	$0x4e, %xmm14, %xmm14
	punpcklqdq	%xmm14, %xmm12
	punpckhqdq	%xmm0, %xmm14
	movdqa	%xmm13, %xmm0
	pshufd	$0x4e, %xmm15, %xmm15
	punpcklqdq	%xmm15, %xmm13
	punpckhqdq	%xmm0, %xmm15
	movdqa	%xmm12, 64(%rdi)
	movdqa	%xmm15, 80(%rdi)
	movdqa	%xmm14, 96(%rdi)
	movdqa	%xmm13, 112(%rdi)
	
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
	
	
#if defined(USE_AVX)

#endif /* USE_AVX */
	
	.text
	.p2align 6
	.globl scrypt_core_3way
	.globl _scrypt_core_3way
scrypt_core_3way:
_scrypt_core_3way:
	pushq	%rbx
	pushq	%rbp
#if defined(_WIN64) || defined(__CYGWIN__)
	subq	$176, %rsp
	movdqa	%xmm6, 8(%rsp)
	movdqa	%xmm7, 24(%rsp)
	movdqa	%xmm8, 40(%rsp)
	movdqa	%xmm9, 56(%rsp)
	movdqa	%xmm10, 72(%rsp)
	movdqa	%xmm11, 88(%rsp)
	movdqa	%xmm12, 104(%rsp)
	movdqa	%xmm13, 120(%rsp)
	movdqa	%xmm14, 136(%rsp)
	movdqa	%xmm15, 152(%rsp)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
#else
	movq	%rdx, %r8
#endif
	subq	$392, %rsp
	
	
#if !defined(USE_AVX)
	jmp scrypt_core_3way_xmm
#else
	/* Check for AVX and OSXSAVE support */
	movl	$1, %eax
	cpuid
	andl	$0x18000000, %ecx
	cmpl	$0x18000000, %ecx
	jne scrypt_core_3way_xmm
	/* Check for XMM and YMM state support */
	xorl	%ecx, %ecx
	xgetbv
	andl	$0x00000006, %eax
	cmpl	$0x00000006, %eax
	jne scrypt_core_3way_xmm
#if defined(USE_XOP)
	/* Check for XOP support */
	movl	$0x80000001, %eax
	cpuid
	andl	$0x00000800, %ecx
	jnz scrypt_core_3way_xop
#endif
	
scrypt_core_3way_avx:
	movl	0+60(%rdi), %eax
	movl	0+44(%rdi), %ebx
	movl	0+28(%rdi), %ecx
	movl	0+12(%rdi), %edx
	movl	%eax, 0+12(%rsp)
	movl	%ebx, 0+28(%rsp)
	movl	%ecx, 0+44(%rsp)
	movl	%edx, 0+60(%rsp)
	movl	0+40(%rdi), %eax
	movl	0+8(%rdi), %ebx
	movl	0+48(%rdi), %ecx
	movl	0+16(%rdi), %edx
	movl	%eax, 0+8(%rsp)
	movl	%ebx, 0+40(%rsp)
	movl	%ecx, 0+16(%rsp)
	movl	%edx, 0+48(%rsp)
	movl	0+20(%rdi), %eax
	movl	0+4(%rdi), %ebx
	movl	0+52(%rdi), %ecx
	movl	0+36(%rdi), %edx
	movl	%eax, 0+4(%rsp)
	movl	%ebx, 0+20(%rsp)
	movl	%ecx, 0+36(%rsp)
	movl	%edx, 0+52(%rsp)
	movl	0+0(%rdi), %eax
	movl	0+24(%rdi), %ebx
	movl	0+32(%rdi), %ecx
	movl	0+56(%rdi), %edx
	movl	%eax, 0+0(%rsp)
	movl	%ebx, 0+24(%rsp)
	movl	%ecx, 0+32(%rsp)
	movl	%edx, 0+56(%rsp)
	movl	64+60(%rdi), %eax
	movl	64+44(%rdi), %ebx
	movl	64+28(%rdi), %ecx
	movl	64+12(%rdi), %edx
	movl	%eax, 64+12(%rsp)
	movl	%ebx, 64+28(%rsp)
	movl	%ecx, 64+44(%rsp)
	movl	%edx, 64+60(%rsp)
	movl	64+40(%rdi), %eax
	movl	64+8(%rdi), %ebx
	movl	64+48(%rdi), %ecx
	movl	64+16(%rdi), %edx
	movl	%eax, 64+8(%rsp)
	movl	%ebx, 64+40(%rsp)
	movl	%ecx, 64+16(%rsp)
	movl	%edx, 64+48(%rsp)
	movl	64+20(%rdi), %eax
	movl	64+4(%rdi), %ebx
	movl	64+52(%rdi), %ecx
	movl	64+36(%rdi), %edx
	movl	%eax, 64+4(%rsp)
	movl	%ebx, 64+20(%rsp)
	movl	%ecx, 64+36(%rsp)
	movl	%edx, 64+52(%rsp)
	movl	64+0(%rdi), %eax
	movl	64+24(%rdi), %ebx
	movl	64+32(%rdi), %ecx
	movl	64+56(%rdi), %edx
	movl	%eax, 64+0(%rsp)
	movl	%ebx, 64+24(%rsp)
	movl	%ecx, 64+32(%rsp)
	movl	%edx, 64+56(%rsp)
	movl	128+60(%rdi), %eax
	movl	128+44(%rdi), %ebx
	movl	128+28(%rdi), %ecx
	movl	128+12(%rdi), %edx
	movl	%eax, 128+12(%rsp)
	movl	%ebx, 128+28(%rsp)
	movl	%ecx, 128+44(%rsp)
	movl	%edx, 128+60(%rsp)
	movl	128+40(%rdi), %eax
	movl	128+8(%rdi), %ebx
	movl	128+48(%rdi), %ecx
	movl	128+16(%rdi), %edx
	movl	%eax, 128+8(%rsp)
	movl	%ebx, 128+40(%rsp)
	movl	%ecx, 128+16(%rsp)
	movl	%edx, 128+48(%rsp)
	movl	128+20(%rdi), %eax
	movl	128+4(%rdi), %ebx
	movl	128+52(%rdi), %ecx
	movl	128+36(%rdi), %edx
	movl	%eax, 128+4(%rsp)
	movl	%ebx, 128+20(%rsp)
	movl	%ecx, 128+36(%rsp)
	movl	%edx, 128+52(%rsp)
	movl	128+0(%rdi), %eax
	movl	128+24(%rdi), %ebx
	movl	128+32(%rdi), %ecx
	movl	128+56(%rdi), %edx
	movl	%eax, 128+0(%rsp)
	movl	%ebx, 128+24(%rsp)
	movl	%ecx, 128+32(%rsp)
	movl	%edx, 128+56(%rsp)
	movl	192+60(%rdi), %eax
	movl	192+44(%rdi), %ebx
	movl	192+28(%rdi), %ecx
	movl	192+12(%rdi), %edx
	movl	%eax, 192+12(%rsp)
	movl	%ebx, 192+28(%rsp)
	movl	%ecx, 192+44(%rsp)
	movl	%edx, 192+60(%rsp)
	movl	192+40(%rdi), %eax
	movl	192+8(%rdi), %ebx
	movl	192+48(%rdi), %ecx
	movl	192+16(%rdi), %edx
	movl	%eax, 192+8(%rsp)
	movl	%ebx, 192+40(%rsp)
	movl	%ecx, 192+16(%rsp)
	movl	%edx, 192+48(%rsp)
	movl	192+20(%rdi), %eax
	movl	192+4(%rdi), %ebx
	movl	192+52(%rdi), %ecx
	movl	192+36(%rdi), %edx
	movl	%eax, 192+4(%rsp)
	movl	%ebx, 192+20(%rsp)
	movl	%ecx, 192+36(%rsp)
	movl	%edx, 192+52(%rsp)
	movl	192+0(%rdi), %eax
	movl	192+24(%rdi), %ebx
	movl	192+32(%rdi), %ecx
	movl	192+56(%rdi), %edx
	movl	%eax, 192+0(%rsp)
	movl	%ebx, 192+24(%rsp)
	movl	%ecx, 192+32(%rsp)
	movl	%edx, 192+56(%rsp)
	movl	256+60(%rdi), %eax
	movl	256+44(%rdi), %ebx
	movl	256+28(%rdi), %ecx
	movl	256+12(%rdi), %edx
	movl	%eax, 256+12(%rsp)
	movl	%ebx, 256+28(%rsp)
	movl	%ecx, 256+44(%rsp)
	movl	%edx, 256+60(%rsp)
	movl	256+40(%rdi), %eax
	movl	256+8(%rdi), %ebx
	movl	256+48(%rdi), %ecx
	movl	256+16(%rdi), %edx
	movl	%eax, 256+8(%rsp)
	movl	%ebx, 256+40(%rsp)
	movl	%ecx, 256+16(%rsp)
	movl	%edx, 256+48(%rsp)
	movl	256+20(%rdi), %eax
	movl	256+4(%rdi), %ebx
	movl	256+52(%rdi), %ecx
	movl	256+36(%rdi), %edx
	movl	%eax, 256+4(%rsp)
	movl	%ebx, 256+20(%rsp)
	movl	%ecx, 256+36(%rsp)
	movl	%edx, 256+52(%rsp)
	movl	256+0(%rdi), %eax
	movl	256+24(%rdi), %ebx
	movl	256+32(%rdi), %ecx
	movl	256+56(%rdi), %edx
	movl	%eax, 256+0(%rsp)
	movl	%ebx, 256+24(%rsp)
	movl	%ecx, 256+32(%rsp)
	movl	%edx, 256+56(%rsp)
	movl	320+60(%rdi), %eax
	movl	320+44(%rdi), %ebx
	movl	320+28(%rdi), %ecx
	movl	320+12(%rdi), %edx
	movl	%eax, 320+12(%rsp)
	movl	%ebx, 320+28(%rsp)
	movl	%ecx, 320+44(%rsp)
	movl	%edx, 320+60(%rsp)
	movl	320+40(%rdi), %eax
	movl	320+8(%rdi), %ebx
	movl	320+48(%rdi), %ecx
	movl	320+16(%rdi), %edx
	movl	%eax, 320+8(%rsp)
	movl	%ebx, 320+40(%rsp)
	movl	%ecx, 320+16(%rsp)
	movl	%edx, 320+48(%rsp)
	movl	320+20(%rdi), %eax
	movl	320+4(%rdi), %ebx
	movl	320+52(%rdi), %ecx
	movl	320+36(%rdi), %edx
	movl	%eax, 320+4(%rsp)
	movl	%ebx, 320+20(%rsp)
	movl	%ecx, 320+36(%rsp)
	movl	%edx, 320+52(%rsp)
	movl	320+0(%rdi), %eax
	movl	320+24(%rdi), %ebx
	movl	320+32(%rdi), %ecx
	movl	320+56(%rdi), %edx
	movl	%eax, 320+0(%rsp)
	movl	%ebx, 320+24(%rsp)
	movl	%ecx, 320+32(%rsp)
	movl	%edx, 320+56(%rsp)
	
	movdqa	64(%rsp), %xmm0
	movdqa	80(%rsp), %xmm1
	movdqa	96(%rsp), %xmm2
	movdqa	112(%rsp), %xmm3
	movdqa	128+64(%rsp), %xmm8
	movdqa	128+80(%rsp), %xmm9
	movdqa	128+96(%rsp), %xmm10
	movdqa	128+112(%rsp), %xmm11
	movdqa	256+64(%rsp), %xmm12
	movdqa	256+80(%rsp), %xmm13
	movdqa	256+96(%rsp), %xmm14
	movdqa	256+112(%rsp), %xmm15
	
	movq	%rsi, %rbx
	leaq	(%r8, %r8, 2), %rax
	shlq	$7, %rax
	addq	%rsi, %rax
scrypt_core_3way_avx_loop1:
	movdqa	%xmm0, 64(%rbx)
	movdqa	%xmm1, 80(%rbx)
	movdqa	%xmm2, 96(%rbx)
	movdqa	%xmm3, 112(%rbx)
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	movdqa	%xmm8, 128+64(%rbx)
	movdqa	%xmm9, 128+80(%rbx)
	movdqa	%xmm10, 128+96(%rbx)
	movdqa	%xmm11, 128+112(%rbx)
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	movdqa	%xmm12, 256+64(%rbx)
	movdqa	%xmm13, 256+80(%rbx)
	movdqa	%xmm14, 256+96(%rbx)
	movdqa	%xmm15, 256+112(%rbx)
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rbx)
	movdqa	%xmm1, 16(%rbx)
	movdqa	%xmm2, 32(%rbx)
	movdqa	%xmm3, 48(%rbx)
	movdqa	%xmm8, 128+0(%rbx)
	movdqa	%xmm9, 128+16(%rbx)
	movdqa	%xmm10, 128+32(%rbx)
	movdqa	%xmm11, 128+48(%rbx)
	movdqa	%xmm12, 256+0(%rbx)
	movdqa	%xmm13, 256+16(%rbx)
	movdqa	%xmm14, 256+32(%rbx)
	movdqa	%xmm15, 256+48(%rbx)
	
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	paddd	0(%rbx), %xmm0
	paddd	16(%rbx), %xmm1
	paddd	32(%rbx), %xmm2
	paddd	48(%rbx), %xmm3
	paddd	128+0(%rbx), %xmm8
	paddd	128+16(%rbx), %xmm9
	paddd	128+32(%rbx), %xmm10
	paddd	128+48(%rbx), %xmm11
	paddd	256+0(%rbx), %xmm12
	paddd	256+16(%rbx), %xmm13
	paddd	256+32(%rbx), %xmm14
	paddd	256+48(%rbx), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rbx), %xmm0
	pxor	80(%rbx), %xmm1
	pxor	96(%rbx), %xmm2
	pxor	112(%rbx), %xmm3
	pxor	128+64(%rbx), %xmm8
	pxor	128+80(%rbx), %xmm9
	pxor	128+96(%rbx), %xmm10
	pxor	128+112(%rbx), %xmm11
	pxor	256+64(%rbx), %xmm12
	pxor	256+80(%rbx), %xmm13
	pxor	256+96(%rbx), %xmm14
	pxor	256+112(%rbx), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	
	addq	$3*128, %rbx
	cmpq	%rax, %rbx
	jne scrypt_core_3way_avx_loop1
	
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	movq	%r8, %rcx
	subq	$1, %r8
scrypt_core_3way_avx_loop2:
	movd	%xmm0, %ebp
	movd	%xmm8, %ebx
	movd	%xmm12, %eax
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	andl	%r8d, %ebp
	leaq	(%rbp, %rbp, 2), %rbp
	shll	$7, %ebp
	andl	%r8d, %ebx
	leaq	1(%rbx, %rbx, 2), %rbx
	shll	$7, %ebx
	andl	%r8d, %eax
	leaq	2(%rax, %rax, 2), %rax
	shll	$7, %eax
	pxor	0(%rsi, %rbp), %xmm0
	pxor	16(%rsi, %rbp), %xmm1
	pxor	32(%rsi, %rbp), %xmm2
	pxor	48(%rsi, %rbp), %xmm3
	pxor	0(%rsi, %rbx), %xmm8
	pxor	16(%rsi, %rbx), %xmm9
	pxor	32(%rsi, %rbx), %xmm10
	pxor	48(%rsi, %rbx), %xmm11
	pxor	0(%rsi, %rax), %xmm12
	pxor	16(%rsi, %rax), %xmm13
	pxor	32(%rsi, %rax), %xmm14
	pxor	48(%rsi, %rax), %xmm15
	
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	paddd	0(%rsp), %xmm0
	paddd	16(%rsp), %xmm1
	paddd	32(%rsp), %xmm2
	paddd	48(%rsp), %xmm3
	paddd	128+0(%rsp), %xmm8
	paddd	128+16(%rsp), %xmm9
	paddd	128+32(%rsp), %xmm10
	paddd	128+48(%rsp), %xmm11
	paddd	256+0(%rsp), %xmm12
	paddd	256+16(%rsp), %xmm13
	paddd	256+32(%rsp), %xmm14
	paddd	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rsi, %rbp), %xmm0
	pxor	80(%rsi, %rbp), %xmm1
	pxor	96(%rsi, %rbp), %xmm2
	pxor	112(%rsi, %rbp), %xmm3
	pxor	64(%rsi, %rbx), %xmm8
	pxor	80(%rsi, %rbx), %xmm9
	pxor	96(%rsi, %rbx), %xmm10
	pxor	112(%rsi, %rbx), %xmm11
	pxor	64(%rsi, %rax), %xmm12
	pxor	80(%rsi, %rax), %xmm13
	pxor	96(%rsi, %rax), %xmm14
	pxor	112(%rsi, %rax), %xmm15
	pxor	64(%rsp), %xmm0
	pxor	80(%rsp), %xmm1
	pxor	96(%rsp), %xmm2
	pxor	112(%rsp), %xmm3
	pxor	128+64(%rsp), %xmm8
	pxor	128+80(%rsp), %xmm9
	pxor	128+96(%rsp), %xmm10
	pxor	128+112(%rsp), %xmm11
	pxor	256+64(%rsp), %xmm12
	pxor	256+80(%rsp), %xmm13
	pxor	256+96(%rsp), %xmm14
	pxor	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vpslld	$7, %xmm4, %xmm5
	vpsrld	$25, %xmm4, %xmm4
	vpshufd	$0x39, %xmm1, %xmm1
	vpxor	%xmm5, %xmm1, %xmm1
	vpxor	%xmm4, %xmm1, %xmm1
	vpslld	$7, %xmm6, %xmm5
	vpsrld	$25, %xmm6, %xmm6
	vpshufd	$0x39, %xmm9, %xmm9
	vpxor	%xmm5, %xmm9, %xmm9
	vpxor	%xmm6, %xmm9, %xmm9
	vpslld	$7, %xmm7, %xmm5
	vpsrld	$25, %xmm7, %xmm7
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm5, %xmm13, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vpslld	$9, %xmm4, %xmm5
	vpsrld	$23, %xmm4, %xmm4
	vpxor	%xmm5, %xmm2, %xmm2
	vpxor	%xmm4, %xmm2, %xmm2
	vpslld	$9, %xmm6, %xmm5
	vpsrld	$23, %xmm6, %xmm6
	vpxor	%xmm5, %xmm10, %xmm10
	vpxor	%xmm6, %xmm10, %xmm10
	vpslld	$9, %xmm7, %xmm5
	vpsrld	$23, %xmm7, %xmm7
	vpxor	%xmm5, %xmm14, %xmm14
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vpslld	$13, %xmm4, %xmm5
	vpsrld	$19, %xmm4, %xmm4
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm5, %xmm3, %xmm3
	vpxor	%xmm4, %xmm3, %xmm3
	vpslld	$13, %xmm6, %xmm5
	vpsrld	$19, %xmm6, %xmm6
	vpxor	%xmm5, %xmm11, %xmm11
	vpxor	%xmm6, %xmm11, %xmm11
	vpslld	$13, %xmm7, %xmm5
	vpsrld	$19, %xmm7, %xmm7
	vpxor	%xmm5, %xmm15, %xmm15
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vpslld	$18, %xmm4, %xmm5
	vpsrld	$14, %xmm4, %xmm4
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpxor	%xmm5, %xmm0, %xmm0
	vpxor	%xmm4, %xmm0, %xmm0
	vpslld	$18, %xmm6, %xmm5
	vpsrld	$14, %xmm6, %xmm6
	vpshufd	$0x4e, %xmm14, %xmm14
	vpshufd	$0x39, %xmm11, %xmm11
	vpxor	%xmm5, %xmm8, %xmm8
	vpxor	%xmm6, %xmm8, %xmm8
	vpslld	$18, %xmm7, %xmm5
	vpsrld	$14, %xmm7, %xmm7
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm15, %xmm15
	vpxor	%xmm5, %xmm12, %xmm12
	vpxor	%xmm7, %xmm12, %xmm12
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	subq	$1, %rcx
	ja scrypt_core_3way_avx_loop2
	
	movl	0+60(%rsp), %eax
	movl	0+44(%rsp), %ebx
	movl	0+28(%rsp), %ecx
	movl	0+12(%rsp), %edx
	movl	%eax, 0+12(%rdi)
	movl	%ebx, 0+28(%rdi)
	movl	%ecx, 0+44(%rdi)
	movl	%edx, 0+60(%rdi)
	movl	0+40(%rsp), %eax
	movl	0+8(%rsp), %ebx
	movl	0+48(%rsp), %ecx
	movl	0+16(%rsp), %edx
	movl	%eax, 0+8(%rdi)
	movl	%ebx, 0+40(%rdi)
	movl	%ecx, 0+16(%rdi)
	movl	%edx, 0+48(%rdi)
	movl	0+20(%rsp), %eax
	movl	0+4(%rsp), %ebx
	movl	0+52(%rsp), %ecx
	movl	0+36(%rsp), %edx
	movl	%eax, 0+4(%rdi)
	movl	%ebx, 0+20(%rdi)
	movl	%ecx, 0+36(%rdi)
	movl	%edx, 0+52(%rdi)
	movl	0+0(%rsp), %eax
	movl	0+24(%rsp), %ebx
	movl	0+32(%rsp), %ecx
	movl	0+56(%rsp), %edx
	movl	%eax, 0+0(%rdi)
	movl	%ebx, 0+24(%rdi)
	movl	%ecx, 0+32(%rdi)
	movl	%edx, 0+56(%rdi)
	movl	64+60(%rsp), %eax
	movl	64+44(%rsp), %ebx
	movl	64+28(%rsp), %ecx
	movl	64+12(%rsp), %edx
	movl	%eax, 64+12(%rdi)
	movl	%ebx, 64+28(%rdi)
	movl	%ecx, 64+44(%rdi)
	movl	%edx, 64+60(%rdi)
	movl	64+40(%rsp), %eax
	movl	64+8(%rsp), %ebx
	movl	64+48(%rsp), %ecx
	movl	64+16(%rsp), %edx
	movl	%eax, 64+8(%rdi)
	movl	%ebx, 64+40(%rdi)
	movl	%ecx, 64+16(%rdi)
	movl	%edx, 64+48(%rdi)
	movl	64+20(%rsp), %eax
	movl	64+4(%rsp), %ebx
	movl	64+52(%rsp), %ecx
	movl	64+36(%rsp), %edx
	movl	%eax, 64+4(%rdi)
	movl	%ebx, 64+20(%rdi)
	movl	%ecx, 64+36(%rdi)
	movl	%edx, 64+52(%rdi)
	movl	64+0(%rsp), %eax
	movl	64+24(%rsp), %ebx
	movl	64+32(%rsp), %ecx
	movl	64+56(%rsp), %edx
	movl	%eax, 64+0(%rdi)
	movl	%ebx, 64+24(%rdi)
	movl	%ecx, 64+32(%rdi)
	movl	%edx, 64+56(%rdi)
	movl	128+60(%rsp), %eax
	movl	128+44(%rsp), %ebx
	movl	128+28(%rsp), %ecx
	movl	128+12(%rsp), %edx
	movl	%eax, 128+12(%rdi)
	movl	%ebx, 128+28(%rdi)
	movl	%ecx, 128+44(%rdi)
	movl	%edx, 128+60(%rdi)
	movl	128+40(%rsp), %eax
	movl	128+8(%rsp), %ebx
	movl	128+48(%rsp), %ecx
	movl	128+16(%rsp), %edx
	movl	%eax, 128+8(%rdi)
	movl	%ebx, 128+40(%rdi)
	movl	%ecx, 128+16(%rdi)
	movl	%edx, 128+48(%rdi)
	movl	128+20(%rsp), %eax
	movl	128+4(%rsp), %ebx
	movl	128+52(%rsp), %ecx
	movl	128+36(%rsp), %edx
	movl	%eax, 128+4(%rdi)
	movl	%ebx, 128+20(%rdi)
	movl	%ecx, 128+36(%rdi)
	movl	%edx, 128+52(%rdi)
	movl	128+0(%rsp), %eax
	movl	128+24(%rsp), %ebx
	movl	128+32(%rsp), %ecx
	movl	128+56(%rsp), %edx
	movl	%eax, 128+0(%rdi)
	movl	%ebx, 128+24(%rdi)
	movl	%ecx, 128+32(%rdi)
	movl	%edx, 128+56(%rdi)
	movl	192+60(%rsp), %eax
	movl	192+44(%rsp), %ebx
	movl	192+28(%rsp), %ecx
	movl	192+12(%rsp), %edx
	movl	%eax, 192+12(%rdi)
	movl	%ebx, 192+28(%rdi)
	movl	%ecx, 192+44(%rdi)
	movl	%edx, 192+60(%rdi)
	movl	192+40(%rsp), %eax
	movl	192+8(%rsp), %ebx
	movl	192+48(%rsp), %ecx
	movl	192+16(%rsp), %edx
	movl	%eax, 192+8(%rdi)
	movl	%ebx, 192+40(%rdi)
	movl	%ecx, 192+16(%rdi)
	movl	%edx, 192+48(%rdi)
	movl	192+20(%rsp), %eax
	movl	192+4(%rsp), %ebx
	movl	192+52(%rsp), %ecx
	movl	192+36(%rsp), %edx
	movl	%eax, 192+4(%rdi)
	movl	%ebx, 192+20(%rdi)
	movl	%ecx, 192+36(%rdi)
	movl	%edx, 192+52(%rdi)
	movl	192+0(%rsp), %eax
	movl	192+24(%rsp), %ebx
	movl	192+32(%rsp), %ecx
	movl	192+56(%rsp), %edx
	movl	%eax, 192+0(%rdi)
	movl	%ebx, 192+24(%rdi)
	movl	%ecx, 192+32(%rdi)
	movl	%edx, 192+56(%rdi)
	movl	256+60(%rsp), %eax
	movl	256+44(%rsp), %ebx
	movl	256+28(%rsp), %ecx
	movl	256+12(%rsp), %edx
	movl	%eax, 256+12(%rdi)
	movl	%ebx, 256+28(%rdi)
	movl	%ecx, 256+44(%rdi)
	movl	%edx, 256+60(%rdi)
	movl	256+40(%rsp), %eax
	movl	256+8(%rsp), %ebx
	movl	256+48(%rsp), %ecx
	movl	256+16(%rsp), %edx
	movl	%eax, 256+8(%rdi)
	movl	%ebx, 256+40(%rdi)
	movl	%ecx, 256+16(%rdi)
	movl	%edx, 256+48(%rdi)
	movl	256+20(%rsp), %eax
	movl	256+4(%rsp), %ebx
	movl	256+52(%rsp), %ecx
	movl	256+36(%rsp), %edx
	movl	%eax, 256+4(%rdi)
	movl	%ebx, 256+20(%rdi)
	movl	%ecx, 256+36(%rdi)
	movl	%edx, 256+52(%rdi)
	movl	256+0(%rsp), %eax
	movl	256+24(%rsp), %ebx
	movl	256+32(%rsp), %ecx
	movl	256+56(%rsp), %edx
	movl	%eax, 256+0(%rdi)
	movl	%ebx, 256+24(%rdi)
	movl	%ecx, 256+32(%rdi)
	movl	%edx, 256+56(%rdi)
	movl	320+60(%rsp), %eax
	movl	320+44(%rsp), %ebx
	movl	320+28(%rsp), %ecx
	movl	320+12(%rsp), %edx
	movl	%eax, 320+12(%rdi)
	movl	%ebx, 320+28(%rdi)
	movl	%ecx, 320+44(%rdi)
	movl	%edx, 320+60(%rdi)
	movl	320+40(%rsp), %eax
	movl	320+8(%rsp), %ebx
	movl	320+48(%rsp), %ecx
	movl	320+16(%rsp), %edx
	movl	%eax, 320+8(%rdi)
	movl	%ebx, 320+40(%rdi)
	movl	%ecx, 320+16(%rdi)
	movl	%edx, 320+48(%rdi)
	movl	320+20(%rsp), %eax
	movl	320+4(%rsp), %ebx
	movl	320+52(%rsp), %ecx
	movl	320+36(%rsp), %edx
	movl	%eax, 320+4(%rdi)
	movl	%ebx, 320+20(%rdi)
	movl	%ecx, 320+36(%rdi)
	movl	%edx, 320+52(%rdi)
	movl	320+0(%rsp), %eax
	movl	320+24(%rsp), %ebx
	movl	320+32(%rsp), %ecx
	movl	320+56(%rsp), %edx
	movl	%eax, 320+0(%rdi)
	movl	%ebx, 320+24(%rdi)
	movl	%ecx, 320+32(%rdi)
	movl	%edx, 320+56(%rdi)
	
	addq	$392, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%rbp
	popq	%rbx
	ret

#if defined(USE_XOP)

	
	.p2align 6
scrypt_core_3way_xop:
	movl	0+60(%rdi), %eax
	movl	0+44(%rdi), %ebx
	movl	0+28(%rdi), %ecx
	movl	0+12(%rdi), %edx
	movl	%eax, 0+12(%rsp)
	movl	%ebx, 0+28(%rsp)
	movl	%ecx, 0+44(%rsp)
	movl	%edx, 0+60(%rsp)
	movl	0+40(%rdi), %eax
	movl	0+8(%rdi), %ebx
	movl	0+48(%rdi), %ecx
	movl	0+16(%rdi), %edx
	movl	%eax, 0+8(%rsp)
	movl	%ebx, 0+40(%rsp)
	movl	%ecx, 0+16(%rsp)
	movl	%edx, 0+48(%rsp)
	movl	0+20(%rdi), %eax
	movl	0+4(%rdi), %ebx
	movl	0+52(%rdi), %ecx
	movl	0+36(%rdi), %edx
	movl	%eax, 0+4(%rsp)
	movl	%ebx, 0+20(%rsp)
	movl	%ecx, 0+36(%rsp)
	movl	%edx, 0+52(%rsp)
	movl	0+0(%rdi), %eax
	movl	0+24(%rdi), %ebx
	movl	0+32(%rdi), %ecx
	movl	0+56(%rdi), %edx
	movl	%eax, 0+0(%rsp)
	movl	%ebx, 0+24(%rsp)
	movl	%ecx, 0+32(%rsp)
	movl	%edx, 0+56(%rsp)
	movl	64+60(%rdi), %eax
	movl	64+44(%rdi), %ebx
	movl	64+28(%rdi), %ecx
	movl	64+12(%rdi), %edx
	movl	%eax, 64+12(%rsp)
	movl	%ebx, 64+28(%rsp)
	movl	%ecx, 64+44(%rsp)
	movl	%edx, 64+60(%rsp)
	movl	64+40(%rdi), %eax
	movl	64+8(%rdi), %ebx
	movl	64+48(%rdi), %ecx
	movl	64+16(%rdi), %edx
	movl	%eax, 64+8(%rsp)
	movl	%ebx, 64+40(%rsp)
	movl	%ecx, 64+16(%rsp)
	movl	%edx, 64+48(%rsp)
	movl	64+20(%rdi), %eax
	movl	64+4(%rdi), %ebx
	movl	64+52(%rdi), %ecx
	movl	64+36(%rdi), %edx
	movl	%eax, 64+4(%rsp)
	movl	%ebx, 64+20(%rsp)
	movl	%ecx, 64+36(%rsp)
	movl	%edx, 64+52(%rsp)
	movl	64+0(%rdi), %eax
	movl	64+24(%rdi), %ebx
	movl	64+32(%rdi), %ecx
	movl	64+56(%rdi), %edx
	movl	%eax, 64+0(%rsp)
	movl	%ebx, 64+24(%rsp)
	movl	%ecx, 64+32(%rsp)
	movl	%edx, 64+56(%rsp)
	movl	128+60(%rdi), %eax
	movl	128+44(%rdi), %ebx
	movl	128+28(%rdi), %ecx
	movl	128+12(%rdi), %edx
	movl	%eax, 128+12(%rsp)
	movl	%ebx, 128+28(%rsp)
	movl	%ecx, 128+44(%rsp)
	movl	%edx, 128+60(%rsp)
	movl	128+40(%rdi), %eax
	movl	128+8(%rdi), %ebx
	movl	128+48(%rdi), %ecx
	movl	128+16(%rdi), %edx
	movl	%eax, 128+8(%rsp)
	movl	%ebx, 128+40(%rsp)
	movl	%ecx, 128+16(%rsp)
	movl	%edx, 128+48(%rsp)
	movl	128+20(%rdi), %eax
	movl	128+4(%rdi), %ebx
	movl	128+52(%rdi), %ecx
	movl	128+36(%rdi), %edx
	movl	%eax, 128+4(%rsp)
	movl	%ebx, 128+20(%rsp)
	movl	%ecx, 128+36(%rsp)
	movl	%edx, 128+52(%rsp)
	movl	128+0(%rdi), %eax
	movl	128+24(%rdi), %ebx
	movl	128+32(%rdi), %ecx
	movl	128+56(%rdi), %edx
	movl	%eax, 128+0(%rsp)
	movl	%ebx, 128+24(%rsp)
	movl	%ecx, 128+32(%rsp)
	movl	%edx, 128+56(%rsp)
	movl	192+60(%rdi), %eax
	movl	192+44(%rdi), %ebx
	movl	192+28(%rdi), %ecx
	movl	192+12(%rdi), %edx
	movl	%eax, 192+12(%rsp)
	movl	%ebx, 192+28(%rsp)
	movl	%ecx, 192+44(%rsp)
	movl	%edx, 192+60(%rsp)
	movl	192+40(%rdi), %eax
	movl	192+8(%rdi), %ebx
	movl	192+48(%rdi), %ecx
	movl	192+16(%rdi), %edx
	movl	%eax, 192+8(%rsp)
	movl	%ebx, 192+40(%rsp)
	movl	%ecx, 192+16(%rsp)
	movl	%edx, 192+48(%rsp)
	movl	192+20(%rdi), %eax
	movl	192+4(%rdi), %ebx
	movl	192+52(%rdi), %ecx
	movl	192+36(%rdi), %edx
	movl	%eax, 192+4(%rsp)
	movl	%ebx, 192+20(%rsp)
	movl	%ecx, 192+36(%rsp)
	movl	%edx, 192+52(%rsp)
	movl	192+0(%rdi), %eax
	movl	192+24(%rdi), %ebx
	movl	192+32(%rdi), %ecx
	movl	192+56(%rdi), %edx
	movl	%eax, 192+0(%rsp)
	movl	%ebx, 192+24(%rsp)
	movl	%ecx, 192+32(%rsp)
	movl	%edx, 192+56(%rsp)
	movl	256+60(%rdi), %eax
	movl	256+44(%rdi), %ebx
	movl	256+28(%rdi), %ecx
	movl	256+12(%rdi), %edx
	movl	%eax, 256+12(%rsp)
	movl	%ebx, 256+28(%rsp)
	movl	%ecx, 256+44(%rsp)
	movl	%edx, 256+60(%rsp)
	movl	256+40(%rdi), %eax
	movl	256+8(%rdi), %ebx
	movl	256+48(%rdi), %ecx
	movl	256+16(%rdi), %edx
	movl	%eax, 256+8(%rsp)
	movl	%ebx, 256+40(%rsp)
	movl	%ecx, 256+16(%rsp)
	movl	%edx, 256+48(%rsp)
	movl	256+20(%rdi), %eax
	movl	256+4(%rdi), %ebx
	movl	256+52(%rdi), %ecx
	movl	256+36(%rdi), %edx
	movl	%eax, 256+4(%rsp)
	movl	%ebx, 256+20(%rsp)
	movl	%ecx, 256+36(%rsp)
	movl	%edx, 256+52(%rsp)
	movl	256+0(%rdi), %eax
	movl	256+24(%rdi), %ebx
	movl	256+32(%rdi), %ecx
	movl	256+56(%rdi), %edx
	movl	%eax, 256+0(%rsp)
	movl	%ebx, 256+24(%rsp)
	movl	%ecx, 256+32(%rsp)
	movl	%edx, 256+56(%rsp)
	movl	320+60(%rdi), %eax
	movl	320+44(%rdi), %ebx
	movl	320+28(%rdi), %ecx
	movl	320+12(%rdi), %edx
	movl	%eax, 320+12(%rsp)
	movl	%ebx, 320+28(%rsp)
	movl	%ecx, 320+44(%rsp)
	movl	%edx, 320+60(%rsp)
	movl	320+40(%rdi), %eax
	movl	320+8(%rdi), %ebx
	movl	320+48(%rdi), %ecx
	movl	320+16(%rdi), %edx
	movl	%eax, 320+8(%rsp)
	movl	%ebx, 320+40(%rsp)
	movl	%ecx, 320+16(%rsp)
	movl	%edx, 320+48(%rsp)
	movl	320+20(%rdi), %eax
	movl	320+4(%rdi), %ebx
	movl	320+52(%rdi), %ecx
	movl	320+36(%rdi), %edx
	movl	%eax, 320+4(%rsp)
	movl	%ebx, 320+20(%rsp)
	movl	%ecx, 320+36(%rsp)
	movl	%edx, 320+52(%rsp)
	movl	320+0(%rdi), %eax
	movl	320+24(%rdi), %ebx
	movl	320+32(%rdi), %ecx
	movl	320+56(%rdi), %edx
	movl	%eax, 320+0(%rsp)
	movl	%ebx, 320+24(%rsp)
	movl	%ecx, 320+32(%rsp)
	movl	%edx, 320+56(%rsp)
	
	movdqa	64(%rsp), %xmm0
	movdqa	80(%rsp), %xmm1
	movdqa	96(%rsp), %xmm2
	movdqa	112(%rsp), %xmm3
	movdqa	128+64(%rsp), %xmm8
	movdqa	128+80(%rsp), %xmm9
	movdqa	128+96(%rsp), %xmm10
	movdqa	128+112(%rsp), %xmm11
	movdqa	256+64(%rsp), %xmm12
	movdqa	256+80(%rsp), %xmm13
	movdqa	256+96(%rsp), %xmm14
	movdqa	256+112(%rsp), %xmm15
	
	movq	%rsi, %rbx
	leaq	(%r8, %r8, 2), %rax
	shlq	$7, %rax
	addq	%rsi, %rax
scrypt_core_3way_xop_loop1:
	movdqa	%xmm0, 64(%rbx)
	movdqa	%xmm1, 80(%rbx)
	movdqa	%xmm2, 96(%rbx)
	movdqa	%xmm3, 112(%rbx)
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	movdqa	%xmm8, 128+64(%rbx)
	movdqa	%xmm9, 128+80(%rbx)
	movdqa	%xmm10, 128+96(%rbx)
	movdqa	%xmm11, 128+112(%rbx)
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	movdqa	%xmm12, 256+64(%rbx)
	movdqa	%xmm13, 256+80(%rbx)
	movdqa	%xmm14, 256+96(%rbx)
	movdqa	%xmm15, 256+112(%rbx)
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rbx)
	movdqa	%xmm1, 16(%rbx)
	movdqa	%xmm2, 32(%rbx)
	movdqa	%xmm3, 48(%rbx)
	movdqa	%xmm8, 128+0(%rbx)
	movdqa	%xmm9, 128+16(%rbx)
	movdqa	%xmm10, 128+32(%rbx)
	movdqa	%xmm11, 128+48(%rbx)
	movdqa	%xmm12, 256+0(%rbx)
	movdqa	%xmm13, 256+16(%rbx)
	movdqa	%xmm14, 256+32(%rbx)
	movdqa	%xmm15, 256+48(%rbx)
	
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	paddd	0(%rbx), %xmm0
	paddd	16(%rbx), %xmm1
	paddd	32(%rbx), %xmm2
	paddd	48(%rbx), %xmm3
	paddd	128+0(%rbx), %xmm8
	paddd	128+16(%rbx), %xmm9
	paddd	128+32(%rbx), %xmm10
	paddd	128+48(%rbx), %xmm11
	paddd	256+0(%rbx), %xmm12
	paddd	256+16(%rbx), %xmm13
	paddd	256+32(%rbx), %xmm14
	paddd	256+48(%rbx), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rbx), %xmm0
	pxor	80(%rbx), %xmm1
	pxor	96(%rbx), %xmm2
	pxor	112(%rbx), %xmm3
	pxor	128+64(%rbx), %xmm8
	pxor	128+80(%rbx), %xmm9
	pxor	128+96(%rbx), %xmm10
	pxor	128+112(%rbx), %xmm11
	pxor	256+64(%rbx), %xmm12
	pxor	256+80(%rbx), %xmm13
	pxor	256+96(%rbx), %xmm14
	pxor	256+112(%rbx), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	
	addq	$3*128, %rbx
	cmpq	%rax, %rbx
	jne scrypt_core_3way_xop_loop1
	
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	movq	%r8, %rcx
	subq	$1, %r8
scrypt_core_3way_xop_loop2:
	movd	%xmm0, %ebp
	movd	%xmm8, %ebx
	movd	%xmm12, %eax
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	andl	%r8d, %ebp
	leaq	(%rbp, %rbp, 2), %rbp
	shll	$7, %ebp
	andl	%r8d, %ebx
	leaq	1(%rbx, %rbx, 2), %rbx
	shll	$7, %ebx
	andl	%r8d, %eax
	leaq	2(%rax, %rax, 2), %rax
	shll	$7, %eax
	pxor	0(%rsi, %rbp), %xmm0
	pxor	16(%rsi, %rbp), %xmm1
	pxor	32(%rsi, %rbp), %xmm2
	pxor	48(%rsi, %rbp), %xmm3
	pxor	0(%rsi, %rbx), %xmm8
	pxor	16(%rsi, %rbx), %xmm9
	pxor	32(%rsi, %rbx), %xmm10
	pxor	48(%rsi, %rbx), %xmm11
	pxor	0(%rsi, %rax), %xmm12
	pxor	16(%rsi, %rax), %xmm13
	pxor	32(%rsi, %rax), %xmm14
	pxor	48(%rsi, %rax), %xmm15
	
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	paddd	0(%rsp), %xmm0
	paddd	16(%rsp), %xmm1
	paddd	32(%rsp), %xmm2
	paddd	48(%rsp), %xmm3
	paddd	128+0(%rsp), %xmm8
	paddd	128+16(%rsp), %xmm9
	paddd	128+32(%rsp), %xmm10
	paddd	128+48(%rsp), %xmm11
	paddd	256+0(%rsp), %xmm12
	paddd	256+16(%rsp), %xmm13
	paddd	256+32(%rsp), %xmm14
	paddd	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rsi, %rbp), %xmm0
	pxor	80(%rsi, %rbp), %xmm1
	pxor	96(%rsi, %rbp), %xmm2
	pxor	112(%rsi, %rbp), %xmm3
	pxor	64(%rsi, %rbx), %xmm8
	pxor	80(%rsi, %rbx), %xmm9
	pxor	96(%rsi, %rbx), %xmm10
	pxor	112(%rsi, %rbx), %xmm11
	pxor	64(%rsi, %rax), %xmm12
	pxor	80(%rsi, %rax), %xmm13
	pxor	96(%rsi, %rax), %xmm14
	pxor	112(%rsi, %rax), %xmm15
	pxor	64(%rsp), %xmm0
	pxor	80(%rsp), %xmm1
	pxor	96(%rsp), %xmm2
	pxor	112(%rsp), %xmm3
	pxor	128+64(%rsp), %xmm8
	pxor	128+80(%rsp), %xmm9
	pxor	128+96(%rsp), %xmm10
	pxor	128+112(%rsp), %xmm11
	pxor	256+64(%rsp), %xmm12
	pxor	256+80(%rsp), %xmm13
	pxor	256+96(%rsp), %xmm14
	pxor	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	vpaddd	%xmm0, %xmm1, %xmm4
	vpaddd	%xmm8, %xmm9, %xmm6
	vpaddd	%xmm12, %xmm13, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm0, %xmm4
	vpaddd	%xmm11, %xmm8, %xmm6
	vpaddd	%xmm15, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm3, %xmm4
	vpaddd	%xmm10, %xmm11, %xmm6
	vpaddd	%xmm14, %xmm15, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm3, %xmm3
	vpshufd	$0x93, %xmm11, %xmm11
	vpshufd	$0x93, %xmm15, %xmm15
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm2, %xmm4
	vpaddd	%xmm9, %xmm10, %xmm6
	vpaddd	%xmm13, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm7, %xmm12, %xmm12
	
	vpaddd	%xmm0, %xmm3, %xmm4
	vpaddd	%xmm8, %xmm11, %xmm6
	vpaddd	%xmm12, %xmm15, %xmm7
	vprotd	$7, %xmm4, %xmm4
	vprotd	$7, %xmm6, %xmm6
	vprotd	$7, %xmm7, %xmm7
	vpshufd	$0x39, %xmm1, %xmm1
	vpshufd	$0x39, %xmm9, %xmm9
	vpshufd	$0x39, %xmm13, %xmm13
	vpxor	%xmm4, %xmm1, %xmm1
	vpxor	%xmm6, %xmm9, %xmm9
	vpxor	%xmm7, %xmm13, %xmm13
	
	vpaddd	%xmm1, %xmm0, %xmm4
	vpaddd	%xmm9, %xmm8, %xmm6
	vpaddd	%xmm13, %xmm12, %xmm7
	vprotd	$9, %xmm4, %xmm4
	vprotd	$9, %xmm6, %xmm6
	vprotd	$9, %xmm7, %xmm7
	vpxor	%xmm4, %xmm2, %xmm2
	vpxor	%xmm6, %xmm10, %xmm10
	vpxor	%xmm7, %xmm14, %xmm14
	
	vpaddd	%xmm2, %xmm1, %xmm4
	vpaddd	%xmm10, %xmm9, %xmm6
	vpaddd	%xmm14, %xmm13, %xmm7
	vprotd	$13, %xmm4, %xmm4
	vprotd	$13, %xmm6, %xmm6
	vprotd	$13, %xmm7, %xmm7
	vpshufd	$0x93, %xmm1, %xmm1
	vpshufd	$0x93, %xmm9, %xmm9
	vpshufd	$0x93, %xmm13, %xmm13
	vpxor	%xmm4, %xmm3, %xmm3
	vpxor	%xmm6, %xmm11, %xmm11
	vpxor	%xmm7, %xmm15, %xmm15
	
	vpaddd	%xmm3, %xmm2, %xmm4
	vpaddd	%xmm11, %xmm10, %xmm6
	vpaddd	%xmm15, %xmm14, %xmm7
	vprotd	$18, %xmm4, %xmm4
	vprotd	$18, %xmm6, %xmm6
	vprotd	$18, %xmm7, %xmm7
	vpshufd	$0x4e, %xmm2, %xmm2
	vpshufd	$0x4e, %xmm10, %xmm10
	vpshufd	$0x4e, %xmm14, %xmm14
	vpxor	%xmm4, %xmm0, %xmm0
	vpxor	%xmm6, %xmm8, %xmm8
	vpxor	%xmm7, %xmm12, %xmm12
	vpshufd	$0x39, %xmm3, %xmm3
	vpshufd	$0x39, %xmm11, %xmm11
	vpshufd	$0x39, %xmm15, %xmm15
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	subq	$1, %rcx
	ja scrypt_core_3way_xop_loop2
	
	movl	0+60(%rsp), %eax
	movl	0+44(%rsp), %ebx
	movl	0+28(%rsp), %ecx
	movl	0+12(%rsp), %edx
	movl	%eax, 0+12(%rdi)
	movl	%ebx, 0+28(%rdi)
	movl	%ecx, 0+44(%rdi)
	movl	%edx, 0+60(%rdi)
	movl	0+40(%rsp), %eax
	movl	0+8(%rsp), %ebx
	movl	0+48(%rsp), %ecx
	movl	0+16(%rsp), %edx
	movl	%eax, 0+8(%rdi)
	movl	%ebx, 0+40(%rdi)
	movl	%ecx, 0+16(%rdi)
	movl	%edx, 0+48(%rdi)
	movl	0+20(%rsp), %eax
	movl	0+4(%rsp), %ebx
	movl	0+52(%rsp), %ecx
	movl	0+36(%rsp), %edx
	movl	%eax, 0+4(%rdi)
	movl	%ebx, 0+20(%rdi)
	movl	%ecx, 0+36(%rdi)
	movl	%edx, 0+52(%rdi)
	movl	0+0(%rsp), %eax
	movl	0+24(%rsp), %ebx
	movl	0+32(%rsp), %ecx
	movl	0+56(%rsp), %edx
	movl	%eax, 0+0(%rdi)
	movl	%ebx, 0+24(%rdi)
	movl	%ecx, 0+32(%rdi)
	movl	%edx, 0+56(%rdi)
	movl	64+60(%rsp), %eax
	movl	64+44(%rsp), %ebx
	movl	64+28(%rsp), %ecx
	movl	64+12(%rsp), %edx
	movl	%eax, 64+12(%rdi)
	movl	%ebx, 64+28(%rdi)
	movl	%ecx, 64+44(%rdi)
	movl	%edx, 64+60(%rdi)
	movl	64+40(%rsp), %eax
	movl	64+8(%rsp), %ebx
	movl	64+48(%rsp), %ecx
	movl	64+16(%rsp), %edx
	movl	%eax, 64+8(%rdi)
	movl	%ebx, 64+40(%rdi)
	movl	%ecx, 64+16(%rdi)
	movl	%edx, 64+48(%rdi)
	movl	64+20(%rsp), %eax
	movl	64+4(%rsp), %ebx
	movl	64+52(%rsp), %ecx
	movl	64+36(%rsp), %edx
	movl	%eax, 64+4(%rdi)
	movl	%ebx, 64+20(%rdi)
	movl	%ecx, 64+36(%rdi)
	movl	%edx, 64+52(%rdi)
	movl	64+0(%rsp), %eax
	movl	64+24(%rsp), %ebx
	movl	64+32(%rsp), %ecx
	movl	64+56(%rsp), %edx
	movl	%eax, 64+0(%rdi)
	movl	%ebx, 64+24(%rdi)
	movl	%ecx, 64+32(%rdi)
	movl	%edx, 64+56(%rdi)
	movl	128+60(%rsp), %eax
	movl	128+44(%rsp), %ebx
	movl	128+28(%rsp), %ecx
	movl	128+12(%rsp), %edx
	movl	%eax, 128+12(%rdi)
	movl	%ebx, 128+28(%rdi)
	movl	%ecx, 128+44(%rdi)
	movl	%edx, 128+60(%rdi)
	movl	128+40(%rsp), %eax
	movl	128+8(%rsp), %ebx
	movl	128+48(%rsp), %ecx
	movl	128+16(%rsp), %edx
	movl	%eax, 128+8(%rdi)
	movl	%ebx, 128+40(%rdi)
	movl	%ecx, 128+16(%rdi)
	movl	%edx, 128+48(%rdi)
	movl	128+20(%rsp), %eax
	movl	128+4(%rsp), %ebx
	movl	128+52(%rsp), %ecx
	movl	128+36(%rsp), %edx
	movl	%eax, 128+4(%rdi)
	movl	%ebx, 128+20(%rdi)
	movl	%ecx, 128+36(%rdi)
	movl	%edx, 128+52(%rdi)
	movl	128+0(%rsp), %eax
	movl	128+24(%rsp), %ebx
	movl	128+32(%rsp), %ecx
	movl	128+56(%rsp), %edx
	movl	%eax, 128+0(%rdi)
	movl	%ebx, 128+24(%rdi)
	movl	%ecx, 128+32(%rdi)
	movl	%edx, 128+56(%rdi)
	movl	192+60(%rsp), %eax
	movl	192+44(%rsp), %ebx
	movl	192+28(%rsp), %ecx
	movl	192+12(%rsp), %edx
	movl	%eax, 192+12(%rdi)
	movl	%ebx, 192+28(%rdi)
	movl	%ecx, 192+44(%rdi)
	movl	%edx, 192+60(%rdi)
	movl	192+40(%rsp), %eax
	movl	192+8(%rsp), %ebx
	movl	192+48(%rsp), %ecx
	movl	192+16(%rsp), %edx
	movl	%eax, 192+8(%rdi)
	movl	%ebx, 192+40(%rdi)
	movl	%ecx, 192+16(%rdi)
	movl	%edx, 192+48(%rdi)
	movl	192+20(%rsp), %eax
	movl	192+4(%rsp), %ebx
	movl	192+52(%rsp), %ecx
	movl	192+36(%rsp), %edx
	movl	%eax, 192+4(%rdi)
	movl	%ebx, 192+20(%rdi)
	movl	%ecx, 192+36(%rdi)
	movl	%edx, 192+52(%rdi)
	movl	192+0(%rsp), %eax
	movl	192+24(%rsp), %ebx
	movl	192+32(%rsp), %ecx
	movl	192+56(%rsp), %edx
	movl	%eax, 192+0(%rdi)
	movl	%ebx, 192+24(%rdi)
	movl	%ecx, 192+32(%rdi)
	movl	%edx, 192+56(%rdi)
	movl	256+60(%rsp), %eax
	movl	256+44(%rsp), %ebx
	movl	256+28(%rsp), %ecx
	movl	256+12(%rsp), %edx
	movl	%eax, 256+12(%rdi)
	movl	%ebx, 256+28(%rdi)
	movl	%ecx, 256+44(%rdi)
	movl	%edx, 256+60(%rdi)
	movl	256+40(%rsp), %eax
	movl	256+8(%rsp), %ebx
	movl	256+48(%rsp), %ecx
	movl	256+16(%rsp), %edx
	movl	%eax, 256+8(%rdi)
	movl	%ebx, 256+40(%rdi)
	movl	%ecx, 256+16(%rdi)
	movl	%edx, 256+48(%rdi)
	movl	256+20(%rsp), %eax
	movl	256+4(%rsp), %ebx
	movl	256+52(%rsp), %ecx
	movl	256+36(%rsp), %edx
	movl	%eax, 256+4(%rdi)
	movl	%ebx, 256+20(%rdi)
	movl	%ecx, 256+36(%rdi)
	movl	%edx, 256+52(%rdi)
	movl	256+0(%rsp), %eax
	movl	256+24(%rsp), %ebx
	movl	256+32(%rsp), %ecx
	movl	256+56(%rsp), %edx
	movl	%eax, 256+0(%rdi)
	movl	%ebx, 256+24(%rdi)
	movl	%ecx, 256+32(%rdi)
	movl	%edx, 256+56(%rdi)
	movl	320+60(%rsp), %eax
	movl	320+44(%rsp), %ebx
	movl	320+28(%rsp), %ecx
	movl	320+12(%rsp), %edx
	movl	%eax, 320+12(%rdi)
	movl	%ebx, 320+28(%rdi)
	movl	%ecx, 320+44(%rdi)
	movl	%edx, 320+60(%rdi)
	movl	320+40(%rsp), %eax
	movl	320+8(%rsp), %ebx
	movl	320+48(%rsp), %ecx
	movl	320+16(%rsp), %edx
	movl	%eax, 320+8(%rdi)
	movl	%ebx, 320+40(%rdi)
	movl	%ecx, 320+16(%rdi)
	movl	%edx, 320+48(%rdi)
	movl	320+20(%rsp), %eax
	movl	320+4(%rsp), %ebx
	movl	320+52(%rsp), %ecx
	movl	320+36(%rsp), %edx
	movl	%eax, 320+4(%rdi)
	movl	%ebx, 320+20(%rdi)
	movl	%ecx, 320+36(%rdi)
	movl	%edx, 320+52(%rdi)
	movl	320+0(%rsp), %eax
	movl	320+24(%rsp), %ebx
	movl	320+32(%rsp), %ecx
	movl	320+56(%rsp), %edx
	movl	%eax, 320+0(%rdi)
	movl	%ebx, 320+24(%rdi)
	movl	%ecx, 320+32(%rdi)
	movl	%edx, 320+56(%rdi)
	
	addq	$392, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%rbp
	popq	%rbx
	ret
#endif /* USE_XOP */
#endif /* USE_AVX */
	

	
	.p2align 6
scrypt_core_3way_xmm:
	movl	0+60(%rdi), %eax
	movl	0+44(%rdi), %ebx
	movl	0+28(%rdi), %ecx
	movl	0+12(%rdi), %edx
	movl	%eax, 0+12(%rsp)
	movl	%ebx, 0+28(%rsp)
	movl	%ecx, 0+44(%rsp)
	movl	%edx, 0+60(%rsp)
	movl	0+40(%rdi), %eax
	movl	0+8(%rdi), %ebx
	movl	0+48(%rdi), %ecx
	movl	0+16(%rdi), %edx
	movl	%eax, 0+8(%rsp)
	movl	%ebx, 0+40(%rsp)
	movl	%ecx, 0+16(%rsp)
	movl	%edx, 0+48(%rsp)
	movl	0+20(%rdi), %eax
	movl	0+4(%rdi), %ebx
	movl	0+52(%rdi), %ecx
	movl	0+36(%rdi), %edx
	movl	%eax, 0+4(%rsp)
	movl	%ebx, 0+20(%rsp)
	movl	%ecx, 0+36(%rsp)
	movl	%edx, 0+52(%rsp)
	movl	0+0(%rdi), %eax
	movl	0+24(%rdi), %ebx
	movl	0+32(%rdi), %ecx
	movl	0+56(%rdi), %edx
	movl	%eax, 0+0(%rsp)
	movl	%ebx, 0+24(%rsp)
	movl	%ecx, 0+32(%rsp)
	movl	%edx, 0+56(%rsp)
	movl	64+60(%rdi), %eax
	movl	64+44(%rdi), %ebx
	movl	64+28(%rdi), %ecx
	movl	64+12(%rdi), %edx
	movl	%eax, 64+12(%rsp)
	movl	%ebx, 64+28(%rsp)
	movl	%ecx, 64+44(%rsp)
	movl	%edx, 64+60(%rsp)
	movl	64+40(%rdi), %eax
	movl	64+8(%rdi), %ebx
	movl	64+48(%rdi), %ecx
	movl	64+16(%rdi), %edx
	movl	%eax, 64+8(%rsp)
	movl	%ebx, 64+40(%rsp)
	movl	%ecx, 64+16(%rsp)
	movl	%edx, 64+48(%rsp)
	movl	64+20(%rdi), %eax
	movl	64+4(%rdi), %ebx
	movl	64+52(%rdi), %ecx
	movl	64+36(%rdi), %edx
	movl	%eax, 64+4(%rsp)
	movl	%ebx, 64+20(%rsp)
	movl	%ecx, 64+36(%rsp)
	movl	%edx, 64+52(%rsp)
	movl	64+0(%rdi), %eax
	movl	64+24(%rdi), %ebx
	movl	64+32(%rdi), %ecx
	movl	64+56(%rdi), %edx
	movl	%eax, 64+0(%rsp)
	movl	%ebx, 64+24(%rsp)
	movl	%ecx, 64+32(%rsp)
	movl	%edx, 64+56(%rsp)
	movl	128+60(%rdi), %eax
	movl	128+44(%rdi), %ebx
	movl	128+28(%rdi), %ecx
	movl	128+12(%rdi), %edx
	movl	%eax, 128+12(%rsp)
	movl	%ebx, 128+28(%rsp)
	movl	%ecx, 128+44(%rsp)
	movl	%edx, 128+60(%rsp)
	movl	128+40(%rdi), %eax
	movl	128+8(%rdi), %ebx
	movl	128+48(%rdi), %ecx
	movl	128+16(%rdi), %edx
	movl	%eax, 128+8(%rsp)
	movl	%ebx, 128+40(%rsp)
	movl	%ecx, 128+16(%rsp)
	movl	%edx, 128+48(%rsp)
	movl	128+20(%rdi), %eax
	movl	128+4(%rdi), %ebx
	movl	128+52(%rdi), %ecx
	movl	128+36(%rdi), %edx
	movl	%eax, 128+4(%rsp)
	movl	%ebx, 128+20(%rsp)
	movl	%ecx, 128+36(%rsp)
	movl	%edx, 128+52(%rsp)
	movl	128+0(%rdi), %eax
	movl	128+24(%rdi), %ebx
	movl	128+32(%rdi), %ecx
	movl	128+56(%rdi), %edx
	movl	%eax, 128+0(%rsp)
	movl	%ebx, 128+24(%rsp)
	movl	%ecx, 128+32(%rsp)
	movl	%edx, 128+56(%rsp)
	movl	192+60(%rdi), %eax
	movl	192+44(%rdi), %ebx
	movl	192+28(%rdi), %ecx
	movl	192+12(%rdi), %edx
	movl	%eax, 192+12(%rsp)
	movl	%ebx, 192+28(%rsp)
	movl	%ecx, 192+44(%rsp)
	movl	%edx, 192+60(%rsp)
	movl	192+40(%rdi), %eax
	movl	192+8(%rdi), %ebx
	movl	192+48(%rdi), %ecx
	movl	192+16(%rdi), %edx
	movl	%eax, 192+8(%rsp)
	movl	%ebx, 192+40(%rsp)
	movl	%ecx, 192+16(%rsp)
	movl	%edx, 192+48(%rsp)
	movl	192+20(%rdi), %eax
	movl	192+4(%rdi), %ebx
	movl	192+52(%rdi), %ecx
	movl	192+36(%rdi), %edx
	movl	%eax, 192+4(%rsp)
	movl	%ebx, 192+20(%rsp)
	movl	%ecx, 192+36(%rsp)
	movl	%edx, 192+52(%rsp)
	movl	192+0(%rdi), %eax
	movl	192+24(%rdi), %ebx
	movl	192+32(%rdi), %ecx
	movl	192+56(%rdi), %edx
	movl	%eax, 192+0(%rsp)
	movl	%ebx, 192+24(%rsp)
	movl	%ecx, 192+32(%rsp)
	movl	%edx, 192+56(%rsp)
	movl	256+60(%rdi), %eax
	movl	256+44(%rdi), %ebx
	movl	256+28(%rdi), %ecx
	movl	256+12(%rdi), %edx
	movl	%eax, 256+12(%rsp)
	movl	%ebx, 256+28(%rsp)
	movl	%ecx, 256+44(%rsp)
	movl	%edx, 256+60(%rsp)
	movl	256+40(%rdi), %eax
	movl	256+8(%rdi), %ebx
	movl	256+48(%rdi), %ecx
	movl	256+16(%rdi), %edx
	movl	%eax, 256+8(%rsp)
	movl	%ebx, 256+40(%rsp)
	movl	%ecx, 256+16(%rsp)
	movl	%edx, 256+48(%rsp)
	movl	256+20(%rdi), %eax
	movl	256+4(%rdi), %ebx
	movl	256+52(%rdi), %ecx
	movl	256+36(%rdi), %edx
	movl	%eax, 256+4(%rsp)
	movl	%ebx, 256+20(%rsp)
	movl	%ecx, 256+36(%rsp)
	movl	%edx, 256+52(%rsp)
	movl	256+0(%rdi), %eax
	movl	256+24(%rdi), %ebx
	movl	256+32(%rdi), %ecx
	movl	256+56(%rdi), %edx
	movl	%eax, 256+0(%rsp)
	movl	%ebx, 256+24(%rsp)
	movl	%ecx, 256+32(%rsp)
	movl	%edx, 256+56(%rsp)
	movl	320+60(%rdi), %eax
	movl	320+44(%rdi), %ebx
	movl	320+28(%rdi), %ecx
	movl	320+12(%rdi), %edx
	movl	%eax, 320+12(%rsp)
	movl	%ebx, 320+28(%rsp)
	movl	%ecx, 320+44(%rsp)
	movl	%edx, 320+60(%rsp)
	movl	320+40(%rdi), %eax
	movl	320+8(%rdi), %ebx
	movl	320+48(%rdi), %ecx
	movl	320+16(%rdi), %edx
	movl	%eax, 320+8(%rsp)
	movl	%ebx, 320+40(%rsp)
	movl	%ecx, 320+16(%rsp)
	movl	%edx, 320+48(%rsp)
	movl	320+20(%rdi), %eax
	movl	320+4(%rdi), %ebx
	movl	320+52(%rdi), %ecx
	movl	320+36(%rdi), %edx
	movl	%eax, 320+4(%rsp)
	movl	%ebx, 320+20(%rsp)
	movl	%ecx, 320+36(%rsp)
	movl	%edx, 320+52(%rsp)
	movl	320+0(%rdi), %eax
	movl	320+24(%rdi), %ebx
	movl	320+32(%rdi), %ecx
	movl	320+56(%rdi), %edx
	movl	%eax, 320+0(%rsp)
	movl	%ebx, 320+24(%rsp)
	movl	%ecx, 320+32(%rsp)
	movl	%edx, 320+56(%rsp)
	
	movdqa	64(%rsp), %xmm0
	movdqa	80(%rsp), %xmm1
	movdqa	96(%rsp), %xmm2
	movdqa	112(%rsp), %xmm3
	movdqa	128+64(%rsp), %xmm8
	movdqa	128+80(%rsp), %xmm9
	movdqa	128+96(%rsp), %xmm10
	movdqa	128+112(%rsp), %xmm11
	movdqa	256+64(%rsp), %xmm12
	movdqa	256+80(%rsp), %xmm13
	movdqa	256+96(%rsp), %xmm14
	movdqa	256+112(%rsp), %xmm15
	
	movq	%rsi, %rbx
	leaq	(%r8, %r8, 2), %rax
	shlq	$7, %rax
	addq	%rsi, %rax
scrypt_core_3way_xmm_loop1:
	movdqa	%xmm0, 64(%rbx)
	movdqa	%xmm1, 80(%rbx)
	movdqa	%xmm2, 96(%rbx)
	movdqa	%xmm3, 112(%rbx)
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	movdqa	%xmm8, 128+64(%rbx)
	movdqa	%xmm9, 128+80(%rbx)
	movdqa	%xmm10, 128+96(%rbx)
	movdqa	%xmm11, 128+112(%rbx)
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	movdqa	%xmm12, 256+64(%rbx)
	movdqa	%xmm13, 256+80(%rbx)
	movdqa	%xmm14, 256+96(%rbx)
	movdqa	%xmm15, 256+112(%rbx)
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rbx)
	movdqa	%xmm1, 16(%rbx)
	movdqa	%xmm2, 32(%rbx)
	movdqa	%xmm3, 48(%rbx)
	movdqa	%xmm8, 128+0(%rbx)
	movdqa	%xmm9, 128+16(%rbx)
	movdqa	%xmm10, 128+32(%rbx)
	movdqa	%xmm11, 128+48(%rbx)
	movdqa	%xmm12, 256+0(%rbx)
	movdqa	%xmm13, 256+16(%rbx)
	movdqa	%xmm14, 256+32(%rbx)
	movdqa	%xmm15, 256+48(%rbx)
	
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	paddd	0(%rbx), %xmm0
	paddd	16(%rbx), %xmm1
	paddd	32(%rbx), %xmm2
	paddd	48(%rbx), %xmm3
	paddd	128+0(%rbx), %xmm8
	paddd	128+16(%rbx), %xmm9
	paddd	128+32(%rbx), %xmm10
	paddd	128+48(%rbx), %xmm11
	paddd	256+0(%rbx), %xmm12
	paddd	256+16(%rbx), %xmm13
	paddd	256+32(%rbx), %xmm14
	paddd	256+48(%rbx), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rbx), %xmm0
	pxor	80(%rbx), %xmm1
	pxor	96(%rbx), %xmm2
	pxor	112(%rbx), %xmm3
	pxor	128+64(%rbx), %xmm8
	pxor	128+80(%rbx), %xmm9
	pxor	128+96(%rbx), %xmm10
	pxor	128+112(%rbx), %xmm11
	pxor	256+64(%rbx), %xmm12
	pxor	256+80(%rbx), %xmm13
	pxor	256+96(%rbx), %xmm14
	pxor	256+112(%rbx), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	
	addq	$3*128, %rbx
	cmpq	%rax, %rbx
	jne scrypt_core_3way_xmm_loop1
	
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	movq	%r8, %rcx
	subq	$1, %r8
scrypt_core_3way_xmm_loop2:
	movd	%xmm0, %ebp
	movd	%xmm8, %ebx
	movd	%xmm12, %eax
	pxor	0(%rsp), %xmm0
	pxor	16(%rsp), %xmm1
	pxor	32(%rsp), %xmm2
	pxor	48(%rsp), %xmm3
	pxor	128+0(%rsp), %xmm8
	pxor	128+16(%rsp), %xmm9
	pxor	128+32(%rsp), %xmm10
	pxor	128+48(%rsp), %xmm11
	pxor	256+0(%rsp), %xmm12
	pxor	256+16(%rsp), %xmm13
	pxor	256+32(%rsp), %xmm14
	pxor	256+48(%rsp), %xmm15
	andl	%r8d, %ebp
	leaq	(%rbp, %rbp, 2), %rbp
	shll	$7, %ebp
	andl	%r8d, %ebx
	leaq	1(%rbx, %rbx, 2), %rbx
	shll	$7, %ebx
	andl	%r8d, %eax
	leaq	2(%rax, %rax, 2), %rax
	shll	$7, %eax
	pxor	0(%rsi, %rbp), %xmm0
	pxor	16(%rsi, %rbp), %xmm1
	pxor	32(%rsi, %rbp), %xmm2
	pxor	48(%rsi, %rbp), %xmm3
	pxor	0(%rsi, %rbx), %xmm8
	pxor	16(%rsi, %rbx), %xmm9
	pxor	32(%rsi, %rbx), %xmm10
	pxor	48(%rsi, %rbx), %xmm11
	pxor	0(%rsi, %rax), %xmm12
	pxor	16(%rsi, %rax), %xmm13
	pxor	32(%rsi, %rax), %xmm14
	pxor	48(%rsi, %rax), %xmm15
	
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	paddd	0(%rsp), %xmm0
	paddd	16(%rsp), %xmm1
	paddd	32(%rsp), %xmm2
	paddd	48(%rsp), %xmm3
	paddd	128+0(%rsp), %xmm8
	paddd	128+16(%rsp), %xmm9
	paddd	128+32(%rsp), %xmm10
	paddd	128+48(%rsp), %xmm11
	paddd	256+0(%rsp), %xmm12
	paddd	256+16(%rsp), %xmm13
	paddd	256+32(%rsp), %xmm14
	paddd	256+48(%rsp), %xmm15
	movdqa	%xmm0, 0(%rsp)
	movdqa	%xmm1, 16(%rsp)
	movdqa	%xmm2, 32(%rsp)
	movdqa	%xmm3, 48(%rsp)
	movdqa	%xmm8, 128+0(%rsp)
	movdqa	%xmm9, 128+16(%rsp)
	movdqa	%xmm10, 128+32(%rsp)
	movdqa	%xmm11, 128+48(%rsp)
	movdqa	%xmm12, 256+0(%rsp)
	movdqa	%xmm13, 256+16(%rsp)
	movdqa	%xmm14, 256+32(%rsp)
	movdqa	%xmm15, 256+48(%rsp)
	
	pxor	64(%rsi, %rbp), %xmm0
	pxor	80(%rsi, %rbp), %xmm1
	pxor	96(%rsi, %rbp), %xmm2
	pxor	112(%rsi, %rbp), %xmm3
	pxor	64(%rsi, %rbx), %xmm8
	pxor	80(%rsi, %rbx), %xmm9
	pxor	96(%rsi, %rbx), %xmm10
	pxor	112(%rsi, %rbx), %xmm11
	pxor	64(%rsi, %rax), %xmm12
	pxor	80(%rsi, %rax), %xmm13
	pxor	96(%rsi, %rax), %xmm14
	pxor	112(%rsi, %rax), %xmm15
	pxor	64(%rsp), %xmm0
	pxor	80(%rsp), %xmm1
	pxor	96(%rsp), %xmm2
	pxor	112(%rsp), %xmm3
	pxor	128+64(%rsp), %xmm8
	pxor	128+80(%rsp), %xmm9
	pxor	128+96(%rsp), %xmm10
	pxor	128+112(%rsp), %xmm11
	pxor	256+64(%rsp), %xmm12
	pxor	256+80(%rsp), %xmm13
	pxor	256+96(%rsp), %xmm14
	pxor	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	movdqa	%xmm1, %xmm4
	movdqa	%xmm9, %xmm6
	movdqa	%xmm13, %xmm7
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	pxor	%xmm5, %xmm3
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm11
	pxor	%xmm5, %xmm11
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm15
	pxor	%xmm5, %xmm15
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pshufd	$0x93, %xmm3, %xmm3
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm11, %xmm6
	pshufd	$0x93, %xmm11, %xmm11
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm14
	pshufd	$0x93, %xmm15, %xmm15
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm1
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm9
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm9
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm13
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm13
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	pxor	%xmm5, %xmm0
	movdqa	%xmm3, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pxor	%xmm5, %xmm8
	movdqa	%xmm11, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	movdqa	%xmm15, %xmm7
	pxor	%xmm5, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	
	paddd	%xmm0, %xmm4
	paddd	%xmm8, %xmm6
	paddd	%xmm12, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, %xmm4
	movdqa	%xmm6, %xmm5
	pslld	$7, %xmm6
	psrld	$25, %xmm5
	pxor	%xmm6, %xmm9
	pxor	%xmm5, %xmm9
	movdqa	%xmm8, %xmm6
	movdqa	%xmm7, %xmm5
	pslld	$7, %xmm7
	psrld	$25, %xmm5
	pxor	%xmm7, %xmm13
	pxor	%xmm5, %xmm13
	movdqa	%xmm12, %xmm7
	
	paddd	%xmm1, %xmm4
	paddd	%xmm9, %xmm6
	paddd	%xmm13, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pshufd	$0x93, %xmm1, %xmm1
	pxor	%xmm5, %xmm2
	movdqa	%xmm6, %xmm5
	pslld	$9, %xmm6
	psrld	$23, %xmm5
	pxor	%xmm6, %xmm10
	movdqa	%xmm9, %xmm6
	pshufd	$0x93, %xmm9, %xmm9
	pxor	%xmm5, %xmm10
	movdqa	%xmm7, %xmm5
	pslld	$9, %xmm7
	psrld	$23, %xmm5
	pxor	%xmm7, %xmm14
	movdqa	%xmm13, %xmm7
	pshufd	$0x93, %xmm13, %xmm13
	pxor	%xmm5, %xmm14
	
	paddd	%xmm2, %xmm4
	paddd	%xmm10, %xmm6
	paddd	%xmm14, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pshufd	$0x4e, %xmm2, %xmm2
	pxor	%xmm5, %xmm3
	movdqa	%xmm6, %xmm5
	pslld	$13, %xmm6
	psrld	$19, %xmm5
	pxor	%xmm6, %xmm11
	movdqa	%xmm10, %xmm6
	pshufd	$0x4e, %xmm10, %xmm10
	pxor	%xmm5, %xmm11
	movdqa	%xmm7, %xmm5
	pslld	$13, %xmm7
	psrld	$19, %xmm5
	pxor	%xmm7, %xmm15
	movdqa	%xmm14, %xmm7
	pshufd	$0x4e, %xmm14, %xmm14
	pxor	%xmm5, %xmm15
	
	paddd	%xmm3, %xmm4
	paddd	%xmm11, %xmm6
	paddd	%xmm15, %xmm7
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	movdqa	%xmm6, %xmm5
	pslld	$18, %xmm6
	psrld	$14, %xmm5
	pxor	%xmm6, %xmm8
	pshufd	$0x39, %xmm11, %xmm11
	pxor	%xmm5, %xmm8
	movdqa	%xmm7, %xmm5
	pslld	$18, %xmm7
	psrld	$14, %xmm5
	pxor	%xmm7, %xmm12
	pshufd	$0x39, %xmm15, %xmm15
	pxor	%xmm5, %xmm12
	paddd	64(%rsp), %xmm0
	paddd	80(%rsp), %xmm1
	paddd	96(%rsp), %xmm2
	paddd	112(%rsp), %xmm3
	paddd	128+64(%rsp), %xmm8
	paddd	128+80(%rsp), %xmm9
	paddd	128+96(%rsp), %xmm10
	paddd	128+112(%rsp), %xmm11
	paddd	256+64(%rsp), %xmm12
	paddd	256+80(%rsp), %xmm13
	paddd	256+96(%rsp), %xmm14
	paddd	256+112(%rsp), %xmm15
	movdqa	%xmm0, 64(%rsp)
	movdqa	%xmm1, 80(%rsp)
	movdqa	%xmm2, 96(%rsp)
	movdqa	%xmm3, 112(%rsp)
	movdqa	%xmm8, 128+64(%rsp)
	movdqa	%xmm9, 128+80(%rsp)
	movdqa	%xmm10, 128+96(%rsp)
	movdqa	%xmm11, 128+112(%rsp)
	movdqa	%xmm12, 256+64(%rsp)
	movdqa	%xmm13, 256+80(%rsp)
	movdqa	%xmm14, 256+96(%rsp)
	movdqa	%xmm15, 256+112(%rsp)
	
	subq	$1, %rcx
	ja scrypt_core_3way_xmm_loop2
	
	movl	0+60(%rsp), %eax
	movl	0+44(%rsp), %ebx
	movl	0+28(%rsp), %ecx
	movl	0+12(%rsp), %edx
	movl	%eax, 0+12(%rdi)
	movl	%ebx, 0+28(%rdi)
	movl	%ecx, 0+44(%rdi)
	movl	%edx, 0+60(%rdi)
	movl	0+40(%rsp), %eax
	movl	0+8(%rsp), %ebx
	movl	0+48(%rsp), %ecx
	movl	0+16(%rsp), %edx
	movl	%eax, 0+8(%rdi)
	movl	%ebx, 0+40(%rdi)
	movl	%ecx, 0+16(%rdi)
	movl	%edx, 0+48(%rdi)
	movl	0+20(%rsp), %eax
	movl	0+4(%rsp), %ebx
	movl	0+52(%rsp), %ecx
	movl	0+36(%rsp), %edx
	movl	%eax, 0+4(%rdi)
	movl	%ebx, 0+20(%rdi)
	movl	%ecx, 0+36(%rdi)
	movl	%edx, 0+52(%rdi)
	movl	0+0(%rsp), %eax
	movl	0+24(%rsp), %ebx
	movl	0+32(%rsp), %ecx
	movl	0+56(%rsp), %edx
	movl	%eax, 0+0(%rdi)
	movl	%ebx, 0+24(%rdi)
	movl	%ecx, 0+32(%rdi)
	movl	%edx, 0+56(%rdi)
	movl	64+60(%rsp), %eax
	movl	64+44(%rsp), %ebx
	movl	64+28(%rsp), %ecx
	movl	64+12(%rsp), %edx
	movl	%eax, 64+12(%rdi)
	movl	%ebx, 64+28(%rdi)
	movl	%ecx, 64+44(%rdi)
	movl	%edx, 64+60(%rdi)
	movl	64+40(%rsp), %eax
	movl	64+8(%rsp), %ebx
	movl	64+48(%rsp), %ecx
	movl	64+16(%rsp), %edx
	movl	%eax, 64+8(%rdi)
	movl	%ebx, 64+40(%rdi)
	movl	%ecx, 64+16(%rdi)
	movl	%edx, 64+48(%rdi)
	movl	64+20(%rsp), %eax
	movl	64+4(%rsp), %ebx
	movl	64+52(%rsp), %ecx
	movl	64+36(%rsp), %edx
	movl	%eax, 64+4(%rdi)
	movl	%ebx, 64+20(%rdi)
	movl	%ecx, 64+36(%rdi)
	movl	%edx, 64+52(%rdi)
	movl	64+0(%rsp), %eax
	movl	64+24(%rsp), %ebx
	movl	64+32(%rsp), %ecx
	movl	64+56(%rsp), %edx
	movl	%eax, 64+0(%rdi)
	movl	%ebx, 64+24(%rdi)
	movl	%ecx, 64+32(%rdi)
	movl	%edx, 64+56(%rdi)
	movl	128+60(%rsp), %eax
	movl	128+44(%rsp), %ebx
	movl	128+28(%rsp), %ecx
	movl	128+12(%rsp), %edx
	movl	%eax, 128+12(%rdi)
	movl	%ebx, 128+28(%rdi)
	movl	%ecx, 128+44(%rdi)
	movl	%edx, 128+60(%rdi)
	movl	128+40(%rsp), %eax
	movl	128+8(%rsp), %ebx
	movl	128+48(%rsp), %ecx
	movl	128+16(%rsp), %edx
	movl	%eax, 128+8(%rdi)
	movl	%ebx, 128+40(%rdi)
	movl	%ecx, 128+16(%rdi)
	movl	%edx, 128+48(%rdi)
	movl	128+20(%rsp), %eax
	movl	128+4(%rsp), %ebx
	movl	128+52(%rsp), %ecx
	movl	128+36(%rsp), %edx
	movl	%eax, 128+4(%rdi)
	movl	%ebx, 128+20(%rdi)
	movl	%ecx, 128+36(%rdi)
	movl	%edx, 128+52(%rdi)
	movl	128+0(%rsp), %eax
	movl	128+24(%rsp), %ebx
	movl	128+32(%rsp), %ecx
	movl	128+56(%rsp), %edx
	movl	%eax, 128+0(%rdi)
	movl	%ebx, 128+24(%rdi)
	movl	%ecx, 128+32(%rdi)
	movl	%edx, 128+56(%rdi)
	movl	192+60(%rsp), %eax
	movl	192+44(%rsp), %ebx
	movl	192+28(%rsp), %ecx
	movl	192+12(%rsp), %edx
	movl	%eax, 192+12(%rdi)
	movl	%ebx, 192+28(%rdi)
	movl	%ecx, 192+44(%rdi)
	movl	%edx, 192+60(%rdi)
	movl	192+40(%rsp), %eax
	movl	192+8(%rsp), %ebx
	movl	192+48(%rsp), %ecx
	movl	192+16(%rsp), %edx
	movl	%eax, 192+8(%rdi)
	movl	%ebx, 192+40(%rdi)
	movl	%ecx, 192+16(%rdi)
	movl	%edx, 192+48(%rdi)
	movl	192+20(%rsp), %eax
	movl	192+4(%rsp), %ebx
	movl	192+52(%rsp), %ecx
	movl	192+36(%rsp), %edx
	movl	%eax, 192+4(%rdi)
	movl	%ebx, 192+20(%rdi)
	movl	%ecx, 192+36(%rdi)
	movl	%edx, 192+52(%rdi)
	movl	192+0(%rsp), %eax
	movl	192+24(%rsp), %ebx
	movl	192+32(%rsp), %ecx
	movl	192+56(%rsp), %edx
	movl	%eax, 192+0(%rdi)
	movl	%ebx, 192+24(%rdi)
	movl	%ecx, 192+32(%rdi)
	movl	%edx, 192+56(%rdi)
	movl	256+60(%rsp), %eax
	movl	256+44(%rsp), %ebx
	movl	256+28(%rsp), %ecx
	movl	256+12(%rsp), %edx
	movl	%eax, 256+12(%rdi)
	movl	%ebx, 256+28(%rdi)
	movl	%ecx, 256+44(%rdi)
	movl	%edx, 256+60(%rdi)
	movl	256+40(%rsp), %eax
	movl	256+8(%rsp), %ebx
	movl	256+48(%rsp), %ecx
	movl	256+16(%rsp), %edx
	movl	%eax, 256+8(%rdi)
	movl	%ebx, 256+40(%rdi)
	movl	%ecx, 256+16(%rdi)
	movl	%edx, 256+48(%rdi)
	movl	256+20(%rsp), %eax
	movl	256+4(%rsp), %ebx
	movl	256+52(%rsp), %ecx
	movl	256+36(%rsp), %edx
	movl	%eax, 256+4(%rdi)
	movl	%ebx, 256+20(%rdi)
	movl	%ecx, 256+36(%rdi)
	movl	%edx, 256+52(%rdi)
	movl	256+0(%rsp), %eax
	movl	256+24(%rsp), %ebx
	movl	256+32(%rsp), %ecx
	movl	256+56(%rsp), %edx
	movl	%eax, 256+0(%rdi)
	movl	%ebx, 256+24(%rdi)
	movl	%ecx, 256+32(%rdi)
	movl	%edx, 256+56(%rdi)
	movl	320+60(%rsp), %eax
	movl	320+44(%rsp), %ebx
	movl	320+28(%rsp), %ecx
	movl	320+12(%rsp), %edx
	movl	%eax, 320+12(%rdi)
	movl	%ebx, 320+28(%rdi)
	movl	%ecx, 320+44(%rdi)
	movl	%edx, 320+60(%rdi)
	movl	320+40(%rsp), %eax
	movl	320+8(%rsp), %ebx
	movl	320+48(%rsp), %ecx
	movl	320+16(%rsp), %edx
	movl	%eax, 320+8(%rdi)
	movl	%ebx, 320+40(%rdi)
	movl	%ecx, 320+16(%rdi)
	movl	%edx, 320+48(%rdi)
	movl	320+20(%rsp), %eax
	movl	320+4(%rsp), %ebx
	movl	320+52(%rsp), %ecx
	movl	320+36(%rsp), %edx
	movl	%eax, 320+4(%rdi)
	movl	%ebx, 320+20(%rdi)
	movl	%ecx, 320+36(%rdi)
	movl	%edx, 320+52(%rdi)
	movl	320+0(%rsp), %eax
	movl	320+24(%rsp), %ebx
	movl	320+32(%rsp), %ecx
	movl	320+56(%rsp), %edx
	movl	%eax, 320+0(%rdi)
	movl	%ebx, 320+24(%rdi)
	movl	%ecx, 320+32(%rdi)
	movl	%edx, 320+56(%rdi)
	
	addq	$392, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%rbp
	popq	%rbx
	ret


#if defined(USE_AVX2)


	
	.text
	.p2align 6
	.globl scrypt_core_6way
	.globl _scrypt_core_6way
scrypt_core_6way:
_scrypt_core_6way:
	pushq	%rbx
	pushq	%rbp
#if defined(_WIN64) || defined(__CYGWIN__)
	subq	$176, %rsp
	vmovdqa	%xmm6, 8(%rsp)
	vmovdqa	%xmm7, 24(%rsp)
	vmovdqa	%xmm8, 40(%rsp)
	vmovdqa	%xmm9, 56(%rsp)
	vmovdqa	%xmm10, 72(%rsp)
	vmovdqa	%xmm11, 88(%rsp)
	vmovdqa	%xmm12, 104(%rsp)
	vmovdqa	%xmm13, 120(%rsp)
	vmovdqa	%xmm14, 136(%rsp)
	vmovdqa	%xmm15, 152(%rsp)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
#else
	movq	%rdx, %r8
#endif
	movq	%rsp, %rdx
	subq	$768, %rsp
	andq	$-128, %rsp
	


	
scrypt_core_6way_avx2:
	vmovdqa	0*256+0+0*16(%rdi), %xmm0
	vmovdqa	0*256+0+1*16(%rdi), %xmm1
	vmovdqa	0*256+0+2*16(%rdi), %xmm2
	vmovdqa	0*256+0+3*16(%rdi), %xmm3
	vinserti128	$1, 0*256+0+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 0*256+0+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 0*256+0+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 0*256+0+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 0*128+0*32(%rsp)
	vmovdqa	%ymm1, 0*128+1*32(%rsp)
	vmovdqa	%ymm2, 0*128+2*32(%rsp)
	vmovdqa	%ymm3, 0*128+3*32(%rsp)
	vmovdqa	0*256+64+0*16(%rdi), %xmm0
	vmovdqa	0*256+64+1*16(%rdi), %xmm1
	vmovdqa	0*256+64+2*16(%rdi), %xmm2
	vmovdqa	0*256+64+3*16(%rdi), %xmm3
	vinserti128	$1, 0*256+64+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 0*256+64+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 0*256+64+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 0*256+64+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 1*128+0*32(%rsp)
	vmovdqa	%ymm1, 1*128+1*32(%rsp)
	vmovdqa	%ymm2, 1*128+2*32(%rsp)
	vmovdqa	%ymm3, 1*128+3*32(%rsp)
	vmovdqa	1*256+0+0*16(%rdi), %xmm0
	vmovdqa	1*256+0+1*16(%rdi), %xmm1
	vmovdqa	1*256+0+2*16(%rdi), %xmm2
	vmovdqa	1*256+0+3*16(%rdi), %xmm3
	vinserti128	$1, 1*256+0+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 1*256+0+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 1*256+0+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 1*256+0+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 2*128+0*32(%rsp)
	vmovdqa	%ymm1, 2*128+1*32(%rsp)
	vmovdqa	%ymm2, 2*128+2*32(%rsp)
	vmovdqa	%ymm3, 2*128+3*32(%rsp)
	vmovdqa	1*256+64+0*16(%rdi), %xmm0
	vmovdqa	1*256+64+1*16(%rdi), %xmm1
	vmovdqa	1*256+64+2*16(%rdi), %xmm2
	vmovdqa	1*256+64+3*16(%rdi), %xmm3
	vinserti128	$1, 1*256+64+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 1*256+64+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 1*256+64+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 1*256+64+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 3*128+0*32(%rsp)
	vmovdqa	%ymm1, 3*128+1*32(%rsp)
	vmovdqa	%ymm2, 3*128+2*32(%rsp)
	vmovdqa	%ymm3, 3*128+3*32(%rsp)
	vmovdqa	2*256+0+0*16(%rdi), %xmm0
	vmovdqa	2*256+0+1*16(%rdi), %xmm1
	vmovdqa	2*256+0+2*16(%rdi), %xmm2
	vmovdqa	2*256+0+3*16(%rdi), %xmm3
	vinserti128	$1, 2*256+0+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 2*256+0+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 2*256+0+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 2*256+0+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 4*128+0*32(%rsp)
	vmovdqa	%ymm1, 4*128+1*32(%rsp)
	vmovdqa	%ymm2, 4*128+2*32(%rsp)
	vmovdqa	%ymm3, 4*128+3*32(%rsp)
	vmovdqa	2*256+64+0*16(%rdi), %xmm0
	vmovdqa	2*256+64+1*16(%rdi), %xmm1
	vmovdqa	2*256+64+2*16(%rdi), %xmm2
	vmovdqa	2*256+64+3*16(%rdi), %xmm3
	vinserti128	$1, 2*256+64+128+0*16(%rdi), %ymm0, %ymm0
	vinserti128	$1, 2*256+64+128+1*16(%rdi), %ymm1, %ymm1
	vinserti128	$1, 2*256+64+128+2*16(%rdi), %ymm2, %ymm2
	vinserti128	$1, 2*256+64+128+3*16(%rdi), %ymm3, %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%ymm0, 5*128+0*32(%rsp)
	vmovdqa	%ymm1, 5*128+1*32(%rsp)
	vmovdqa	%ymm2, 5*128+2*32(%rsp)
	vmovdqa	%ymm3, 5*128+3*32(%rsp)
	
	vmovdqa	0*256+4*32(%rsp), %ymm0
	vmovdqa	0*256+5*32(%rsp), %ymm1
	vmovdqa	0*256+6*32(%rsp), %ymm2
	vmovdqa	0*256+7*32(%rsp), %ymm3
	vmovdqa	1*256+4*32(%rsp), %ymm8
	vmovdqa	1*256+5*32(%rsp), %ymm9
	vmovdqa	1*256+6*32(%rsp), %ymm10
	vmovdqa	1*256+7*32(%rsp), %ymm11
	vmovdqa	2*256+4*32(%rsp), %ymm12
	vmovdqa	2*256+5*32(%rsp), %ymm13
	vmovdqa	2*256+6*32(%rsp), %ymm14
	vmovdqa	2*256+7*32(%rsp), %ymm15
	
	movq	%rsi, %rbx
	leaq	(%r8, %r8, 2), %rax
	shlq	$8, %rax
	addq	%rsi, %rax
scrypt_core_6way_avx2_loop1:
	vmovdqa	%ymm0, 0*256+4*32(%rbx)
	vmovdqa	%ymm1, 0*256+5*32(%rbx)
	vmovdqa	%ymm2, 0*256+6*32(%rbx)
	vmovdqa	%ymm3, 0*256+7*32(%rbx)
	vpxor	0*256+0*32(%rsp), %ymm0, %ymm0
	vpxor	0*256+1*32(%rsp), %ymm1, %ymm1
	vpxor	0*256+2*32(%rsp), %ymm2, %ymm2
	vpxor	0*256+3*32(%rsp), %ymm3, %ymm3
	vmovdqa	%ymm8, 1*256+4*32(%rbx)
	vmovdqa	%ymm9, 1*256+5*32(%rbx)
	vmovdqa	%ymm10, 1*256+6*32(%rbx)
	vmovdqa	%ymm11, 1*256+7*32(%rbx)
	vpxor	1*256+0*32(%rsp), %ymm8, %ymm8
	vpxor	1*256+1*32(%rsp), %ymm9, %ymm9
	vpxor	1*256+2*32(%rsp), %ymm10, %ymm10
	vpxor	1*256+3*32(%rsp), %ymm11, %ymm11
	vmovdqa	%ymm12, 2*256+4*32(%rbx)
	vmovdqa	%ymm13, 2*256+5*32(%rbx)
	vmovdqa	%ymm14, 2*256+6*32(%rbx)
	vmovdqa	%ymm15, 2*256+7*32(%rbx)
	vpxor	2*256+0*32(%rsp), %ymm12, %ymm12
	vpxor	2*256+1*32(%rsp), %ymm13, %ymm13
	vpxor	2*256+2*32(%rsp), %ymm14, %ymm14
	vpxor	2*256+3*32(%rsp), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+0*32(%rbx)
	vmovdqa	%ymm1, 0*256+1*32(%rbx)
	vmovdqa	%ymm2, 0*256+2*32(%rbx)
	vmovdqa	%ymm3, 0*256+3*32(%rbx)
	vmovdqa	%ymm8, 1*256+0*32(%rbx)
	vmovdqa	%ymm9, 1*256+1*32(%rbx)
	vmovdqa	%ymm10, 1*256+2*32(%rbx)
	vmovdqa	%ymm11, 1*256+3*32(%rbx)
	vmovdqa	%ymm12, 2*256+0*32(%rbx)
	vmovdqa	%ymm13, 2*256+1*32(%rbx)
	vmovdqa	%ymm14, 2*256+2*32(%rbx)
	vmovdqa	%ymm15, 2*256+3*32(%rbx)
	
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	0*256+0*32(%rbx), %ymm0, %ymm0
	vpaddd	0*256+1*32(%rbx), %ymm1, %ymm1
	vpaddd	0*256+2*32(%rbx), %ymm2, %ymm2
	vpaddd	0*256+3*32(%rbx), %ymm3, %ymm3
	vpaddd	1*256+0*32(%rbx), %ymm8, %ymm8
	vpaddd	1*256+1*32(%rbx), %ymm9, %ymm9
	vpaddd	1*256+2*32(%rbx), %ymm10, %ymm10
	vpaddd	1*256+3*32(%rbx), %ymm11, %ymm11
	vpaddd	2*256+0*32(%rbx), %ymm12, %ymm12
	vpaddd	2*256+1*32(%rbx), %ymm13, %ymm13
	vpaddd	2*256+2*32(%rbx), %ymm14, %ymm14
	vpaddd	2*256+3*32(%rbx), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+0*32(%rsp)
	vmovdqa	%ymm1, 0*256+1*32(%rsp)
	vmovdqa	%ymm2, 0*256+2*32(%rsp)
	vmovdqa	%ymm3, 0*256+3*32(%rsp)
	vmovdqa	%ymm8, 1*256+0*32(%rsp)
	vmovdqa	%ymm9, 1*256+1*32(%rsp)
	vmovdqa	%ymm10, 1*256+2*32(%rsp)
	vmovdqa	%ymm11, 1*256+3*32(%rsp)
	vmovdqa	%ymm12, 2*256+0*32(%rsp)
	vmovdqa	%ymm13, 2*256+1*32(%rsp)
	vmovdqa	%ymm14, 2*256+2*32(%rsp)
	vmovdqa	%ymm15, 2*256+3*32(%rsp)
	
	vpxor	0*256+4*32(%rbx), %ymm0, %ymm0
	vpxor	0*256+5*32(%rbx), %ymm1, %ymm1
	vpxor	0*256+6*32(%rbx), %ymm2, %ymm2
	vpxor	0*256+7*32(%rbx), %ymm3, %ymm3
	vpxor	1*256+4*32(%rbx), %ymm8, %ymm8
	vpxor	1*256+5*32(%rbx), %ymm9, %ymm9
	vpxor	1*256+6*32(%rbx), %ymm10, %ymm10
	vpxor	1*256+7*32(%rbx), %ymm11, %ymm11
	vpxor	2*256+4*32(%rbx), %ymm12, %ymm12
	vpxor	2*256+5*32(%rbx), %ymm13, %ymm13
	vpxor	2*256+6*32(%rbx), %ymm14, %ymm14
	vpxor	2*256+7*32(%rbx), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+4*32(%rsp)
	vmovdqa	%ymm1, 0*256+5*32(%rsp)
	vmovdqa	%ymm2, 0*256+6*32(%rsp)
	vmovdqa	%ymm3, 0*256+7*32(%rsp)
	vmovdqa	%ymm8, 1*256+4*32(%rsp)
	vmovdqa	%ymm9, 1*256+5*32(%rsp)
	vmovdqa	%ymm10, 1*256+6*32(%rsp)
	vmovdqa	%ymm11, 1*256+7*32(%rsp)
	vmovdqa	%ymm12, 2*256+4*32(%rsp)
	vmovdqa	%ymm13, 2*256+5*32(%rsp)
	vmovdqa	%ymm14, 2*256+6*32(%rsp)
	vmovdqa	%ymm15, 2*256+7*32(%rsp)
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	0*256+4*32(%rsp), %ymm0, %ymm0
	vpaddd	0*256+5*32(%rsp), %ymm1, %ymm1
	vpaddd	0*256+6*32(%rsp), %ymm2, %ymm2
	vpaddd	0*256+7*32(%rsp), %ymm3, %ymm3
	vpaddd	1*256+4*32(%rsp), %ymm8, %ymm8
	vpaddd	1*256+5*32(%rsp), %ymm9, %ymm9
	vpaddd	1*256+6*32(%rsp), %ymm10, %ymm10
	vpaddd	1*256+7*32(%rsp), %ymm11, %ymm11
	vpaddd	2*256+4*32(%rsp), %ymm12, %ymm12
	vpaddd	2*256+5*32(%rsp), %ymm13, %ymm13
	vpaddd	2*256+6*32(%rsp), %ymm14, %ymm14
	vpaddd	2*256+7*32(%rsp), %ymm15, %ymm15
	
	addq	$6*128, %rbx
	cmpq	%rax, %rbx
	jne scrypt_core_6way_avx2_loop1
	
	vmovdqa	%ymm0, 0*256+4*32(%rsp)
	vmovdqa	%ymm1, 0*256+5*32(%rsp)
	vmovdqa	%ymm2, 0*256+6*32(%rsp)
	vmovdqa	%ymm3, 0*256+7*32(%rsp)
	vmovdqa	%ymm8, 1*256+4*32(%rsp)
	vmovdqa	%ymm9, 1*256+5*32(%rsp)
	vmovdqa	%ymm10, 1*256+6*32(%rsp)
	vmovdqa	%ymm11, 1*256+7*32(%rsp)
	vmovdqa	%ymm12, 2*256+4*32(%rsp)
	vmovdqa	%ymm13, 2*256+5*32(%rsp)
	vmovdqa	%ymm14, 2*256+6*32(%rsp)
	vmovdqa	%ymm15, 2*256+7*32(%rsp)
	
	movq	%r8, %rcx
	leaq	-1(%r8), %r11
scrypt_core_6way_avx2_loop2:
	vmovd	%xmm0, %ebp
	vmovd	%xmm8, %ebx
	vmovd	%xmm12, %eax
	vextracti128	$1, %ymm0, %xmm4
	vextracti128	$1, %ymm8, %xmm5
	vextracti128	$1, %ymm12, %xmm6
	vmovd	%xmm4, %r8d
	vmovd	%xmm5, %r9d
	vmovd	%xmm6, %r10d
	vpxor	0*256+0*32(%rsp), %ymm0, %ymm0
	vpxor	0*256+1*32(%rsp), %ymm1, %ymm1
	vpxor	0*256+2*32(%rsp), %ymm2, %ymm2
	vpxor	0*256+3*32(%rsp), %ymm3, %ymm3
	vpxor	1*256+0*32(%rsp), %ymm8, %ymm8
	vpxor	1*256+1*32(%rsp), %ymm9, %ymm9
	vpxor	1*256+2*32(%rsp), %ymm10, %ymm10
	vpxor	1*256+3*32(%rsp), %ymm11, %ymm11
	vpxor	2*256+0*32(%rsp), %ymm12, %ymm12
	vpxor	2*256+1*32(%rsp), %ymm13, %ymm13
	vpxor	2*256+2*32(%rsp), %ymm14, %ymm14
	vpxor	2*256+3*32(%rsp), %ymm15, %ymm15
	andl	%r11d, %ebp
	leaq	0(%rbp, %rbp, 2), %rbp
	shll	$8, %ebp
	andl	%r11d, %ebx
	leaq	1(%rbx, %rbx, 2), %rbx
	shll	$8, %ebx
	andl	%r11d, %eax
	leaq	2(%rax, %rax, 2), %rax
	shll	$8, %eax
	andl	%r11d, %r8d
	leaq	0(%r8, %r8, 2), %r8
	shll	$8, %r8d
	andl	%r11d, %r9d
	leaq	1(%r9, %r9, 2), %r9
	shll	$8, %r9d
	andl	%r11d, %r10d
	leaq	2(%r10, %r10, 2), %r10
	shll	$8, %r10d
	vmovdqa	0*32(%rsi, %rbp), %xmm4
	vinserti128	$1, 0*32+16(%rsi, %r8), %ymm4, %ymm4
	vmovdqa	1*32(%rsi, %rbp), %xmm5
	vinserti128	$1, 1*32+16(%rsi, %r8), %ymm5, %ymm5
	vmovdqa	2*32(%rsi, %rbp), %xmm6
	vinserti128	$1, 2*32+16(%rsi, %r8), %ymm6, %ymm6
	vmovdqa	3*32(%rsi, %rbp), %xmm7
	vinserti128	$1, 3*32+16(%rsi, %r8), %ymm7, %ymm7
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm6, %ymm2, %ymm2
	vpxor	%ymm7, %ymm3, %ymm3
	vmovdqa	0*32(%rsi, %rbx), %xmm4
	vinserti128	$1, 0*32+16(%rsi, %r9), %ymm4, %ymm4
	vmovdqa	1*32(%rsi, %rbx), %xmm5
	vinserti128	$1, 1*32+16(%rsi, %r9), %ymm5, %ymm5
	vmovdqa	2*32(%rsi, %rbx), %xmm6
	vinserti128	$1, 2*32+16(%rsi, %r9), %ymm6, %ymm6
	vmovdqa	3*32(%rsi, %rbx), %xmm7
	vinserti128	$1, 3*32+16(%rsi, %r9), %ymm7, %ymm7
	vpxor	%ymm4, %ymm8, %ymm8
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm10, %ymm10
	vpxor	%ymm7, %ymm11, %ymm11
	vmovdqa	0*32(%rsi, %rax), %xmm4
	vinserti128	$1, 0*32+16(%rsi, %r10), %ymm4, %ymm4
	vmovdqa	1*32(%rsi, %rax), %xmm5
	vinserti128	$1, 1*32+16(%rsi, %r10), %ymm5, %ymm5
	vmovdqa	2*32(%rsi, %rax), %xmm6
	vinserti128	$1, 2*32+16(%rsi, %r10), %ymm6, %ymm6
	vmovdqa	3*32(%rsi, %rax), %xmm7
	vinserti128	$1, 3*32+16(%rsi, %r10), %ymm7, %ymm7
	vpxor	%ymm4, %ymm12, %ymm12
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm6, %ymm14, %ymm14
	vpxor	%ymm7, %ymm15, %ymm15
	
	vmovdqa	%ymm0, 0*256+0*32(%rsp)
	vmovdqa	%ymm1, 0*256+1*32(%rsp)
	vmovdqa	%ymm2, 0*256+2*32(%rsp)
	vmovdqa	%ymm3, 0*256+3*32(%rsp)
	vmovdqa	%ymm8, 1*256+0*32(%rsp)
	vmovdqa	%ymm9, 1*256+1*32(%rsp)
	vmovdqa	%ymm10, 1*256+2*32(%rsp)
	vmovdqa	%ymm11, 1*256+3*32(%rsp)
	vmovdqa	%ymm12, 2*256+0*32(%rsp)
	vmovdqa	%ymm13, 2*256+1*32(%rsp)
	vmovdqa	%ymm14, 2*256+2*32(%rsp)
	vmovdqa	%ymm15, 2*256+3*32(%rsp)
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	0*256+0*32(%rsp), %ymm0, %ymm0
	vpaddd	0*256+1*32(%rsp), %ymm1, %ymm1
	vpaddd	0*256+2*32(%rsp), %ymm2, %ymm2
	vpaddd	0*256+3*32(%rsp), %ymm3, %ymm3
	vpaddd	1*256+0*32(%rsp), %ymm8, %ymm8
	vpaddd	1*256+1*32(%rsp), %ymm9, %ymm9
	vpaddd	1*256+2*32(%rsp), %ymm10, %ymm10
	vpaddd	1*256+3*32(%rsp), %ymm11, %ymm11
	vpaddd	2*256+0*32(%rsp), %ymm12, %ymm12
	vpaddd	2*256+1*32(%rsp), %ymm13, %ymm13
	vpaddd	2*256+2*32(%rsp), %ymm14, %ymm14
	vpaddd	2*256+3*32(%rsp), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+0*32(%rsp)
	vmovdqa	%ymm1, 0*256+1*32(%rsp)
	vmovdqa	%ymm2, 0*256+2*32(%rsp)
	vmovdqa	%ymm3, 0*256+3*32(%rsp)
	vmovdqa	%ymm8, 1*256+0*32(%rsp)
	vmovdqa	%ymm9, 1*256+1*32(%rsp)
	vmovdqa	%ymm10, 1*256+2*32(%rsp)
	vmovdqa	%ymm11, 1*256+3*32(%rsp)
	vmovdqa	%ymm12, 2*256+0*32(%rsp)
	vmovdqa	%ymm13, 2*256+1*32(%rsp)
	vmovdqa	%ymm14, 2*256+2*32(%rsp)
	vmovdqa	%ymm15, 2*256+3*32(%rsp)
	
	vmovdqa	4*32(%rsi, %rbp), %xmm4
	vinserti128	$1, 4*32+16(%rsi, %r8), %ymm4, %ymm4
	vmovdqa	5*32(%rsi, %rbp), %xmm5
	vinserti128	$1, 5*32+16(%rsi, %r8), %ymm5, %ymm5
	vmovdqa	6*32(%rsi, %rbp), %xmm6
	vinserti128	$1, 6*32+16(%rsi, %r8), %ymm6, %ymm6
	vmovdqa	7*32(%rsi, %rbp), %xmm7
	vinserti128	$1, 7*32+16(%rsi, %r8), %ymm7, %ymm7
	vpxor	%ymm4, %ymm0, %ymm0
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm6, %ymm2, %ymm2
	vpxor	%ymm7, %ymm3, %ymm3
	vmovdqa	4*32(%rsi, %rbx), %xmm4
	vinserti128	$1, 4*32+16(%rsi, %r9), %ymm4, %ymm4
	vmovdqa	5*32(%rsi, %rbx), %xmm5
	vinserti128	$1, 5*32+16(%rsi, %r9), %ymm5, %ymm5
	vmovdqa	6*32(%rsi, %rbx), %xmm6
	vinserti128	$1, 6*32+16(%rsi, %r9), %ymm6, %ymm6
	vmovdqa	7*32(%rsi, %rbx), %xmm7
	vinserti128	$1, 7*32+16(%rsi, %r9), %ymm7, %ymm7
	vpxor	%ymm4, %ymm8, %ymm8
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm10, %ymm10
	vpxor	%ymm7, %ymm11, %ymm11
	vmovdqa	4*32(%rsi, %rax), %xmm4
	vinserti128	$1, 4*32+16(%rsi, %r10), %ymm4, %ymm4
	vmovdqa	5*32(%rsi, %rax), %xmm5
	vinserti128	$1, 5*32+16(%rsi, %r10), %ymm5, %ymm5
	vmovdqa	6*32(%rsi, %rax), %xmm6
	vinserti128	$1, 6*32+16(%rsi, %r10), %ymm6, %ymm6
	vmovdqa	7*32(%rsi, %rax), %xmm7
	vinserti128	$1, 7*32+16(%rsi, %r10), %ymm7, %ymm7
	vpxor	%ymm4, %ymm12, %ymm12
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm6, %ymm14, %ymm14
	vpxor	%ymm7, %ymm15, %ymm15
	vpxor	0*256+4*32(%rsp), %ymm0, %ymm0
	vpxor	0*256+5*32(%rsp), %ymm1, %ymm1
	vpxor	0*256+6*32(%rsp), %ymm2, %ymm2
	vpxor	0*256+7*32(%rsp), %ymm3, %ymm3
	vpxor	1*256+4*32(%rsp), %ymm8, %ymm8
	vpxor	1*256+5*32(%rsp), %ymm9, %ymm9
	vpxor	1*256+6*32(%rsp), %ymm10, %ymm10
	vpxor	1*256+7*32(%rsp), %ymm11, %ymm11
	vpxor	2*256+4*32(%rsp), %ymm12, %ymm12
	vpxor	2*256+5*32(%rsp), %ymm13, %ymm13
	vpxor	2*256+6*32(%rsp), %ymm14, %ymm14
	vpxor	2*256+7*32(%rsp), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+4*32(%rsp)
	vmovdqa	%ymm1, 0*256+5*32(%rsp)
	vmovdqa	%ymm2, 0*256+6*32(%rsp)
	vmovdqa	%ymm3, 0*256+7*32(%rsp)
	vmovdqa	%ymm8, 1*256+4*32(%rsp)
	vmovdqa	%ymm9, 1*256+5*32(%rsp)
	vmovdqa	%ymm10, 1*256+6*32(%rsp)
	vmovdqa	%ymm11, 1*256+7*32(%rsp)
	vmovdqa	%ymm12, 2*256+4*32(%rsp)
	vmovdqa	%ymm13, 2*256+5*32(%rsp)
	vmovdqa	%ymm14, 2*256+6*32(%rsp)
	vmovdqa	%ymm15, 2*256+7*32(%rsp)
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	%ymm0, %ymm1, %ymm4
	vpaddd	%ymm8, %ymm9, %ymm6
	vpaddd	%ymm12, %ymm13, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm0, %ymm4
	vpaddd	%ymm11, %ymm8, %ymm6
	vpaddd	%ymm15, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm3, %ymm4
	vpaddd	%ymm10, %ymm11, %ymm6
	vpaddd	%ymm14, %ymm15, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm3, %ymm3
	vpshufd	$0x93, %ymm11, %ymm11
	vpshufd	$0x93, %ymm15, %ymm15
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm2, %ymm4
	vpaddd	%ymm9, %ymm10, %ymm6
	vpaddd	%ymm13, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpshufd	$0x4e, %ymm14, %ymm14
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	
	vpaddd	%ymm0, %ymm3, %ymm4
	vpaddd	%ymm8, %ymm11, %ymm6
	vpaddd	%ymm12, %ymm15, %ymm7
	vpslld	$7, %ymm4, %ymm5
	vpsrld	$25, %ymm4, %ymm4
	vpshufd	$0x39, %ymm1, %ymm1
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm4, %ymm1, %ymm1
	vpslld	$7, %ymm6, %ymm5
	vpsrld	$25, %ymm6, %ymm6
	vpshufd	$0x39, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpslld	$7, %ymm7, %ymm5
	vpsrld	$25, %ymm7, %ymm7
	vpshufd	$0x39, %ymm13, %ymm13
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm7, %ymm13, %ymm13
	
	vpaddd	%ymm1, %ymm0, %ymm4
	vpaddd	%ymm9, %ymm8, %ymm6
	vpaddd	%ymm13, %ymm12, %ymm7
	vpslld	$9, %ymm4, %ymm5
	vpsrld	$23, %ymm4, %ymm4
	vpxor	%ymm5, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpslld	$9, %ymm6, %ymm5
	vpsrld	$23, %ymm6, %ymm6
	vpxor	%ymm5, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm10
	vpslld	$9, %ymm7, %ymm5
	vpsrld	$23, %ymm7, %ymm7
	vpxor	%ymm5, %ymm14, %ymm14
	vpxor	%ymm7, %ymm14, %ymm14
	
	vpaddd	%ymm2, %ymm1, %ymm4
	vpaddd	%ymm10, %ymm9, %ymm6
	vpaddd	%ymm14, %ymm13, %ymm7
	vpslld	$13, %ymm4, %ymm5
	vpsrld	$19, %ymm4, %ymm4
	vpshufd	$0x93, %ymm1, %ymm1
	vpshufd	$0x93, %ymm9, %ymm9
	vpshufd	$0x93, %ymm13, %ymm13
	vpxor	%ymm5, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpslld	$13, %ymm6, %ymm5
	vpsrld	$19, %ymm6, %ymm6
	vpxor	%ymm5, %ymm11, %ymm11
	vpxor	%ymm6, %ymm11, %ymm11
	vpslld	$13, %ymm7, %ymm5
	vpsrld	$19, %ymm7, %ymm7
	vpxor	%ymm5, %ymm15, %ymm15
	vpxor	%ymm7, %ymm15, %ymm15
	
	vpaddd	%ymm3, %ymm2, %ymm4
	vpaddd	%ymm11, %ymm10, %ymm6
	vpaddd	%ymm15, %ymm14, %ymm7
	vpslld	$18, %ymm4, %ymm5
	vpsrld	$14, %ymm4, %ymm4
	vpshufd	$0x4e, %ymm2, %ymm2
	vpshufd	$0x4e, %ymm10, %ymm10
	vpxor	%ymm5, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpslld	$18, %ymm6, %ymm5
	vpsrld	$14, %ymm6, %ymm6
	vpshufd	$0x4e, %ymm14, %ymm14
	vpshufd	$0x39, %ymm11, %ymm11
	vpxor	%ymm5, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpslld	$18, %ymm7, %ymm5
	vpsrld	$14, %ymm7, %ymm7
	vpshufd	$0x39, %ymm3, %ymm3
	vpshufd	$0x39, %ymm15, %ymm15
	vpxor	%ymm5, %ymm12, %ymm12
	vpxor	%ymm7, %ymm12, %ymm12
	vpaddd	0*256+4*32(%rsp), %ymm0, %ymm0
	vpaddd	0*256+5*32(%rsp), %ymm1, %ymm1
	vpaddd	0*256+6*32(%rsp), %ymm2, %ymm2
	vpaddd	0*256+7*32(%rsp), %ymm3, %ymm3
	vpaddd	1*256+4*32(%rsp), %ymm8, %ymm8
	vpaddd	1*256+5*32(%rsp), %ymm9, %ymm9
	vpaddd	1*256+6*32(%rsp), %ymm10, %ymm10
	vpaddd	1*256+7*32(%rsp), %ymm11, %ymm11
	vpaddd	2*256+4*32(%rsp), %ymm12, %ymm12
	vpaddd	2*256+5*32(%rsp), %ymm13, %ymm13
	vpaddd	2*256+6*32(%rsp), %ymm14, %ymm14
	vpaddd	2*256+7*32(%rsp), %ymm15, %ymm15
	vmovdqa	%ymm0, 0*256+4*32(%rsp)
	vmovdqa	%ymm1, 0*256+5*32(%rsp)
	vmovdqa	%ymm2, 0*256+6*32(%rsp)
	vmovdqa	%ymm3, 0*256+7*32(%rsp)
	vmovdqa	%ymm8, 1*256+4*32(%rsp)
	vmovdqa	%ymm9, 1*256+5*32(%rsp)
	vmovdqa	%ymm10, 1*256+6*32(%rsp)
	vmovdqa	%ymm11, 1*256+7*32(%rsp)
	vmovdqa	%ymm12, 2*256+4*32(%rsp)
	vmovdqa	%ymm13, 2*256+5*32(%rsp)
	vmovdqa	%ymm14, 2*256+6*32(%rsp)
	vmovdqa	%ymm15, 2*256+7*32(%rsp)
	
	subq	$1, %rcx
	ja scrypt_core_6way_avx2_loop2
	
	vmovdqa	0*128+0*32(%rsp), %ymm0
	vmovdqa	0*128+1*32(%rsp), %ymm1
	vmovdqa	0*128+2*32(%rsp), %ymm2
	vmovdqa	0*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 0*256+0+0*16(%rdi)
	vmovdqa	%xmm1, 0*256+0+1*16(%rdi)
	vmovdqa	%xmm2, 0*256+0+2*16(%rdi)
	vmovdqa	%xmm3, 0*256+0+3*16(%rdi)
	vextracti128	$1, %ymm0, 0*256+0+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 0*256+0+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 0*256+0+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 0*256+0+128+3*16(%rdi)
	vmovdqa	1*128+0*32(%rsp), %ymm0
	vmovdqa	1*128+1*32(%rsp), %ymm1
	vmovdqa	1*128+2*32(%rsp), %ymm2
	vmovdqa	1*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 0*256+64+0*16(%rdi)
	vmovdqa	%xmm1, 0*256+64+1*16(%rdi)
	vmovdqa	%xmm2, 0*256+64+2*16(%rdi)
	vmovdqa	%xmm3, 0*256+64+3*16(%rdi)
	vextracti128	$1, %ymm0, 0*256+64+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 0*256+64+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 0*256+64+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 0*256+64+128+3*16(%rdi)
	vmovdqa	2*128+0*32(%rsp), %ymm0
	vmovdqa	2*128+1*32(%rsp), %ymm1
	vmovdqa	2*128+2*32(%rsp), %ymm2
	vmovdqa	2*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 1*256+0+0*16(%rdi)
	vmovdqa	%xmm1, 1*256+0+1*16(%rdi)
	vmovdqa	%xmm2, 1*256+0+2*16(%rdi)
	vmovdqa	%xmm3, 1*256+0+3*16(%rdi)
	vextracti128	$1, %ymm0, 1*256+0+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 1*256+0+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 1*256+0+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 1*256+0+128+3*16(%rdi)
	vmovdqa	3*128+0*32(%rsp), %ymm0
	vmovdqa	3*128+1*32(%rsp), %ymm1
	vmovdqa	3*128+2*32(%rsp), %ymm2
	vmovdqa	3*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 1*256+64+0*16(%rdi)
	vmovdqa	%xmm1, 1*256+64+1*16(%rdi)
	vmovdqa	%xmm2, 1*256+64+2*16(%rdi)
	vmovdqa	%xmm3, 1*256+64+3*16(%rdi)
	vextracti128	$1, %ymm0, 1*256+64+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 1*256+64+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 1*256+64+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 1*256+64+128+3*16(%rdi)
	vmovdqa	4*128+0*32(%rsp), %ymm0
	vmovdqa	4*128+1*32(%rsp), %ymm1
	vmovdqa	4*128+2*32(%rsp), %ymm2
	vmovdqa	4*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 2*256+0+0*16(%rdi)
	vmovdqa	%xmm1, 2*256+0+1*16(%rdi)
	vmovdqa	%xmm2, 2*256+0+2*16(%rdi)
	vmovdqa	%xmm3, 2*256+0+3*16(%rdi)
	vextracti128	$1, %ymm0, 2*256+0+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 2*256+0+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 2*256+0+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 2*256+0+128+3*16(%rdi)
	vmovdqa	5*128+0*32(%rsp), %ymm0
	vmovdqa	5*128+1*32(%rsp), %ymm1
	vmovdqa	5*128+2*32(%rsp), %ymm2
	vmovdqa	5*128+3*32(%rsp), %ymm3
	vpblendd	$0x33, %ymm0, %ymm2, %ymm4
	vpblendd	$0xcc, %ymm1, %ymm3, %ymm5
	vpblendd	$0x33, %ymm2, %ymm0, %ymm6
	vpblendd	$0xcc, %ymm3, %ymm1, %ymm7
	vpblendd	$0x55, %ymm7, %ymm6, %ymm3
	vpblendd	$0x55, %ymm6, %ymm5, %ymm2
	vpblendd	$0x55, %ymm5, %ymm4, %ymm1
	vpblendd	$0x55, %ymm4, %ymm7, %ymm0
	vmovdqa	%xmm0, 2*256+64+0*16(%rdi)
	vmovdqa	%xmm1, 2*256+64+1*16(%rdi)
	vmovdqa	%xmm2, 2*256+64+2*16(%rdi)
	vmovdqa	%xmm3, 2*256+64+3*16(%rdi)
	vextracti128	$1, %ymm0, 2*256+64+128+0*16(%rdi)
	vextracti128	$1, %ymm1, 2*256+64+128+1*16(%rdi)
	vextracti128	$1, %ymm2, 2*256+64+128+2*16(%rdi)
	vextracti128	$1, %ymm3, 2*256+64+128+3*16(%rdi)
	
	movq	%rdx, %rsp
#if defined(_WIN64) || defined(__CYGWIN__)
	popq	%rsi
	popq	%rdi
	vmovdqa	8(%rsp), %xmm6
	vmovdqa	24(%rsp), %xmm7
	vmovdqa	40(%rsp), %xmm8
	vmovdqa	56(%rsp), %xmm9
	vmovdqa	72(%rsp), %xmm10
	vmovdqa	88(%rsp), %xmm11
	vmovdqa	104(%rsp), %xmm12
	vmovdqa	120(%rsp), %xmm13
	vmovdqa	136(%rsp), %xmm14
	vmovdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%rbp
	popq	%rbx
	ret

#endif /* USE_AVX2 */

#endif
