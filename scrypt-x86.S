/*
 * Copyright 2011-2012, 2014 pooler@litecoinpool.org
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

#if defined(USE_ASM) && defined(__i386__)
	


	.text
	.p2align 5
salsa8_core_gen:
	movl	52(%esp), %ecx
	movl	4(%esp), %edx
	movl	20(%esp), %ebx
	movl	8(%esp), %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 4(%esp)
	movl	36(%esp), %edi
	leal	(%edx, %ebx), %ebp
	roll	$9, %ebp
	xorl	%ebp, %edi
	movl	24(%esp), %ebp
	movl	%edi, 8(%esp)
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	40(%esp), %ebx
	movl	%ecx, 20(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 24(%esp)
	movl	56(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 36(%esp)
	movl	28(%esp), %ecx
	movl	%edx, 28(%esp)
	movl	44(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	60(%esp), %ebx
	movl	%esi, 40(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 44(%esp)
	movl	12(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 12(%esp)
	movl	48(%esp), %esi
	movl	%ebp, 48(%esp)
	movl	64(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	32(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 32(%esp)
	movl	%ebx, %ecx
	movl	%edx, 52(%esp)
	movl	28(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	40(%esp), %ebx
	movl	%esi, 28(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 40(%esp)
	movl	12(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 12(%esp)
	movl	4(%esp), %esi
	movl	%ebp, 4(%esp)
	movl	48(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 48(%esp)
	movl	32(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 32(%esp)
	movl	24(%esp), %ecx
	movl	%edx, 24(%esp)
	movl	52(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	28(%esp), %ebx
	movl	%esi, 28(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 52(%esp)
	movl	8(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 8(%esp)
	movl	44(%esp), %esi
	movl	%ebp, 44(%esp)
	movl	4(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	20(%esp), %ebx
	movl	%ecx, 4(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	36(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 20(%esp)
	movl	%ebx, %ecx
	movl	%edx, 36(%esp)
	movl	24(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	28(%esp), %ebx
	movl	%esi, 24(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 28(%esp)
	xorl	%esi, %ebp
	movl	8(%esp), %esi
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	40(%esp), %edi
	movl	%ebp, 8(%esp)
	movl	44(%esp), %ebp
	movl	%esi, 40(%esp)
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	4(%esp), %ebx
	movl	%ecx, 44(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 4(%esp)
	movl	20(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 56(%esp)
	movl	48(%esp), %ecx
	movl	%edx, 20(%esp)
	movl	36(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	24(%esp), %ebx
	movl	%edi, 24(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 60(%esp)
	movl	12(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 12(%esp)
	movl	52(%esp), %edi
	movl	%ebp, 36(%esp)
	movl	8(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	32(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 32(%esp)
	movl	%ebx, %ecx
	movl	%edx, 48(%esp)
	movl	20(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	24(%esp), %ebx
	movl	%edi, 20(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 8(%esp)
	movl	12(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 12(%esp)
	movl	28(%esp), %edi
	movl	%ebp, 52(%esp)
	movl	36(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 28(%esp)
	movl	32(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 32(%esp)
	movl	4(%esp), %ecx
	movl	%edx, 4(%esp)
	movl	48(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	20(%esp), %ebx
	movl	%edi, 20(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 48(%esp)
	movl	40(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 36(%esp)
	movl	60(%esp), %edi
	movl	%ebp, 24(%esp)
	movl	52(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	44(%esp), %ebx
	movl	%ecx, 40(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 52(%esp)
	movl	56(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 56(%esp)
	addl	%esi, %ebx
	movl	%edx, 44(%esp)
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	%edi, 60(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	xorl	%edi, %ebp
	movl	%ebp, 64(%esp)
	movl	52(%esp), %ecx
	movl	4(%esp), %edx
	movl	20(%esp), %ebx
	movl	8(%esp), %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 4(%esp)
	movl	36(%esp), %edi
	leal	(%edx, %ebx), %ebp
	roll	$9, %ebp
	xorl	%ebp, %edi
	movl	24(%esp), %ebp
	movl	%edi, 8(%esp)
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	40(%esp), %ebx
	movl	%ecx, 20(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 24(%esp)
	movl	56(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 36(%esp)
	movl	28(%esp), %ecx
	movl	%edx, 28(%esp)
	movl	44(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	60(%esp), %ebx
	movl	%esi, 40(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 44(%esp)
	movl	12(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 12(%esp)
	movl	48(%esp), %esi
	movl	%ebp, 48(%esp)
	movl	64(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	32(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 32(%esp)
	movl	%ebx, %ecx
	movl	%edx, 52(%esp)
	movl	28(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	40(%esp), %ebx
	movl	%esi, 28(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 40(%esp)
	movl	12(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 12(%esp)
	movl	4(%esp), %esi
	movl	%ebp, 4(%esp)
	movl	48(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 48(%esp)
	movl	32(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 32(%esp)
	movl	24(%esp), %ecx
	movl	%edx, 24(%esp)
	movl	52(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	28(%esp), %ebx
	movl	%esi, 28(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 52(%esp)
	movl	8(%esp), %edi
	xorl	%esi, %ebp
	leal	(%edx, %ebx), %esi
	roll	$9, %esi
	xorl	%esi, %edi
	movl	%edi, 8(%esp)
	movl	44(%esp), %esi
	movl	%ebp, 44(%esp)
	movl	4(%esp), %ebp
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	20(%esp), %ebx
	movl	%ecx, 4(%esp)
	addl	%edi, %ecx
	roll	$18, %ecx
	leal	(%esi, %ebp), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	36(%esp), %edi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %edi
	movl	%edi, 20(%esp)
	movl	%ebx, %ecx
	movl	%edx, 36(%esp)
	movl	24(%esp), %edx
	addl	%edi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %esi
	movl	28(%esp), %ebx
	movl	%esi, 24(%esp)
	addl	%edi, %esi
	roll	$18, %esi
	leal	(%ecx, %edx), %edi
	roll	$7, %edi
	xorl	%edi, %ebx
	movl	%ebx, 28(%esp)
	xorl	%esi, %ebp
	movl	8(%esp), %esi
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	40(%esp), %edi
	movl	%ebp, 8(%esp)
	movl	44(%esp), %ebp
	movl	%esi, 40(%esp)
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	4(%esp), %ebx
	movl	%ecx, 44(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 4(%esp)
	movl	20(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 56(%esp)
	movl	48(%esp), %ecx
	movl	%edx, 20(%esp)
	movl	36(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	24(%esp), %ebx
	movl	%edi, 24(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 60(%esp)
	movl	12(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 12(%esp)
	movl	52(%esp), %edi
	movl	%ebp, 36(%esp)
	movl	8(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	32(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 32(%esp)
	movl	%ebx, %ecx
	movl	%edx, 48(%esp)
	movl	20(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	24(%esp), %ebx
	movl	%edi, 20(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 8(%esp)
	movl	12(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 12(%esp)
	movl	28(%esp), %edi
	movl	%ebp, 52(%esp)
	movl	36(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	16(%esp), %ebx
	movl	%ecx, 16(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 28(%esp)
	movl	32(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 32(%esp)
	movl	4(%esp), %ecx
	movl	%edx, 4(%esp)
	movl	48(%esp), %edx
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	20(%esp), %ebx
	movl	%edi, 20(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	leal	(%ecx, %edx), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 48(%esp)
	movl	40(%esp), %esi
	xorl	%edi, %ebp
	leal	(%edx, %ebx), %edi
	roll	$9, %edi
	xorl	%edi, %esi
	movl	%esi, 36(%esp)
	movl	60(%esp), %edi
	movl	%ebp, 24(%esp)
	movl	52(%esp), %ebp
	addl	%esi, %ebx
	roll	$13, %ebx
	xorl	%ebx, %ecx
	movl	44(%esp), %ebx
	movl	%ecx, 40(%esp)
	addl	%esi, %ecx
	roll	$18, %ecx
	leal	(%edi, %ebp), %esi
	roll	$7, %esi
	xorl	%esi, %ebx
	movl	%ebx, 52(%esp)
	movl	56(%esp), %esi
	xorl	%ecx, %edx
	leal	(%ebp, %ebx), %ecx
	roll	$9, %ecx
	xorl	%ecx, %esi
	movl	%esi, 56(%esp)
	addl	%esi, %ebx
	movl	%edx, 44(%esp)
	roll	$13, %ebx
	xorl	%ebx, %edi
	movl	%edi, 60(%esp)
	addl	%esi, %edi
	roll	$18, %edi
	xorl	%edi, %ebp
	movl	%ebp, 64(%esp)
	ret
	
	
	.text
	.p2align 5
	.globl scrypt_core
	.globl _scrypt_core
scrypt_core:
_scrypt_core:
	pushl	%ebx
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	
	/* Check for SSE2 availability */
	movl	$1, %eax
	cpuid
	andl	$0x04000000, %edx
	jnz scrypt_core_sse2
	
scrypt_core_gen:
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	movl	28(%esp), %ecx
	subl	$72, %esp
	
	
	
	
	
	shll	$7, %ecx
	addl	%esi, %ecx
scrypt_core_gen_loop1:
	movl	%esi, 64(%esp)
	movl	%ecx, 68(%esp)
	
	movl	0(%edi), %eax
	movl	64(%edi), %edx
	movl	%eax, 0(%esi)
	movl	%edx, 64(%esi)
	xorl	%edx, %eax
	movl	%eax, 0(%edi)
	movl	%eax, 0(%esp)
	movl	4(%edi), %eax
	movl	68(%edi), %edx
	movl	%eax, 4(%esi)
	movl	%edx, 68(%esi)
	xorl	%edx, %eax
	movl	%eax, 4(%edi)
	movl	%eax, 4(%esp)
	movl	8(%edi), %eax
	movl	72(%edi), %edx
	movl	%eax, 8(%esi)
	movl	%edx, 72(%esi)
	xorl	%edx, %eax
	movl	%eax, 8(%edi)
	movl	%eax, 8(%esp)
	movl	12(%edi), %eax
	movl	76(%edi), %edx
	movl	%eax, 12(%esi)
	movl	%edx, 76(%esi)
	xorl	%edx, %eax
	movl	%eax, 12(%edi)
	movl	%eax, 12(%esp)
	movl	16(%edi), %eax
	movl	80(%edi), %edx
	movl	%eax, 16(%esi)
	movl	%edx, 80(%esi)
	xorl	%edx, %eax
	movl	%eax, 16(%edi)
	movl	%eax, 16(%esp)
	movl	20(%edi), %eax
	movl	84(%edi), %edx
	movl	%eax, 20(%esi)
	movl	%edx, 84(%esi)
	xorl	%edx, %eax
	movl	%eax, 20(%edi)
	movl	%eax, 20(%esp)
	movl	24(%edi), %eax
	movl	88(%edi), %edx
	movl	%eax, 24(%esi)
	movl	%edx, 88(%esi)
	xorl	%edx, %eax
	movl	%eax, 24(%edi)
	movl	%eax, 24(%esp)
	movl	28(%edi), %eax
	movl	92(%edi), %edx
	movl	%eax, 28(%esi)
	movl	%edx, 92(%esi)
	xorl	%edx, %eax
	movl	%eax, 28(%edi)
	movl	%eax, 28(%esp)
	movl	32(%edi), %eax
	movl	96(%edi), %edx
	movl	%eax, 32(%esi)
	movl	%edx, 96(%esi)
	xorl	%edx, %eax
	movl	%eax, 32(%edi)
	movl	%eax, 32(%esp)
	movl	36(%edi), %eax
	movl	100(%edi), %edx
	movl	%eax, 36(%esi)
	movl	%edx, 100(%esi)
	xorl	%edx, %eax
	movl	%eax, 36(%edi)
	movl	%eax, 36(%esp)
	movl	40(%edi), %eax
	movl	104(%edi), %edx
	movl	%eax, 40(%esi)
	movl	%edx, 104(%esi)
	xorl	%edx, %eax
	movl	%eax, 40(%edi)
	movl	%eax, 40(%esp)
	movl	44(%edi), %eax
	movl	108(%edi), %edx
	movl	%eax, 44(%esi)
	movl	%edx, 108(%esi)
	xorl	%edx, %eax
	movl	%eax, 44(%edi)
	movl	%eax, 44(%esp)
	movl	48(%edi), %eax
	movl	112(%edi), %edx
	movl	%eax, 48(%esi)
	movl	%edx, 112(%esi)
	xorl	%edx, %eax
	movl	%eax, 48(%edi)
	movl	%eax, 48(%esp)
	movl	52(%edi), %eax
	movl	116(%edi), %edx
	movl	%eax, 52(%esi)
	movl	%edx, 116(%esi)
	xorl	%edx, %eax
	movl	%eax, 52(%edi)
	movl	%eax, 52(%esp)
	movl	56(%edi), %eax
	movl	120(%edi), %edx
	movl	%eax, 56(%esi)
	movl	%edx, 120(%esi)
	xorl	%edx, %eax
	movl	%eax, 56(%edi)
	movl	%eax, 56(%esp)
	movl	60(%edi), %eax
	movl	124(%edi), %edx
	movl	%eax, 60(%esi)
	movl	%edx, 124(%esi)
	xorl	%edx, %eax
	movl	%eax, 60(%edi)
	movl	%eax, 60(%esp)
	
	call salsa8_core_gen
	
	movl	92(%esp), %edi
	movl	0(%esp), %eax
	addl	0(%edi), %eax
	movl	%eax, 0(%edi)
	xorl	64(%edi), %eax
	movl	%eax, 64(%edi)
	movl	%eax, 0(%esp)
	movl	4(%esp), %eax
	addl	4(%edi), %eax
	movl	%eax, 4(%edi)
	xorl	68(%edi), %eax
	movl	%eax, 68(%edi)
	movl	%eax, 4(%esp)
	movl	8(%esp), %eax
	addl	8(%edi), %eax
	movl	%eax, 8(%edi)
	xorl	72(%edi), %eax
	movl	%eax, 72(%edi)
	movl	%eax, 8(%esp)
	movl	12(%esp), %eax
	addl	12(%edi), %eax
	movl	%eax, 12(%edi)
	xorl	76(%edi), %eax
	movl	%eax, 76(%edi)
	movl	%eax, 12(%esp)
	movl	16(%esp), %eax
	addl	16(%edi), %eax
	movl	%eax, 16(%edi)
	xorl	80(%edi), %eax
	movl	%eax, 80(%edi)
	movl	%eax, 16(%esp)
	movl	20(%esp), %eax
	addl	20(%edi), %eax
	movl	%eax, 20(%edi)
	xorl	84(%edi), %eax
	movl	%eax, 84(%edi)
	movl	%eax, 20(%esp)
	movl	24(%esp), %eax
	addl	24(%edi), %eax
	movl	%eax, 24(%edi)
	xorl	88(%edi), %eax
	movl	%eax, 88(%edi)
	movl	%eax, 24(%esp)
	movl	28(%esp), %eax
	addl	28(%edi), %eax
	movl	%eax, 28(%edi)
	xorl	92(%edi), %eax
	movl	%eax, 92(%edi)
	movl	%eax, 28(%esp)
	movl	32(%esp), %eax
	addl	32(%edi), %eax
	movl	%eax, 32(%edi)
	xorl	96(%edi), %eax
	movl	%eax, 96(%edi)
	movl	%eax, 32(%esp)
	movl	36(%esp), %eax
	addl	36(%edi), %eax
	movl	%eax, 36(%edi)
	xorl	100(%edi), %eax
	movl	%eax, 100(%edi)
	movl	%eax, 36(%esp)
	movl	40(%esp), %eax
	addl	40(%edi), %eax
	movl	%eax, 40(%edi)
	xorl	104(%edi), %eax
	movl	%eax, 104(%edi)
	movl	%eax, 40(%esp)
	movl	44(%esp), %eax
	addl	44(%edi), %eax
	movl	%eax, 44(%edi)
	xorl	108(%edi), %eax
	movl	%eax, 108(%edi)
	movl	%eax, 44(%esp)
	movl	48(%esp), %eax
	addl	48(%edi), %eax
	movl	%eax, 48(%edi)
	xorl	112(%edi), %eax
	movl	%eax, 112(%edi)
	movl	%eax, 48(%esp)
	movl	52(%esp), %eax
	addl	52(%edi), %eax
	movl	%eax, 52(%edi)
	xorl	116(%edi), %eax
	movl	%eax, 116(%edi)
	movl	%eax, 52(%esp)
	movl	56(%esp), %eax
	addl	56(%edi), %eax
	movl	%eax, 56(%edi)
	xorl	120(%edi), %eax
	movl	%eax, 120(%edi)
	movl	%eax, 56(%esp)
	movl	60(%esp), %eax
	addl	60(%edi), %eax
	movl	%eax, 60(%edi)
	xorl	124(%edi), %eax
	movl	%eax, 124(%edi)
	movl	%eax, 60(%esp)
	
	call salsa8_core_gen
	
	movl	92(%esp), %edi
	movl	0(%esp), %eax
	addl	64(%edi), %eax
	movl	%eax, 64(%edi)
	movl	4(%esp), %eax
	addl	68(%edi), %eax
	movl	%eax, 68(%edi)
	movl	8(%esp), %eax
	addl	72(%edi), %eax
	movl	%eax, 72(%edi)
	movl	12(%esp), %eax
	addl	76(%edi), %eax
	movl	%eax, 76(%edi)
	movl	16(%esp), %eax
	addl	80(%edi), %eax
	movl	%eax, 80(%edi)
	movl	20(%esp), %eax
	addl	84(%edi), %eax
	movl	%eax, 84(%edi)
	movl	24(%esp), %eax
	addl	88(%edi), %eax
	movl	%eax, 88(%edi)
	movl	28(%esp), %eax
	addl	92(%edi), %eax
	movl	%eax, 92(%edi)
	movl	32(%esp), %eax
	addl	96(%edi), %eax
	movl	%eax, 96(%edi)
	movl	36(%esp), %eax
	addl	100(%edi), %eax
	movl	%eax, 100(%edi)
	movl	40(%esp), %eax
	addl	104(%edi), %eax
	movl	%eax, 104(%edi)
	movl	44(%esp), %eax
	addl	108(%edi), %eax
	movl	%eax, 108(%edi)
	movl	48(%esp), %eax
	addl	112(%edi), %eax
	movl	%eax, 112(%edi)
	movl	52(%esp), %eax
	addl	116(%edi), %eax
	movl	%eax, 116(%edi)
	movl	56(%esp), %eax
	addl	120(%edi), %eax
	movl	%eax, 120(%edi)
	movl	60(%esp), %eax
	addl	124(%edi), %eax
	movl	%eax, 124(%edi)
	
	movl	64(%esp), %esi
	movl	68(%esp), %ecx
	addl	$128, %esi
	cmpl	%ecx, %esi
	jne scrypt_core_gen_loop1

	movl	96(%esp), %esi
	movl	100(%esp), %ecx
	movl	%ecx, %eax
	subl	$1, %eax
	movl	%eax, 100(%esp)
scrypt_core_gen_loop2:
	movl	%ecx, 68(%esp)
	
	movl	64(%edi), %edx
	andl	100(%esp), %edx
	shll	$7, %edx
	
	movl	0(%edi), %eax
	xorl	0(%esi, %edx), %eax
	movl	64(%edi), %ebx
	xorl	64(%esi, %edx), %ebx
	movl	%ebx, 64(%edi)
	xorl	%ebx, %eax
	movl	%eax, 0(%edi)
	movl	%eax, 0(%esp)
	movl	4(%edi), %eax
	xorl	4(%esi, %edx), %eax
	movl	68(%edi), %ebx
	xorl	68(%esi, %edx), %ebx
	movl	%ebx, 68(%edi)
	xorl	%ebx, %eax
	movl	%eax, 4(%edi)
	movl	%eax, 4(%esp)
	movl	8(%edi), %eax
	xorl	8(%esi, %edx), %eax
	movl	72(%edi), %ebx
	xorl	72(%esi, %edx), %ebx
	movl	%ebx, 72(%edi)
	xorl	%ebx, %eax
	movl	%eax, 8(%edi)
	movl	%eax, 8(%esp)
	movl	12(%edi), %eax
	xorl	12(%esi, %edx), %eax
	movl	76(%edi), %ebx
	xorl	76(%esi, %edx), %ebx
	movl	%ebx, 76(%edi)
	xorl	%ebx, %eax
	movl	%eax, 12(%edi)
	movl	%eax, 12(%esp)
	movl	16(%edi), %eax
	xorl	16(%esi, %edx), %eax
	movl	80(%edi), %ebx
	xorl	80(%esi, %edx), %ebx
	movl	%ebx, 80(%edi)
	xorl	%ebx, %eax
	movl	%eax, 16(%edi)
	movl	%eax, 16(%esp)
	movl	20(%edi), %eax
	xorl	20(%esi, %edx), %eax
	movl	84(%edi), %ebx
	xorl	84(%esi, %edx), %ebx
	movl	%ebx, 84(%edi)
	xorl	%ebx, %eax
	movl	%eax, 20(%edi)
	movl	%eax, 20(%esp)
	movl	24(%edi), %eax
	xorl	24(%esi, %edx), %eax
	movl	88(%edi), %ebx
	xorl	88(%esi, %edx), %ebx
	movl	%ebx, 88(%edi)
	xorl	%ebx, %eax
	movl	%eax, 24(%edi)
	movl	%eax, 24(%esp)
	movl	28(%edi), %eax
	xorl	28(%esi, %edx), %eax
	movl	92(%edi), %ebx
	xorl	92(%esi, %edx), %ebx
	movl	%ebx, 92(%edi)
	xorl	%ebx, %eax
	movl	%eax, 28(%edi)
	movl	%eax, 28(%esp)
	movl	32(%edi), %eax
	xorl	32(%esi, %edx), %eax
	movl	96(%edi), %ebx
	xorl	96(%esi, %edx), %ebx
	movl	%ebx, 96(%edi)
	xorl	%ebx, %eax
	movl	%eax, 32(%edi)
	movl	%eax, 32(%esp)
	movl	36(%edi), %eax
	xorl	36(%esi, %edx), %eax
	movl	100(%edi), %ebx
	xorl	100(%esi, %edx), %ebx
	movl	%ebx, 100(%edi)
	xorl	%ebx, %eax
	movl	%eax, 36(%edi)
	movl	%eax, 36(%esp)
	movl	40(%edi), %eax
	xorl	40(%esi, %edx), %eax
	movl	104(%edi), %ebx
	xorl	104(%esi, %edx), %ebx
	movl	%ebx, 104(%edi)
	xorl	%ebx, %eax
	movl	%eax, 40(%edi)
	movl	%eax, 40(%esp)
	movl	44(%edi), %eax
	xorl	44(%esi, %edx), %eax
	movl	108(%edi), %ebx
	xorl	108(%esi, %edx), %ebx
	movl	%ebx, 108(%edi)
	xorl	%ebx, %eax
	movl	%eax, 44(%edi)
	movl	%eax, 44(%esp)
	movl	48(%edi), %eax
	xorl	48(%esi, %edx), %eax
	movl	112(%edi), %ebx
	xorl	112(%esi, %edx), %ebx
	movl	%ebx, 112(%edi)
	xorl	%ebx, %eax
	movl	%eax, 48(%edi)
	movl	%eax, 48(%esp)
	movl	52(%edi), %eax
	xorl	52(%esi, %edx), %eax
	movl	116(%edi), %ebx
	xorl	116(%esi, %edx), %ebx
	movl	%ebx, 116(%edi)
	xorl	%ebx, %eax
	movl	%eax, 52(%edi)
	movl	%eax, 52(%esp)
	movl	56(%edi), %eax
	xorl	56(%esi, %edx), %eax
	movl	120(%edi), %ebx
	xorl	120(%esi, %edx), %ebx
	movl	%ebx, 120(%edi)
	xorl	%ebx, %eax
	movl	%eax, 56(%edi)
	movl	%eax, 56(%esp)
	movl	60(%edi), %eax
	xorl	60(%esi, %edx), %eax
	movl	124(%edi), %ebx
	xorl	124(%esi, %edx), %ebx
	movl	%ebx, 124(%edi)
	xorl	%ebx, %eax
	movl	%eax, 60(%edi)
	movl	%eax, 60(%esp)
	
	call salsa8_core_gen
	
	movl	92(%esp), %edi
	movl	0(%esp), %eax
	addl	0(%edi), %eax
	movl	%eax, 0(%edi)
	xorl	64(%edi), %eax
	movl	%eax, 64(%edi)
	movl	%eax, 0(%esp)
	movl	4(%esp), %eax
	addl	4(%edi), %eax
	movl	%eax, 4(%edi)
	xorl	68(%edi), %eax
	movl	%eax, 68(%edi)
	movl	%eax, 4(%esp)
	movl	8(%esp), %eax
	addl	8(%edi), %eax
	movl	%eax, 8(%edi)
	xorl	72(%edi), %eax
	movl	%eax, 72(%edi)
	movl	%eax, 8(%esp)
	movl	12(%esp), %eax
	addl	12(%edi), %eax
	movl	%eax, 12(%edi)
	xorl	76(%edi), %eax
	movl	%eax, 76(%edi)
	movl	%eax, 12(%esp)
	movl	16(%esp), %eax
	addl	16(%edi), %eax
	movl	%eax, 16(%edi)
	xorl	80(%edi), %eax
	movl	%eax, 80(%edi)
	movl	%eax, 16(%esp)
	movl	20(%esp), %eax
	addl	20(%edi), %eax
	movl	%eax, 20(%edi)
	xorl	84(%edi), %eax
	movl	%eax, 84(%edi)
	movl	%eax, 20(%esp)
	movl	24(%esp), %eax
	addl	24(%edi), %eax
	movl	%eax, 24(%edi)
	xorl	88(%edi), %eax
	movl	%eax, 88(%edi)
	movl	%eax, 24(%esp)
	movl	28(%esp), %eax
	addl	28(%edi), %eax
	movl	%eax, 28(%edi)
	xorl	92(%edi), %eax
	movl	%eax, 92(%edi)
	movl	%eax, 28(%esp)
	movl	32(%esp), %eax
	addl	32(%edi), %eax
	movl	%eax, 32(%edi)
	xorl	96(%edi), %eax
	movl	%eax, 96(%edi)
	movl	%eax, 32(%esp)
	movl	36(%esp), %eax
	addl	36(%edi), %eax
	movl	%eax, 36(%edi)
	xorl	100(%edi), %eax
	movl	%eax, 100(%edi)
	movl	%eax, 36(%esp)
	movl	40(%esp), %eax
	addl	40(%edi), %eax
	movl	%eax, 40(%edi)
	xorl	104(%edi), %eax
	movl	%eax, 104(%edi)
	movl	%eax, 40(%esp)
	movl	44(%esp), %eax
	addl	44(%edi), %eax
	movl	%eax, 44(%edi)
	xorl	108(%edi), %eax
	movl	%eax, 108(%edi)
	movl	%eax, 44(%esp)
	movl	48(%esp), %eax
	addl	48(%edi), %eax
	movl	%eax, 48(%edi)
	xorl	112(%edi), %eax
	movl	%eax, 112(%edi)
	movl	%eax, 48(%esp)
	movl	52(%esp), %eax
	addl	52(%edi), %eax
	movl	%eax, 52(%edi)
	xorl	116(%edi), %eax
	movl	%eax, 116(%edi)
	movl	%eax, 52(%esp)
	movl	56(%esp), %eax
	addl	56(%edi), %eax
	movl	%eax, 56(%edi)
	xorl	120(%edi), %eax
	movl	%eax, 120(%edi)
	movl	%eax, 56(%esp)
	movl	60(%esp), %eax
	addl	60(%edi), %eax
	movl	%eax, 60(%edi)
	xorl	124(%edi), %eax
	movl	%eax, 124(%edi)
	movl	%eax, 60(%esp)
	
	call salsa8_core_gen
	
	movl	92(%esp), %edi
	movl	96(%esp), %esi
	movl	0(%esp), %eax
	addl	64(%edi), %eax
	movl	%eax, 64(%edi)
	movl	4(%esp), %eax
	addl	68(%edi), %eax
	movl	%eax, 68(%edi)
	movl	8(%esp), %eax
	addl	72(%edi), %eax
	movl	%eax, 72(%edi)
	movl	12(%esp), %eax
	addl	76(%edi), %eax
	movl	%eax, 76(%edi)
	movl	16(%esp), %eax
	addl	80(%edi), %eax
	movl	%eax, 80(%edi)
	movl	20(%esp), %eax
	addl	84(%edi), %eax
	movl	%eax, 84(%edi)
	movl	24(%esp), %eax
	addl	88(%edi), %eax
	movl	%eax, 88(%edi)
	movl	28(%esp), %eax
	addl	92(%edi), %eax
	movl	%eax, 92(%edi)
	movl	32(%esp), %eax
	addl	96(%edi), %eax
	movl	%eax, 96(%edi)
	movl	36(%esp), %eax
	addl	100(%edi), %eax
	movl	%eax, 100(%edi)
	movl	40(%esp), %eax
	addl	104(%edi), %eax
	movl	%eax, 104(%edi)
	movl	44(%esp), %eax
	addl	108(%edi), %eax
	movl	%eax, 108(%edi)
	movl	48(%esp), %eax
	addl	112(%edi), %eax
	movl	%eax, 112(%edi)
	movl	52(%esp), %eax
	addl	116(%edi), %eax
	movl	%eax, 116(%edi)
	movl	56(%esp), %eax
	addl	120(%edi), %eax
	movl	%eax, 120(%edi)
	movl	60(%esp), %eax
	addl	124(%edi), %eax
	movl	%eax, 124(%edi)
	
	movl	68(%esp), %ecx
	subl	$1, %ecx
	ja scrypt_core_gen_loop2
	
	addl	$72, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret



	
	.p2align 5
scrypt_core_sse2:
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	movl	%esp, %ebp
	subl	$128, %esp
	andl	$-16, %esp
	
	movl	0+60(%edi), %eax
	movl	0+44(%edi), %ebx
	movl	0+28(%edi), %ecx
	movl	0+12(%edi), %edx
	movl	%eax, 0+12(%esp)
	movl	%ebx, 0+28(%esp)
	movl	%ecx, 0+44(%esp)
	movl	%edx, 0+60(%esp)
	movl	0+40(%edi), %eax
	movl	0+8(%edi), %ebx
	movl	0+48(%edi), %ecx
	movl	0+16(%edi), %edx
	movl	%eax, 0+8(%esp)
	movl	%ebx, 0+40(%esp)
	movl	%ecx, 0+16(%esp)
	movl	%edx, 0+48(%esp)
	movl	0+20(%edi), %eax
	movl	0+4(%edi), %ebx
	movl	0+52(%edi), %ecx
	movl	0+36(%edi), %edx
	movl	%eax, 0+4(%esp)
	movl	%ebx, 0+20(%esp)
	movl	%ecx, 0+36(%esp)
	movl	%edx, 0+52(%esp)
	movl	0+0(%edi), %eax
	movl	0+24(%edi), %ebx
	movl	0+32(%edi), %ecx
	movl	0+56(%edi), %edx
	movl	%eax, 0+0(%esp)
	movl	%ebx, 0+24(%esp)
	movl	%ecx, 0+32(%esp)
	movl	%edx, 0+56(%esp)
	movl	64+60(%edi), %eax
	movl	64+44(%edi), %ebx
	movl	64+28(%edi), %ecx
	movl	64+12(%edi), %edx
	movl	%eax, 64+12(%esp)
	movl	%ebx, 64+28(%esp)
	movl	%ecx, 64+44(%esp)
	movl	%edx, 64+60(%esp)
	movl	64+40(%edi), %eax
	movl	64+8(%edi), %ebx
	movl	64+48(%edi), %ecx
	movl	64+16(%edi), %edx
	movl	%eax, 64+8(%esp)
	movl	%ebx, 64+40(%esp)
	movl	%ecx, 64+16(%esp)
	movl	%edx, 64+48(%esp)
	movl	64+20(%edi), %eax
	movl	64+4(%edi), %ebx
	movl	64+52(%edi), %ecx
	movl	64+36(%edi), %edx
	movl	%eax, 64+4(%esp)
	movl	%ebx, 64+20(%esp)
	movl	%ecx, 64+36(%esp)
	movl	%edx, 64+52(%esp)
	movl	64+0(%edi), %eax
	movl	64+24(%edi), %ebx
	movl	64+32(%edi), %ecx
	movl	64+56(%edi), %edx
	movl	%eax, 64+0(%esp)
	movl	%ebx, 64+24(%esp)
	movl	%ecx, 64+32(%esp)
	movl	%edx, 64+56(%esp)
	
	movdqa	96(%esp), %xmm6
	movdqa	112(%esp), %xmm7
	
	movl	%esi, %edx
	movl	28(%ebp), %ecx
	shll	$7, %ecx
	addl	%esi, %ecx
scrypt_core_sse2_loop1:
	movdqa	0(%esp), %xmm0
	movdqa	16(%esp), %xmm1
	movdqa	32(%esp), %xmm2
	movdqa	48(%esp), %xmm3
	movdqa	64(%esp), %xmm4
	movdqa	80(%esp), %xmm5
	pxor	%xmm4, %xmm0
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 64(%edx)
	movdqa	%xmm5, 80(%edx)
	movdqa	%xmm6, 96(%edx)
	movdqa	%xmm7, 112(%edx)
	
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
	paddd	0(%edx), %xmm0
	paddd	16(%edx), %xmm1
	paddd	32(%edx), %xmm2
	paddd	48(%edx), %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)
	
	pxor	64(%esp), %xmm0
	pxor	80(%esp), %xmm1
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, %xmm6
	movdqa	%xmm3, %xmm7
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
	paddd	64(%esp), %xmm0
	paddd	80(%esp), %xmm1
	paddd	%xmm2, %xmm6
	paddd	%xmm3, %xmm7
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	
	addl	$128, %edx
	cmpl	%ecx, %edx
	jne scrypt_core_sse2_loop1
	
	movdqa	64(%esp), %xmm4
	movdqa	80(%esp), %xmm5
	
	movl	28(%ebp), %ecx
	movl	%ecx, %eax
	subl	$1, %eax
scrypt_core_sse2_loop2:
	movd	%xmm4, %edx
	movdqa	0(%esp), %xmm0
	movdqa	16(%esp), %xmm1
	movdqa	32(%esp), %xmm2
	movdqa	48(%esp), %xmm3
	andl	%eax, %edx
	shll	$7, %edx
	pxor	0(%esi, %edx), %xmm0
	pxor	16(%esi, %edx), %xmm1
	pxor	32(%esi, %edx), %xmm2
	pxor	48(%esi, %edx), %xmm3
	
	pxor	%xmm4, %xmm0
	pxor	%xmm5, %xmm1
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)
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
	paddd	0(%esp), %xmm0
	paddd	16(%esp), %xmm1
	paddd	32(%esp), %xmm2
	paddd	48(%esp), %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)
	
	pxor	64(%esi, %edx), %xmm0
	pxor	80(%esi, %edx), %xmm1
	pxor	96(%esi, %edx), %xmm2
	pxor	112(%esi, %edx), %xmm3
	pxor	64(%esp), %xmm0
	pxor	80(%esp), %xmm1
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, %xmm6
	movdqa	%xmm3, %xmm7
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
	paddd	64(%esp), %xmm0
	paddd	80(%esp), %xmm1
	paddd	%xmm2, %xmm6
	paddd	%xmm3, %xmm7
	movdqa	%xmm0, %xmm4
	movdqa	%xmm1, %xmm5
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	
	subl	$1, %ecx
	ja scrypt_core_sse2_loop2
	
	movdqa	%xmm6, 96(%esp)
	movdqa	%xmm7, 112(%esp)
	
	movl	0+60(%esp), %eax
	movl	0+44(%esp), %ebx
	movl	0+28(%esp), %ecx
	movl	0+12(%esp), %edx
	movl	%eax, 0+12(%edi)
	movl	%ebx, 0+28(%edi)
	movl	%ecx, 0+44(%edi)
	movl	%edx, 0+60(%edi)
	movl	0+40(%esp), %eax
	movl	0+8(%esp), %ebx
	movl	0+48(%esp), %ecx
	movl	0+16(%esp), %edx
	movl	%eax, 0+8(%edi)
	movl	%ebx, 0+40(%edi)
	movl	%ecx, 0+16(%edi)
	movl	%edx, 0+48(%edi)
	movl	0+20(%esp), %eax
	movl	0+4(%esp), %ebx
	movl	0+52(%esp), %ecx
	movl	0+36(%esp), %edx
	movl	%eax, 0+4(%edi)
	movl	%ebx, 0+20(%edi)
	movl	%ecx, 0+36(%edi)
	movl	%edx, 0+52(%edi)
	movl	0+0(%esp), %eax
	movl	0+24(%esp), %ebx
	movl	0+32(%esp), %ecx
	movl	0+56(%esp), %edx
	movl	%eax, 0+0(%edi)
	movl	%ebx, 0+24(%edi)
	movl	%ecx, 0+32(%edi)
	movl	%edx, 0+56(%edi)
	movl	64+60(%esp), %eax
	movl	64+44(%esp), %ebx
	movl	64+28(%esp), %ecx
	movl	64+12(%esp), %edx
	movl	%eax, 64+12(%edi)
	movl	%ebx, 64+28(%edi)
	movl	%ecx, 64+44(%edi)
	movl	%edx, 64+60(%edi)
	movl	64+40(%esp), %eax
	movl	64+8(%esp), %ebx
	movl	64+48(%esp), %ecx
	movl	64+16(%esp), %edx
	movl	%eax, 64+8(%edi)
	movl	%ebx, 64+40(%edi)
	movl	%ecx, 64+16(%edi)
	movl	%edx, 64+48(%edi)
	movl	64+20(%esp), %eax
	movl	64+4(%esp), %ebx
	movl	64+52(%esp), %ecx
	movl	64+36(%esp), %edx
	movl	%eax, 64+4(%edi)
	movl	%ebx, 64+20(%edi)
	movl	%ecx, 64+36(%edi)
	movl	%edx, 64+52(%edi)
	movl	64+0(%esp), %eax
	movl	64+24(%esp), %ebx
	movl	64+32(%esp), %ecx
	movl	64+56(%esp), %edx
	movl	%eax, 64+0(%edi)
	movl	%ebx, 64+24(%edi)
	movl	%ecx, 64+32(%edi)
	movl	%edx, 64+56(%edi)
	
	movl	%ebp, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret

#endif
