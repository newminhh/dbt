#include "dbt_internal.h"

.text
.p2align 4

/*
 * void dbt_enter_block(newminhh_cpu_t *cpu, void *host_code)
 *   %edi = cpu
 *   %esi = host_code
 */
.globl dbt_enter_block
.type dbt_enter_block, @function
dbt_enter_block:
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $8, %rsp                /* 6 pushes (48B) + 8B + ret(8B) -> 16B aligned */

    movl    %edi, %r15d             /* R15 = &cpu (zero-extended) */
    movl    %esi, %r11d             /* R11 = host_code */

    fxrstor NM_CPU_OFF_FXSAVE(%r15)
    movl    NM_CPU_OFF_GS_BASE(%r15), %r14d

    movl    NM_CPU_OFF_EFLAGS(%r15), %r8d
    pushq   %r8
    popfq

    movl    NM_CPU_OFF_EAX(%r15), %eax
    movl    NM_CPU_OFF_ECX(%r15), %ecx
    movl    NM_CPU_OFF_EDX(%r15), %edx
    movl    NM_CPU_OFF_EBX(%r15), %ebx
    movl    NM_CPU_OFF_ESP(%r15), %r12d
    movl    NM_CPU_OFF_EBP(%r15), %ebp
    movl    NM_CPU_OFF_ESI(%r15), %esi
    movl    NM_CPU_OFF_EDI(%r15), %edi

    jmp     *%r11
.size dbt_enter_block, .-dbt_enter_block

/*
 * Translated code jumps here after writing cpu->eip, cpu->exit_reason, (cpu->exit_arg).
 */
.globl dbt_trampoline_exit
.type dbt_trampoline_exit, @function
dbt_trampoline_exit:
    movl    %eax, NM_CPU_OFF_EAX(%r15)
    movl    %ecx, NM_CPU_OFF_ECX(%r15)
    movl    %edx, NM_CPU_OFF_EDX(%r15)
    movl    %ebx, NM_CPU_OFF_EBX(%r15)
    movl    %r12d, NM_CPU_OFF_ESP(%r15)
    movl    %ebp, NM_CPU_OFF_EBP(%r15)
    movl    %esi, NM_CPU_OFF_ESI(%r15)
    movl    %edi, NM_CPU_OFF_EDI(%r15)

    pushfq
    popq    %r8
    movl    %r8d, NM_CPU_OFF_EFLAGS(%r15)

    fxsave  NM_CPU_OFF_FXSAVE(%r15)

    addq    $8, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
.size dbt_trampoline_exit, .-dbt_trampoline_exit

/*
 * void dbt_fxsave_push_f32(void *fxsave_area, float val)
 */
.globl dbt_fxsave_push_f32
.type dbt_fxsave_push_f32, @function
dbt_fxsave_push_f32:
    movl    %edi, %eax
    movss   %xmm0, -8(%rsp)
    fxrstor (%rax)
    flds    -8(%rsp)
    fxsave  (%rax)
    ret
.size dbt_fxsave_push_f32, .-dbt_fxsave_push_f32

/*
 * void dbt_fxsave_push_f64(void *fxsave_area, double val)
 */
.globl dbt_fxsave_push_f64
.type dbt_fxsave_push_f64, @function
dbt_fxsave_push_f64:
    movl    %edi, %eax
    movsd   %xmm0, -8(%rsp)
    fxrstor (%rax)
    fldl    -8(%rsp)
    fxsave  (%rax)
    ret
.size dbt_fxsave_push_f64, .-dbt_fxsave_push_f64

/*
 * double dbt_fxsave_pop_f64(void *fxsave_area)
 */
.globl dbt_fxsave_pop_f64
.type dbt_fxsave_pop_f64, @function
dbt_fxsave_pop_f64:
    movl    %edi, %eax
    fxrstor (%rax)
    fstpl   -8(%rsp)
    movsd   -8(%rsp), %xmm0
    fxsave  (%rax)
    ret
.size dbt_fxsave_pop_f64, .-dbt_fxsave_pop_f64

/*
 * float dbt_fxsave_pop_f32(void *fxsave_area)
 */
.globl dbt_fxsave_pop_f32
.type dbt_fxsave_pop_f32, @function
dbt_fxsave_pop_f32:
    movl    %edi, %eax
    fxrstor (%rax)
    fstps   -8(%rsp)
    movss   -8(%rsp), %xmm0
    fxsave  (%rax)
    ret
.size dbt_fxsave_pop_f32, .-dbt_fxsave_pop_f32

/*
 * uint64_t dbt_call_native_x32_6(void *fn, uint32_t a0, uint32_t a1, uint32_t a2,
 *                                uint32_t a3, uint32_t a4, uint32_t a5)
 * On x32 SysV ABI:
 *   %edi = fn, %esi = a0, %edx = a1, %ecx = a2, %r8d = a3, %r9d = a4, 8(%rsp) = a5
 */
.globl dbt_call_native_x32_6
.type dbt_call_native_x32_6, @function
dbt_call_native_x32_6:
    movl    %edi, %r11d             /* fn */
    movl    8(%rsp), %r10d          /* a5 from caller stack */
    movl    %esi, %edi              /* arg0 */
    movl    %edx, %esi              /* arg1 */
    movl    %ecx, %edx              /* arg2 */
    movl    %r8d, %ecx              /* arg3 */
    movl    %r9d, %r8d              /* arg4 */
    movl    %r10d, %r9d             /* arg5 */
    xorl    %eax, %eax              /* 0 XMM args */
    jmp     *%r11                   /* tail call preserves return addr & alignment */
.size dbt_call_native_x32_6, .-dbt_call_native_x32_6

/*
 * Signal-safe NX-guard callback common entry:
 * Entered via 16B trampoline slot:
 *   movl $slot_id, %r11d
 *   jmp  dbt_segv_cb_entry
 */
.globl dbt_segv_cb_entry
.type dbt_segv_cb_entry, @function
dbt_segv_cb_entry:
    leaq    8(%rsp), %r10           /* caller stack-spill pointer */
    pushq   %rbp
    movq    %rsp, %rbp              /* %rsp is now 16B aligned */
    subq    $128, %rsp

    /* Save x32 GPR arg regs: gprs[0..5] at [%rsp + 0..47] */
    movq    %rdi,  0(%rsp)
    movq    %rsi,  8(%rsp)
    movq    %rdx, 16(%rsp)
    movq    %rcx, 24(%rsp)
    movq    %r8,  32(%rsp)
    movq    %r9,  40(%rsp)

    /* Save x32 XMM arg regs: xmms[0..7] at [%rsp + 48..111] */
    movsd   %xmm0,  48(%rsp)
    movsd   %xmm1,  56(%rsp)
    movsd   %xmm2,  64(%rsp)
    movsd   %xmm3,  72(%rsp)
    movsd   %xmm4,  80(%rsp)
    movsd   %xmm5,  88(%rsp)
    movsd   %xmm6,  96(%rsp)
    movsd   %xmm7, 104(%rsp)

    movq    $0, 112(%rsp)           /* double out_fp = 0.0 */

    movl    %r11d, %edi             /* slot_id */
    movq    %rsp, %rsi              /* gprs */
    leaq    48(%rsp), %rdx          /* xmms */
    movq    %r10, %rcx              /* caller_stack */
    leaq    112(%rsp), %r8          /* &out_fp */
    call    dbt_segv_cb_dispatch

    leave
    ret
.size dbt_segv_cb_entry, .-dbt_segv_cb_entry

.section .note.GNU-stack,"",@progbits
