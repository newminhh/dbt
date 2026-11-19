#define _GNU_SOURCE
#include "dbt_internal.h"

#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DBT_MAX_BLOCK_INSNS 128
#define DBT_EMIT_BUF_CAP    16384
#define DBT_MAX_FIXUPS      256

typedef enum {
    FIXUP_ABS_EXIT = 1,      /* rel32 at code_off -> dbt_trampoline_exit */
    FIXUP_REL_LOCAL,         /* rel32 at code_off -> label_off inside block */
    FIXUP_EDGE_STUB_RETADDR, /* imm32 at code_off -> final_base + patch_site_off */
    FIXUP_JIT_ADDR32         /* imm32 at code_off -> (uint32_t)target_abs */
} fixup_kind_t;

typedef struct {
    fixup_kind_t kind;
    uint32_t code_off;
    uint32_t target; /* label offset or extra arg */
    uintptr_t abs_target;
} emit_fixup_t;

typedef struct {
    uint8_t buf[DBT_EMIT_BUF_CAP];
    uint32_t len;
    emit_fixup_t fixups[DBT_MAX_FIXUPS];
    int nfixups;
    int error;
} emit_ctx_t;

static inline void emit8(emit_ctx_t *ctx, uint8_t b) {
    if (ctx->len + 1 > DBT_EMIT_BUF_CAP) {
        ctx->error = 1;
        return;
    }
    ctx->buf[ctx->len++] = b;
}

static inline void emit32(emit_ctx_t *ctx, uint32_t v) {
    if (ctx->len + 4 > DBT_EMIT_BUF_CAP) {
        ctx->error = 1;
        return;
    }
    memcpy(ctx->buf + ctx->len, &v, 4);
    ctx->len += 4;
}

static inline void emit16(emit_ctx_t *ctx, uint16_t v) {
    if (ctx->len + 2 > DBT_EMIT_BUF_CAP) {
        ctx->error = 1;
        return;
    }
    memcpy(ctx->buf + ctx->len, &v, 2);
    ctx->len += 2;
}

static inline void emit_bytes(emit_ctx_t *ctx, const uint8_t *p, size_t n) {
    if (ctx->len + n > DBT_EMIT_BUF_CAP) {
        ctx->error = 1;
        return;
    }
    memcpy(ctx->buf + ctx->len, p, n);
    ctx->len += (uint32_t)n;
}

static void add_fixup(emit_ctx_t *ctx, fixup_kind_t kind, uint32_t code_off,
                      uint32_t target, uintptr_t abs_target) {
    if (ctx->nfixups >= DBT_MAX_FIXUPS) {
        ctx->error = 1;
        return;
    }
    ctx->fixups[ctx->nfixups++] = (emit_fixup_t){kind, code_off, target, abs_target};
}

static void emit_jmp_trampoline_exit(emit_ctx_t *ctx) {
    emit8(ctx, 0xE9);
    uint32_t off = ctx->len;
    emit32(ctx, 0);
    add_fixup(ctx, FIXUP_ABS_EXIT, off, 0, (uintptr_t)dbt_trampoline_exit);
}

static void emit_mov_r15_off_imm32(emit_ctx_t *ctx, uint8_t off, uint32_t imm) {
    /* movl $imm, off(%r15): 41 c7 47 <off> <imm32> */
    emit8(ctx, 0x41);
    emit8(ctx, 0xC7);
    emit8(ctx, 0x47);
    emit8(ctx, off);
    emit32(ctx, imm);
}

static void emit_exit_with_reason(emit_ctx_t *ctx, uint32_t eip, uint32_t reason, uint32_t arg) {
    emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EIP, eip);
    if (arg != 0) {
        emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EXIT_ARG, arg);
    }
    emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EXIT_REASON, reason);
    emit_jmp_trampoline_exit(ctx);
}

/* Emit a patchable direct branch edge:
 *   patch_site_off: jcc/jmp rel32 -> initially points to edge_stub
 *   edge_stub: movl $target_eip, EIP(%r15); movl $patch_site_va, EXIT_ARG(%r15);
 *              movl $NM_EXIT_CHAIN_RESOLVE, EXIT_REASON(%r15); jmp dbt_trampoline_exit
 */
typedef struct {
    uint32_t patch_rel_off;
    uint32_t target_eip;
} pending_edge_t;

static void emit_edge_stub(emit_ctx_t *ctx, const pending_edge_t *edge) {
    /* Patch the branch at edge->patch_rel_off to jump here */
    uint32_t stub_off = ctx->len;
    int32_t rel = (int32_t)stub_off - (int32_t)(edge->patch_rel_off + 4);
    memcpy(ctx->buf + edge->patch_rel_off, &rel, 4);

    emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EIP, edge->target_eip);
    /* movl $patch_site_va, NM_CPU_OFF_EXIT_ARG(%r15) */
    emit8(ctx, 0x41);
    emit8(ctx, 0xC7);
    emit8(ctx, 0x47);
    emit8(ctx, NM_CPU_OFF_EXIT_ARG);
    uint32_t imm_off = ctx->len;
    emit32(ctx, 0);
    add_fixup(ctx, FIXUP_EDGE_STUB_RETADDR, imm_off, edge->patch_rel_off, 0);

    emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EXIT_REASON, NM_EXIT_CHAIN_RESOLVE);
    emit_jmp_trampoline_exit(ctx);
}

static void align_rel32_patch_site(emit_ctx_t *ctx, uint32_t opcode_len) {
    while (((ctx->len + opcode_len) & 3u) != 0u) {
        emit8(ctx, 0x90);
    }
}

/* Emit inline 64K cache lookup on %r10d; on miss exit to C dispatcher with cpu->eip = %r10d */
static void emit_indirect_dispatch_r10d(emit_ctx_t *ctx) {
    /* movl %r10d, %r9d : 45 89 d1 */
    emit8(ctx, 0x45); emit8(ctx, 0x89); emit8(ctx, 0xD1);
    /* shrl $12, %r9d : 41 c1 e9 0c */
    emit8(ctx, 0x41); emit8(ctx, 0xC1); emit8(ctx, 0xE9); emit8(ctx, 0x0C);
    /* xorl %r10d, %r9d : 45 31 d1 */
    emit8(ctx, 0x45); emit8(ctx, 0x31); emit8(ctx, 0xD1);
    /* andl $0xFFFF, %r9d : 41 81 e1 ff ff 00 00 */
    emit8(ctx, 0x41); emit8(ctx, 0x81); emit8(ctx, 0xE1); emit32(ctx, DBT_FAST_CACHE_MASK);
    /* movl $g_dbt_fast_cache, %r8d : 41 b8 <addr32> */
    emit8(ctx, 0x41); emit8(ctx, 0xB8);
    uint32_t tbl_imm_off = ctx->len;
    emit32(ctx, (uint32_t)(uintptr_t)g_dbt_fast_cache);
    add_fixup(ctx, FIXUP_JIT_ADDR32, tbl_imm_off, 0, (uintptr_t)g_dbt_fast_cache);
    /* movq (%r8, %r9, 8), %r8 : 4f 8b 04 c8 (single 8-byte atomic load) */
    emit8(ctx, 0x4F); emit8(ctx, 0x8B); emit8(ctx, 0x04); emit8(ctx, 0xC8);
    /* cmpl %r10d, %r8d : 45 39 d0 */
    emit8(ctx, 0x45); emit8(ctx, 0x39); emit8(ctx, 0xD0);
    /* jne .Lmiss (short) : 75 <disp8> */
    emit8(ctx, 0x75);
    uint32_t jcc_disp_off = ctx->len;
    emit8(ctx, 0);
    /* shrq $32, %r8 : 49 c1 e8 20 */
    emit8(ctx, 0x49); emit8(ctx, 0xC1); emit8(ctx, 0xE8); emit8(ctx, 0x20);
    /* testl %r8d, %r8d : 45 85 c0 */
    emit8(ctx, 0x45); emit8(ctx, 0x85); emit8(ctx, 0xC0);
    /* jz .Lmiss (short) : 74 <disp8> */
    emit8(ctx, 0x74);
    uint32_t jz_disp_off = ctx->len;
    emit8(ctx, 0);
    /* jmp *%r8 : 41 ff e0 */
    emit8(ctx, 0x41); emit8(ctx, 0xFF); emit8(ctx, 0xE0);

    /* .Lmiss: */
    uint32_t miss_off = ctx->len;
    ctx->buf[jcc_disp_off] = (uint8_t)(miss_off - (jcc_disp_off + 1));
    ctx->buf[jz_disp_off] = (uint8_t)(miss_off - (jz_disp_off + 1));

    /* movl %r10d, NM_CPU_OFF_EIP(%r15) : 45 89 57 20 */
    emit8(ctx, 0x45); emit8(ctx, 0x89); emit8(ctx, 0x57); emit8(ctx, NM_CPU_OFF_EIP);
    emit_mov_r15_off_imm32(ctx, NM_CPU_OFF_EXIT_REASON, NM_EXIT_NONE);
    emit_jmp_trampoline_exit(ctx);
}

static int is_esp_reg(x86_reg r) {
    return (r == X86_REG_ESP || r == X86_REG_SP);
}

static int is_hi8_reg(x86_reg r) {
    return (r == X86_REG_AH || r == X86_REG_CH || r == X86_REG_DH || r == X86_REG_BH);
}

static int reg_code_gpr(x86_reg r) {
    switch (r) {
    case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return 0;
    case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: return 1;
    case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: return 2;
    case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: return 3;
    case X86_REG_ESP: case X86_REG_SP: case X86_REG_AH: return 4;
    case X86_REG_EBP: case X86_REG_BP: case X86_REG_CH: return 5;
    case X86_REG_ESI: case X86_REG_SI: case X86_REG_DH: return 6;
    case X86_REG_EDI: case X86_REG_DI: case X86_REG_BH: return 7;
    default: return -1;
    }
}

/* Emit xchg %al/%ah (or cl/ch, dl/dh, bl/bh) to allow REX prefix without breaking AH..BH */
static void emit_hi8_swap(emit_ctx_t *ctx, x86_reg r) {
    switch (r) {
    case X86_REG_AH: emit8(ctx, 0x86); emit8(ctx, 0xC4); break; /* xchg %al, %ah */
    case X86_REG_CH: emit8(ctx, 0x86); emit8(ctx, 0xCD); break; /* xchg %cl, %ch */
    case X86_REG_DH: emit8(ctx, 0x86); emit8(ctx, 0xD6); break; /* xchg %dl, %dh */
    case X86_REG_BH: emit8(ctx, 0x86); emit8(ctx, 0xDF); break; /* xchg %bl, %bh */
    default: break;
    }
}

/* Emit 32-bit LEA of a memory operand (ignoring segment) into %r10d, then add %r14d if with_gs */
static void emit_lea_mem_to_r10d(emit_ctx_t *ctx, const x86_op_mem *mem, int with_gs) {
    int base_c = (mem->base != X86_REG_INVALID) ? reg_code_gpr(mem->base) : -1;
    int idx_c = (mem->index != X86_REG_INVALID) ? reg_code_gpr(mem->index) : -1;
    uint8_t sbits = 0;
    if (mem->scale == 2) sbits = 1;
    else if (mem->scale == 4) sbits = 2;
    else if (mem->scale == 8) sbits = 3;

    if (base_c < 0 && idx_c < 0) {
        /* movl $disp32, %r10d : 41 ba <u32> */
        emit8(ctx, 0x41); emit8(ctx, 0xBA); emit32(ctx, (uint32_t)(int32_t)mem->disp);
    } else {
        /* 0x67 lea <mem>, %r10d (reg=2, REX.R=1) */
        emit8(ctx, 0x67);
        uint8_t rex = 0x44; /* REX.R for R10 */
        if (base_c == 4) rex |= 0x01; /* REX.B for R12 */
        if (idx_c == 4) rex |= 0x02;  /* REX.X for R12 */
        emit8(ctx, rex);
        emit8(ctx, 0x8D);
        if (idx_c < 0 && base_c != 4) {
            /* No SIB needed unless base==R12 */
            if (mem->disp == 0 && base_c != 5) {
                emit8(ctx, (uint8_t)((2 << 3) | base_c));
            } else {
                emit8(ctx, (uint8_t)(0x80 | (2 << 3) | base_c));
                emit32(ctx, (uint32_t)(int32_t)mem->disp);
            }
        } else {
            uint8_t b = (base_c >= 0) ? (uint8_t)base_c : 5;
            uint8_t x = (idx_c >= 0) ? (uint8_t)idx_c : 4;
            uint8_t mod = (base_c < 0) ? 0 : 2;
            if (base_c >= 0 && mem->disp == 0 && base_c != 5) mod = 0;
            emit8(ctx, (uint8_t)((mod << 6) | (2 << 3) | 4));
            emit8(ctx, (uint8_t)((sbits << 6) | (x << 3) | b));
            if (mod == 2 || base_c < 0) {
                emit32(ctx, (uint32_t)(int32_t)mem->disp);
            }
        }
    }

    if (with_gs) {
        /* 0x67 lea (%r14d, %r10d, 1), %r10d : 67 47 8d 14 16 */
        emit8(ctx, 0x67);
        emit8(ctx, 0x47);
        emit8(ctx, 0x8D);
        emit8(ctx, 0x14);
        emit8(ctx, 0x16);
    }
}

/* Emit movl <op>, %r10d (for indirect call/jmp/push mem) */
static void emit_load_rm32_to_r10d(emit_ctx_t *ctx, const cs_x86_op *op, int size_bytes) {
    if (op->type == X86_OP_REG) {
        int r = reg_code_gpr(op->reg);
        if (size_bytes == 2) emit8(ctx, 0x66);
        /* mov %reg, %r10d : 41 89 <c0|(r<<3)|2> (if r==ESP, REX.R=1 -> 45) */
        uint8_t rex = 0x41 | (r == 4 ? 0x04 : 0x00);
        emit8(ctx, rex);
        emit8(ctx, 0x89);
        emit8(ctx, (uint8_t)(0xC0 | ((r & 7) << 3) | 2));
        return;
    }

    /* X86_OP_MEM */
    const x86_op_mem *m = &op->mem;
    if (m->segment == X86_REG_GS) {
        emit_lea_mem_to_r10d(ctx, m, 1);
        if (size_bytes == 2) emit8(ctx, 0x66);
        /* mov (%r10d), %r10d : 67 45 8b 12 */
        emit8(ctx, 0x67);
        emit8(ctx, 0x45);
        emit8(ctx, 0x8B);
        emit8(ctx, 0x12);
        return;
    }

    emit_lea_mem_to_r10d(ctx, m, 0);
    if (size_bytes == 2) emit8(ctx, 0x66);
    /* mov (%r10d), %r10d : 67 45 8b 12 */
    emit8(ctx, 0x67);
    emit8(ctx, 0x45);
    emit8(ctx, 0x8B);
    emit8(ctx, 0x12);
}

/* Emit movl %r10d, <mem> (for pop mem) */
static void emit_store_r10d_to_mem(emit_ctx_t *ctx, const x86_op_mem *m, int size_bytes) {
    if (m->segment == X86_REG_GS) {
        /* Save %r10d in %r11d, compute gs EA in %r10d, store %r11d to (%r10d) */
        emit8(ctx, 0x45); emit8(ctx, 0x89); emit8(ctx, 0xD3); /* mov %r10d, %r11d */
        emit_lea_mem_to_r10d(ctx, m, 1);
        if (size_bytes == 2) emit8(ctx, 0x66);
        emit8(ctx, 0x67); emit8(ctx, 0x45); emit8(ctx, 0x89); emit8(ctx, 0x1A); /* mov %r11d, (%r10d) */
        return;
    }

    int base_c = (m->base != X86_REG_INVALID) ? reg_code_gpr(m->base) : -1;
    int idx_c = (m->index != X86_REG_INVALID) ? reg_code_gpr(m->index) : -1;
    uint8_t sbits = (m->scale == 2) ? 1 : (m->scale == 4) ? 2 : (m->scale == 8) ? 3 : 0;

    if (size_bytes == 2) emit8(ctx, 0x66);
    emit8(ctx, 0x67);
    uint8_t rex = 0x44; /* REX.R for R10 */
    if (base_c == 4) rex |= 0x01;
    if (idx_c == 4) rex |= 0x02;
    emit8(ctx, rex);
    emit8(ctx, 0x89);
    if (base_c < 0 && idx_c < 0) {
        emit8(ctx, 0x14); /* mod=0, reg=2, rm=4 */
        emit8(ctx, 0x25);
        emit32(ctx, (uint32_t)(int32_t)m->disp);
    } else if (idx_c < 0 && base_c != 4) {
        emit8(ctx, (uint8_t)(0x80 | (2 << 3) | base_c));
        emit32(ctx, (uint32_t)(int32_t)m->disp);
    } else {
        uint8_t b = (base_c >= 0) ? (uint8_t)base_c : 5;
        uint8_t x = (idx_c >= 0) ? (uint8_t)idx_c : 4;
        emit8(ctx, (uint8_t)(0x80 | (2 << 3) | 4));
        emit8(ctx, (uint8_t)((sbits << 6) | (x << 3) | b));
        emit32(ctx, (uint32_t)(int32_t)m->disp);
    }
}

static void emit_lea_r12d_delta(emit_ctx_t *ctx, int32_t delta) {
    /* 0x67 0x45 0x8D 0x64 0x24 <disp8> or 0xA4 0x24 <disp32> */
    emit8(ctx, 0x67);
    emit8(ctx, 0x45);
    emit8(ctx, 0x8D);
    if (delta >= -128 && delta <= 127) {
        emit8(ctx, 0x64);
        emit8(ctx, 0x24);
        emit8(ctx, (uint8_t)(int8_t)delta);
    } else {
        emit8(ctx, 0xA4);
        emit8(ctx, 0x24);
        emit32(ctx, (uint32_t)delta);
    }
}

static int is_unsupported_insn(unsigned int id, const cs_x86 *x) {
    switch (id) {
    case X86_INS_HLT:
    case X86_INS_UD0:
    case X86_INS_UD1:
    case X86_INS_UD2:
    case X86_INS_IN:
    case X86_INS_OUT:
    case X86_INS_INSB:
    case X86_INS_INSW:
    case X86_INS_INSD:
    case X86_INS_OUTSB:
    case X86_INS_OUTSW:
    case X86_INS_OUTSD:
    case X86_INS_CLI:
    case X86_INS_STI:
    case X86_INS_ARPL:
    case X86_INS_BOUND:
    case X86_INS_INTO:
    case X86_INS_IRET:
    case X86_INS_IRETD:
    case X86_INS_AAA:
    case X86_INS_AAD:
    case X86_INS_AAM:
    case X86_INS_AAS:
    case X86_INS_DAA:
    case X86_INS_DAS:
    case X86_INS_SALC:
    case X86_INS_LDS:
    case X86_INS_LES:
    case X86_INS_LFS:
    case X86_INS_LGS:
    case X86_INS_LSS:
    case X86_INS_LGDT:
    case X86_INS_LIDT:
    case X86_INS_LLDT:
    case X86_INS_LTR:
    case X86_INS_SGDT:
    case X86_INS_SIDT:
    case X86_INS_SLDT:
    case X86_INS_STR:
    case X86_INS_LMSW:
    case X86_INS_SMSW:
    case X86_INS_CLTS:
    case X86_INS_INVD:
    case X86_INS_WBINVD:
    case X86_INS_INVLPG:
    case X86_INS_RDMSR:
    case X86_INS_WRMSR:
    case X86_INS_RDPMC:
    case X86_INS_SYSEXIT:
    case X86_INS_SYSRET:
    case X86_INS_LAR:
    case X86_INS_LSL:
    case X86_INS_VERR:
    case X86_INS_VERW:
    case X86_INS_LJMP:
    case X86_INS_LCALL:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
    case X86_INS_INT1:
    case X86_INS_INT3:
        return 1;
    case X86_INS_INT:
        if (x->op_count < 1 || x->operands[0].type != X86_OP_IMM || x->operands[0].imm != 0x80) {
            return 1;
        }
        return 0;
    default:
        return 0;
    }
}

static int jcc_to_opcode2(unsigned int id) {
    switch (id) {
    case X86_INS_JO:  return 0x80;
    case X86_INS_JNO: return 0x81;
    case X86_INS_JB:  return 0x82;
    case X86_INS_JAE: return 0x83;
    case X86_INS_JE:  return 0x84;
    case X86_INS_JNE: return 0x85;
    case X86_INS_JBE: return 0x86;
    case X86_INS_JA:  return 0x87;
    case X86_INS_JS:  return 0x88;
    case X86_INS_JNS: return 0x89;
    case X86_INS_JP:  return 0x8A;
    case X86_INS_JNP: return 0x8B;
    case X86_INS_JL:  return 0x8C;
    case X86_INS_JGE: return 0x8D;
    case X86_INS_JLE: return 0x8E;
    case X86_INS_JG:  return 0x8F;
    default: return -1;
    }
}

static int is_legacy_prefix(uint8_t b) {
    switch (b) {
    case 0xF0: case 0xF2: case 0xF3:
    case 0x26: case 0x2E: case 0x36: case 0x3E:
    case 0x64: case 0x65: case 0x66: case 0x67:
        return 1;
    default:
        return 0;
    }
}

static int is_seg_prefix(uint8_t b) {
    return (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65);
}

static int is_string_op(unsigned int id) {
    switch (id) {
    case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD:
    case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD:
    case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD:
    case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSD:
    case X86_INS_SCASB: case X86_INS_SCASW: case X86_INS_SCASD:
        return 1;
    default:
        return 0;
    }
}

static int emit_passthru_insn(emit_ctx_t *ctx, const cs_insn *insn) {
    const cs_x86 *x = &insn->detail->x86;
    const uint8_t *bytes = insn->bytes;
    uint8_t size = (uint8_t)insn->size;

    uint8_t pfx_end = 0;
    while (pfx_end < size && is_legacy_prefix(bytes[pfx_end])) {
        pfx_end++;
    }

    /* Check for 0xA0..0xA3 (mov al/ax/eax, moffs32) */
    if (pfx_end < size && bytes[pfx_end] >= 0xA0 && bytes[pfx_end] <= 0xA3 &&
        x->encoding.modrm_offset == 0) {
        uint8_t op = bytes[pfx_end];
        int has_66 = 0, has_gs = 0;
        for (uint8_t i = 0; i < pfx_end; i++) {
            if (bytes[i] == 0x64) return -1;
            if (bytes[i] == 0x66) has_66 = 1;
            if (bytes[i] == 0x65) has_gs = 1;
        }
        uint32_t moffs = 0;
        if (pfx_end + 5 <= size) {
            memcpy(&moffs, bytes + pfx_end + 1, 4);
        } else {
            return -1;
        }
        if (has_gs) {
            /* Re-encode as mov disp32(%r14d), %al/%ax/%eax (or reverse) */
            emit8(ctx, 0x67);
            if (has_66) emit8(ctx, 0x66);
            emit8(ctx, 0x41); /* REX.B = R14 */
            uint8_t new_op = (op == 0xA0) ? 0x8A : (op == 0xA1) ? 0x8B :
                             (op == 0xA2) ? 0x88 : 0x89;
            emit8(ctx, new_op);
            emit8(ctx, 0x86); /* mod=10, reg=0(AL/EAX), rm=6(R14) */
            emit32(ctx, moffs);
        } else {
            emit8(ctx, 0x67);
            if (has_66) emit8(ctx, 0x66);
            emit8(ctx, op);
            emit32(ctx, moffs);
        }
        return 0;
    }

    /* Check if 1-byte 0x40..0x4F inc/dec */
    if (pfx_end < size && bytes[pfx_end] >= 0x40 && bytes[pfx_end] <= 0x4F) {
        uint8_t op = bytes[pfx_end];
        int is_dec = (op >= 0x48);
        uint8_t reg = op & 7;
        for (uint8_t i = 0; i < pfx_end; i++) {
            if (!is_seg_prefix(bytes[i]) && bytes[i] != 0x67) emit8(ctx, bytes[i]);
        }
        if (reg == 4) emit8(ctx, 0x41); /* R12D */
        emit8(ctx, 0xFF);
        emit8(ctx, (uint8_t)(0xC0 | (is_dec ? 8 : 0) | reg));
        return 0;
    }

    /* Find memory operand and hi8/esp register operands */
    int has_mem = 0;
    const x86_op_mem *mem_op = NULL;
    int has_gs = 0;
    x86_reg hi8_reg = X86_REG_INVALID;
    int has_esp = 0;

    for (uint8_t i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_MEM) {
            has_mem = 1;
            mem_op = &op->mem;
            if (mem_op->segment == X86_REG_GS) has_gs = 1;
            if (mem_op->segment == X86_REG_FS) return -1;
        } else if (op->type == X86_OP_REG) {
            if (is_esp_reg(op->reg)) has_esp = 1;
            if (is_hi8_reg(op->reg)) hi8_reg = op->reg;
        }
    }

    uint8_t modrm_off = x->encoding.modrm_offset;
    int str_op = is_string_op(insn->id);

    /* Case A: No ModRM byte */
    if (modrm_off == 0) {
        uint8_t rex = 0;
        if (has_esp) rex |= 0x01; /* e.g., mov $imm, %esp (bc), xchg %eax,%esp (94), bswap %esp */
        if (str_op) emit8(ctx, 0x67);
        for (uint8_t i = 0; i < pfx_end; i++) {
            if (!is_seg_prefix(bytes[i]) && bytes[i] != 0x67) emit8(ctx, bytes[i]);
        }
        if (rex) emit8(ctx, (uint8_t)(0x40 | rex));
        emit_bytes(ctx, bytes + pfx_end, size - pfx_end);
        return 0;
    }

    /* Case B: Has ModRM byte */
    uint8_t modrm = bytes[modrm_off];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg_f = (modrm >> 3) & 7;
    uint8_t rm_f = modrm & 7;

    /* Determine REX bits needed */
    uint8_t rex = 0;
    int use_r10_gs = 0;
    int gs_disp_only = 0;
    int abs_disp32_fix = 0;

    if (mod != 3 && has_mem) {
        /* Non-memory operand (if register & ESP) is in modrm.reg */
        if (has_esp) {
            for (uint8_t i = 0; i < x->op_count; i++) {
                if (x->operands[i].type == X86_OP_REG && is_esp_reg(x->operands[i].reg)) {
                    rex |= 0x04; /* REX.R */
                }
            }
        }
        if (has_gs) {
            if (mem_op->base == X86_REG_INVALID && mem_op->index == X86_REG_INVALID) {
                gs_disp_only = 1;
                rex |= 0x01; /* REX.B for R14 */
            } else {
                use_r10_gs = 1;
                rex |= 0x01; /* REX.B for R10 */
            }
        } else {
            if (mod == 0 && rm_f == 5) {
                abs_disp32_fix = 1;
            } else if (mem_op->base == X86_REG_ESP) {
                rex |= 0x01; /* REX.B for R12 */
            }
        }
    } else {
        /* mod == 3 (register-only or register-imm) */
        if (has_esp) {
            int is_cl_shift = (x->op_count == 2 &&
                               x->operands[1].type == X86_OP_REG &&
                               x->operands[1].reg == X86_REG_CL &&
                               (insn->id == X86_INS_SHL || insn->id == X86_INS_SAL ||
                                insn->id == X86_INS_SHR || insn->id == X86_INS_SAR ||
                                insn->id == X86_INS_ROL || insn->id == X86_INS_ROR ||
                                insn->id == X86_INS_RCL || insn->id == X86_INS_RCR));
            int gpr_ops = 0;
            for (uint8_t i = 0; i < x->op_count; i++) {
                if (x->operands[i].type == X86_OP_REG && reg_code_gpr(x->operands[i].reg) >= 0) {
                    gpr_ops++;
                }
            }
            if (is_cl_shift || gpr_ops < 2) {
                /* Single GPR encoded in modrm (e.g. and $imm, %esp or shl %cl, %esp) */
                if (rm_f == 4) rex |= 0x01;
                else if (reg_f == 4) rex |= 0x04;
            } else {
                if (x->op_count >= 2 &&
                    x->operands[0].type == X86_OP_REG && is_esp_reg(x->operands[0].reg) &&
                    x->operands[1].type == X86_OP_REG && is_esp_reg(x->operands[1].reg)) {
                    if (reg_f == 4) rex |= 0x04;
                    if (rm_f == 4) rex |= 0x01;
                } else if (reg_f == 4 && rm_f != 4) {
                    rex |= 0x04;
                } else if (rm_f == 4 && reg_f != 4) {
                    rex |= 0x01;
                } else {
                    if (x->operands[0].type == X86_OP_REG && is_esp_reg(x->operands[0].reg)) {
                        rex |= 0x04;
                    } else {
                        rex |= 0x01;
                    }
                }
            }
        }
    }

    /* Check if hi8 reg (ah..bh) conflicts with REX */
    int need_hi8_swap = (hi8_reg != X86_REG_INVALID && rex != 0);
    if (need_hi8_swap) {
        emit_hi8_swap(ctx, hi8_reg);
        if (modrm_off > 0) {
            /* Replace reg=4..7 with 0..3 for the hi8 field */
            uint8_t hi_code = (uint8_t)reg_code_gpr(hi8_reg);
            if (mod == 3 && rm_f == hi_code && !(rex & 0x01)) {
                rm_f = hi_code - 4;
            } else if (reg_f == hi_code && !(rex & 0x04)) {
                reg_f = hi_code - 4;
            }
        }
    }

    if (use_r10_gs) {
        emit_lea_mem_to_r10d(ctx, mem_op, 1);
    }

    /* Emit prefixes: 0x67 if memory operand, then non-segment legacy prefixes */
    if (has_mem || str_op) {
        emit8(ctx, 0x67);
    }
    for (uint8_t i = 0; i < pfx_end; i++) {
        uint8_t p = bytes[i];
        if (!is_seg_prefix(p) && p != 0x67) {
            emit8(ctx, p);
        }
    }
    if (rex) {
        emit8(ctx, (uint8_t)(0x40 | rex));
    }

    /* Emit opcode bytes between pfx_end and modrm_off */
    if (modrm_off > pfx_end) {
        emit_bytes(ctx, bytes + pfx_end, modrm_off - pfx_end);
    }

    /* Emit ModRM (+ SIB + disp) */
    uint8_t disp_off = x->encoding.disp_offset;
    uint8_t disp_sz = x->encoding.disp_size;
    uint8_t imm_off = x->encoding.imm_offset;
    uint8_t imm_sz = x->encoding.imm_size;

    if (gs_disp_only) {
        /* mod=10, reg=reg_f, rm=6 (R14) + disp32 */
        emit8(ctx, (uint8_t)(0x80 | (reg_f << 3) | 6));
        emit32(ctx, (uint32_t)(int32_t)mem_op->disp);
    } else if (use_r10_gs) {
        /* mod=00, reg=reg_f, rm=2 (R10) */
        emit8(ctx, (uint8_t)((reg_f << 3) | 2));
    } else if (abs_disp32_fix) {
        /* mod=00, reg=reg_f, rm=4, sib=0x25 + disp32 */
        emit8(ctx, (uint8_t)((reg_f << 3) | 4));
        emit8(ctx, 0x25);
        emit32(ctx, (uint32_t)(int32_t)mem_op->disp);
    } else {
        uint8_t new_modrm = (uint8_t)((mod << 6) | (reg_f << 3) | rm_f);
        emit8(ctx, new_modrm);
        /* Copy SIB + disp (everything from modrm_off+1 up to imm or end) */
        uint8_t tail_start = (uint8_t)(modrm_off + 1);
        uint8_t tail_end = (imm_off != 0) ? imm_off : size;
        if (tail_end > tail_start) {
            emit_bytes(ctx, bytes + tail_start, tail_end - tail_start);
        }
        goto emit_imm_only;
    }

    (void)disp_off;
    (void)disp_sz;

emit_imm_only:
    if (imm_off != 0 && imm_sz > 0) {
        emit_bytes(ctx, bytes + imm_off, imm_sz);
    }

    if (need_hi8_swap) {
        emit_hi8_swap(ctx, hi8_reg);
    }
    return 0;
}

int dbt_translate_block(uint32_t guest_eip, int is_stub, uint32_t stub_id,
                        void **out_host_code, uint32_t *out_guest_end,
                        size_t *out_host_size) {
    emit_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (is_stub) {
        emit_exit_with_reason(&ctx, guest_eip, NM_EXIT_COMPAT_CALL, stub_id);
        if (ctx.error) return NM_ERR_INSN;
        void *jit = dbt_alloc_jit_mem(ctx.len);
        if (!jit) return NM_ERR_INSN;
        memcpy(jit, ctx.buf, ctx.len);
        for (int i = 0; i < ctx.nfixups; i++) {
            const emit_fixup_t *f = &ctx.fixups[i];
            if (f->kind == FIXUP_ABS_EXIT) {
                int32_t rel = (int32_t)((intptr_t)f->abs_target - ((intptr_t)jit + f->code_off + 4));
                memcpy((uint8_t *)jit + f->code_off, &rel, 4);
            }
        }
        *out_host_code = jit;
        *out_guest_end = guest_eip + 8;
        *out_host_size = ctx.len;
        return NM_OK;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        NM_LOG_ERROR("dbt", "cs_open(X86, 32) failed");
        return NM_ERR_INSN;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return NM_ERR_INSN;
    }

    pending_edge_t edges[2];
    int nedges = 0;

    uint64_t addr = guest_eip;
    const uint8_t *code_ptr = (const uint8_t *)(uintptr_t)guest_eip;
    size_t code_avail = 4096; /* per-insn decode; readable guest memory */
    int block_ended = 0;
    int insn_count = 0;

    while (!block_ended && insn_count < DBT_MAX_BLOCK_INSNS) {
        if (!cs_disasm_iter(handle, &code_ptr, &code_avail, &addr, insn)) {
            /* Invalid/undecodable opcode */
            emit_exit_with_reason(&ctx, (uint32_t)addr, NM_EXIT_UNSUPPORTED, 0);
            block_ended = 1;
            break;
        }
        insn_count++;
        const cs_x86 *x = &insn->detail->x86;
        uint32_t cur_eip = (uint32_t)insn->address;
        uint32_t next_eip = cur_eip + (uint32_t)insn->size;

        if (is_unsupported_insn(insn->id, x)) {
            emit_exit_with_reason(&ctx, cur_eip, NM_EXIT_UNSUPPORTED, 0);
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_INT || insn->id == X86_INS_SYSENTER) {
            emit_exit_with_reason(&ctx, next_eip, NM_EXIT_SYSCALL, 0);
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_ENDBR32 || insn->id == X86_INS_NOP || insn->id == X86_INS_FNOP) {
            emit8(&ctx, 0x90);
            continue;
        }

        if (insn->id == X86_INS_JMP) {
            if (x->op_count == 1 && x->operands[0].type == X86_OP_IMM) {
                uint32_t target = (uint32_t)x->operands[0].imm;
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){rel_off, target};
            } else {
                emit_load_rm32_to_r10d(&ctx, &x->operands[0], 4);
                emit_indirect_dispatch_r10d(&ctx);
            }
            block_ended = 1;
            break;
        }

        int jcc_op2 = jcc_to_opcode2(insn->id);
        if (jcc_op2 >= 0) {
            uint32_t taken = (uint32_t)x->operands[0].imm;
            align_rel32_patch_site(&ctx, 2);
            emit8(&ctx, 0x0F);
            emit8(&ctx, (uint8_t)jcc_op2);
            uint32_t taken_rel_off = ctx.len;
            emit32(&ctx, 0);
            edges[nedges++] = (pending_edge_t){taken_rel_off, taken};

            align_rel32_patch_site(&ctx, 1);
            emit8(&ctx, 0xE9);
            uint32_t fall_rel_off = ctx.len;
            emit32(&ctx, 0);
            edges[nedges++] = (pending_edge_t){fall_rel_off, next_eip};
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_JECXZ || insn->id == X86_INS_JCXZ) {
            uint32_t taken = (uint32_t)x->operands[0].imm;
            if (insn->id == X86_INS_JCXZ) emit8(&ctx, 0x66);
            /* testl %ecx, %ecx : 85 c9 */
            emit8(&ctx, 0x85); emit8(&ctx, 0xC9);
            /* jz taken */
            align_rel32_patch_site(&ctx, 2);
            emit8(&ctx, 0x0F); emit8(&ctx, 0x84);
            uint32_t taken_rel_off = ctx.len;
            emit32(&ctx, 0);
            edges[nedges++] = (pending_edge_t){taken_rel_off, taken};
            /* jmp next_eip */
            align_rel32_patch_site(&ctx, 1);
            emit8(&ctx, 0xE9);
            uint32_t fall_rel_off = ctx.len;
            emit32(&ctx, 0);
            edges[nedges++] = (pending_edge_t){fall_rel_off, next_eip};
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_LOOP || insn->id == X86_INS_LOOPE || insn->id == X86_INS_LOOPNE) {
            uint32_t taken = (uint32_t)x->operands[0].imm;
            /* lea -1(%ecx), %ecx : 67 8d 49 ff (does not modify flags!) */
            emit8(&ctx, 0x67); emit8(&ctx, 0x8D); emit8(&ctx, 0x49); emit8(&ctx, 0xFF);
            if (insn->id == X86_INS_LOOP) {
                /* jrcxz fallthrough (0xE3 <disp8>) */
                emit8(&ctx, 0xE3);
                uint32_t skip_off = ctx.len;
                emit8(&ctx, 0);
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t taken_rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){taken_rel_off, taken};
                ctx.buf[skip_off] = (uint8_t)(ctx.len - (skip_off + 1));
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t fall_rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){fall_rel_off, next_eip};
            } else {
                uint8_t jcc = (insn->id == X86_INS_LOOPE) ? 0x84 : 0x85;
                emit8(&ctx, 0x0F); emit8(&ctx, jcc); emit8(&ctx, 5); emit8(&ctx, 0); emit8(&ctx, 0); emit8(&ctx, 0);
                emit8(&ctx, 0xE9);
                uint32_t f1_off = ctx.len;
                emit32(&ctx, 0);
                emit8(&ctx, 0xE3);
                uint32_t skip_off = ctx.len;
                emit8(&ctx, 0);
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t taken_rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){taken_rel_off, taken};
                uint32_t f_lbl = ctx.len;
                int32_t f1_rel = (int32_t)f_lbl - (int32_t)(f1_off + 4);
                memcpy(ctx.buf + f1_off, &f1_rel, 4);
                ctx.buf[skip_off] = (uint8_t)(f_lbl - (skip_off + 1));
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t fall_rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){fall_rel_off, next_eip};
            }
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_CALL) {
            if (x->op_count == 1 && x->operands[0].type == X86_OP_IMM) {
                uint32_t target = (uint32_t)x->operands[0].imm;
                emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0xC7);
                emit8(&ctx, 0x44); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                emit32(&ctx, next_eip);
                emit_lea_r12d_delta(&ctx, -4);
                align_rel32_patch_site(&ctx, 1);
                emit8(&ctx, 0xE9);
                uint32_t rel_off = ctx.len;
                emit32(&ctx, 0);
                edges[nedges++] = (pending_edge_t){rel_off, target};
            } else {
                emit_load_rm32_to_r10d(&ctx, &x->operands[0], 4);
                emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0xC7);
                emit8(&ctx, 0x44); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                emit32(&ctx, next_eip);
                emit_lea_r12d_delta(&ctx, -4);
                emit_indirect_dispatch_r10d(&ctx);
            }
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_RET) {
            uint32_t imm16 = (x->op_count == 1 && x->operands[0].type == X86_OP_IMM)
                           ? (uint32_t)(uint16_t)x->operands[0].imm : 0;
            emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x8B);
            emit8(&ctx, 0x14); emit8(&ctx, 0x24);
            emit_lea_r12d_delta(&ctx, (int32_t)(4 + imm16));
            emit_indirect_dispatch_r10d(&ctx);
            block_ended = 1;
            break;
        }

        if (insn->id == X86_INS_PUSH) {
            const cs_x86_op *op = &x->operands[0];
            if (op->type == X86_OP_REG) {
                if (op->reg == X86_REG_CS || op->reg == X86_REG_DS ||
                    op->reg == X86_REG_ES || op->reg == X86_REG_SS) {
                    emit_exit_with_reason(&ctx, cur_eip, NM_EXIT_UNSUPPORTED, 0);
                    block_ended = 1;
                    break;
                }
                int r = reg_code_gpr(op->reg);
                if (r < 0) {
                    emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0xC7);
                    emit8(&ctx, 0x44); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                    emit32(&ctx, 0);
                    emit_lea_r12d_delta(&ctx, -4);
                } else if (op->size == 2) {
                    emit8(&ctx, 0x66); emit8(&ctx, 0x67);
                    emit8(&ctx, (uint8_t)(0x41 | (r == 4 ? 0x04 : 0)));
                    emit8(&ctx, 0x89);
                    emit8(&ctx, (uint8_t)(0x44 | ((r & 7) << 3)));
                    emit8(&ctx, 0x24); emit8(&ctx, 0xFE);
                    emit_lea_r12d_delta(&ctx, -2);
                } else {
                    emit8(&ctx, 0x67);
                    emit8(&ctx, (uint8_t)(0x41 | (r == 4 ? 0x04 : 0)));
                    emit8(&ctx, 0x89);
                    emit8(&ctx, (uint8_t)(0x44 | ((r & 7) << 3)));
                    emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                    emit_lea_r12d_delta(&ctx, -4);
                }
            } else if (op->type == X86_OP_IMM) {
                if (op->size == 2) {
                    emit8(&ctx, 0x66); emit8(&ctx, 0x67); emit8(&ctx, 0x41);
                    emit8(&ctx, 0xC7); emit8(&ctx, 0x44); emit8(&ctx, 0x24); emit8(&ctx, 0xFE);
                    emit16(&ctx, (uint16_t)op->imm);
                    emit_lea_r12d_delta(&ctx, -2);
                } else {
                    emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0xC7);
                    emit8(&ctx, 0x44); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                    emit32(&ctx, (uint32_t)op->imm);
                    emit_lea_r12d_delta(&ctx, -4);
                }
            } else if (op->type == X86_OP_MEM) {
                emit_load_rm32_to_r10d(&ctx, op, op->size == 2 ? 2 : 4);
                if (op->size == 2) {
                    emit8(&ctx, 0x66); emit8(&ctx, 0x67); emit8(&ctx, 0x45);
                    emit8(&ctx, 0x89); emit8(&ctx, 0x54); emit8(&ctx, 0x24); emit8(&ctx, 0xFE);
                    emit_lea_r12d_delta(&ctx, -2);
                } else {
                    emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x89);
                    emit8(&ctx, 0x54); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
                    emit_lea_r12d_delta(&ctx, -4);
                }
            }
            continue;
        }

        if (insn->id == X86_INS_POP) {
            const cs_x86_op *op = &x->operands[0];
            if (op->type == X86_OP_REG) {
                if (op->reg == X86_REG_CS || op->reg == X86_REG_DS ||
                    op->reg == X86_REG_ES || op->reg == X86_REG_SS) {
                    emit_exit_with_reason(&ctx, cur_eip, NM_EXIT_UNSUPPORTED, 0);
                    block_ended = 1;
                    break;
                }
                int r = reg_code_gpr(op->reg);
                if (r < 0) {
                    emit_lea_r12d_delta(&ctx, 4);
                } else if (r == 4) {
                    if (op->size == 2) emit8(&ctx, 0x66);
                    emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x8B);
                    emit8(&ctx, 0x24); emit8(&ctx, 0x24);
                } else {
                    if (op->size == 2) emit8(&ctx, 0x66);
                    emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0x8B);
                    emit8(&ctx, (uint8_t)((r << 3) | 4)); emit8(&ctx, 0x24);
                    emit_lea_r12d_delta(&ctx, op->size == 2 ? 2 : 4);
                }
            } else if (op->type == X86_OP_MEM) {
                if (op->size == 2) emit8(&ctx, 0x66);
                emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x8B);
                emit8(&ctx, 0x14); emit8(&ctx, 0x24);
                emit_lea_r12d_delta(&ctx, op->size == 2 ? 2 : 4);
                emit_store_r10d_to_mem(&ctx, &op->mem, op->size == 2 ? 2 : 4);
            }
            continue;
        }

        if (insn->id == X86_INS_PUSHAL || insn->id == X86_INS_PUSHAW) {
            emit8(&ctx, 0x45); emit8(&ctx, 0x89); emit8(&ctx, 0xE2);
            static const uint8_t regs[8] = {0, 1, 2, 3, 4, 5, 6, 7};
            for (int k = 0; k < 8; k++) {
                int8_t disp = (int8_t)(-4 * (k + 1));
                emit8(&ctx, 0x67);
                if (regs[k] == 4) {
                    emit8(&ctx, 0x45); emit8(&ctx, 0x89); emit8(&ctx, 0x54);
                    emit8(&ctx, 0x24); emit8(&ctx, (uint8_t)disp);
                } else {
                    emit8(&ctx, 0x41); emit8(&ctx, 0x89);
                    emit8(&ctx, (uint8_t)(0x44 | (regs[k] << 3)));
                    emit8(&ctx, 0x24); emit8(&ctx, (uint8_t)disp);
                }
            }
            emit_lea_r12d_delta(&ctx, -32);
            continue;
        }

        if (insn->id == X86_INS_POPAL || insn->id == X86_INS_POPAW) {
            static const int8_t offs[7] = {0, 4, 8, 16, 20, 24, 28};
            static const uint8_t regs[7] = {7, 6, 5, 3, 2, 1, 0};
            for (int k = 0; k < 7; k++) {
                emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0x8B);
                emit8(&ctx, (uint8_t)(0x44 | (regs[k] << 3)));
                emit8(&ctx, 0x24); emit8(&ctx, (uint8_t)offs[k]);
            }
            emit_lea_r12d_delta(&ctx, 32);
            continue;
        }

        if (insn->id == X86_INS_PUSHF || insn->id == X86_INS_PUSHFD) {
            emit8(&ctx, 0x9C);
            emit8(&ctx, 0x41); emit8(&ctx, 0x5A);
            emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x89);
            emit8(&ctx, 0x54); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
            emit_lea_r12d_delta(&ctx, -4);
            continue;
        }

        if (insn->id == X86_INS_POPF || insn->id == X86_INS_POPFD) {
            emit8(&ctx, 0x67); emit8(&ctx, 0x45); emit8(&ctx, 0x8B);
            emit8(&ctx, 0x14); emit8(&ctx, 0x24);
            emit_lea_r12d_delta(&ctx, 4);
            emit8(&ctx, 0x41); emit8(&ctx, 0x52);
            emit8(&ctx, 0x9D);
            continue;
        }

        if (insn->id == X86_INS_LEAVE) {
            emit8(&ctx, 0x41); emit8(&ctx, 0x89); emit8(&ctx, 0xEC);
            emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0x8B);
            emit8(&ctx, 0x2C); emit8(&ctx, 0x24);
            emit_lea_r12d_delta(&ctx, 4);
            continue;
        }

        if (insn->id == X86_INS_ENTER) {
            uint16_t alloc_sz = (uint16_t)x->operands[0].imm;
            emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0x89);
            emit8(&ctx, 0x6C); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
            emit8(&ctx, 0x67); emit8(&ctx, 0x41); emit8(&ctx, 0x8D);
            emit8(&ctx, 0x6C); emit8(&ctx, 0x24); emit8(&ctx, 0xFC);
            emit_lea_r12d_delta(&ctx, -(4 + (int32_t)alloc_sz));
            continue;
        }

        if (insn->id == X86_INS_XLATB) {
            emit8(&ctx, 0x44); emit8(&ctx, 0x0F); emit8(&ctx, 0xB6); emit8(&ctx, 0xD0);
            emit8(&ctx, 0x67); emit8(&ctx, 0x42); emit8(&ctx, 0x8A); emit8(&ctx, 0x04); emit8(&ctx, 0x13);
            continue;
        }

        if (emit_passthru_insn(&ctx, insn) != 0) {
            emit_exit_with_reason(&ctx, cur_eip, NM_EXIT_UNSUPPORTED, 0);
            block_ended = 1;
            break;
        }
    }

    if (!block_ended) {
        /* Hit max insns per block: emit direct chain edge to current addr */
        align_rel32_patch_site(&ctx, 1);
        emit8(&ctx, 0xE9);
        uint32_t rel_off = ctx.len;
        emit32(&ctx, 0);
        edges[nedges++] = (pending_edge_t){rel_off, (uint32_t)addr};
    }

    for (int e = 0; e < nedges; e++) {
        emit_edge_stub(&ctx, &edges[e]);
    }

    cs_free(insn, 1);
    cs_close(&handle);

    if (ctx.error) {
        NM_LOG_ERROR("dbt", "JIT emission buffer overflow at eip=0x%08x", guest_eip);
        return NM_ERR_INSN;
    }

    void *jit = dbt_alloc_jit_mem(ctx.len);
    if (!jit) {
        return NM_ERR_INSN;
    }
    memcpy(jit, ctx.buf, ctx.len);

    for (int i = 0; i < ctx.nfixups; i++) {
        const emit_fixup_t *f = &ctx.fixups[i];
        if (f->kind == FIXUP_ABS_EXIT) {
            int32_t rel = (int32_t)((intptr_t)f->abs_target - ((intptr_t)jit + f->code_off + 4));
            memcpy((uint8_t *)jit + f->code_off, &rel, 4);
        } else if (f->kind == FIXUP_EDGE_STUB_RETADDR) {
            uint32_t patch_va = (uint32_t)((uintptr_t)jit + f->target);
            memcpy((uint8_t *)jit + f->code_off, &patch_va, 4);
        } else if (f->kind == FIXUP_JIT_ADDR32) {
            uint32_t addr32 = (uint32_t)f->abs_target;
            memcpy((uint8_t *)jit + f->code_off, &addr32, 4);
        }
    }

    *out_host_code = jit;
    *out_guest_end = (uint32_t)addr;
    *out_host_size = ctx.len;
    return NM_OK;
}
