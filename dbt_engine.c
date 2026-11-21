#define _GNU_SOURCE
#include "dbt_internal.h"

#include <asm/prctl.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define DBT_JIT_CHUNK_SIZE (16u * 1024u * 1024u)
#define DBT_BLOCK_MAP_SIZE 65536u
#define DBT_BLOCK_MAP_MASK (DBT_BLOCK_MAP_SIZE - 1u)
#define DBT_EDGE_MAP_SIZE  4096u
#define DBT_EDGE_MAP_MASK  (DBT_EDGE_MAP_SIZE - 1u)
#define DBT_THREAD_STACK_SZ (2u * 1024u * 1024u)

alignas(8) dbt_fast_entry_t g_dbt_fast_cache[DBT_FAST_CACHE_SIZE];

typedef struct dbt_block_node {
    uint32_t guest_eip;
    uint32_t guest_end;
    void    *host_code;
    size_t   host_size;
    int      valid;
    struct dbt_block_node *next;
} dbt_block_node_t;

typedef struct dbt_patched_edge {
    uint32_t patch_site_va;
    int32_t  orig_stub_rel;
    uint32_t target_guest_eip;
    int      patched;
    struct dbt_patched_edge *next;
} dbt_patched_edge_t;

static pthread_mutex_t g_jit_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t *g_jit_cur = nullptr;
static size_t   g_jit_rem = 0;
static dbt_block_node_t *g_block_buckets[DBT_BLOCK_MAP_SIZE];
static dbt_patched_edge_t *g_edge_buckets[DBT_EDGE_MAP_SIZE];

/* SIGSEGV NX-guard state (100% async-signal-safe, pre-allocated trampoline pool) */
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static struct sigaction g_prev_segv;

#define DBT_SEGV_CB_CAP 1024
static _Atomic uint32_t g_segv_vas[DBT_SEGV_CB_CAP];
static _Atomic(uint8_t *) g_segv_tramp_page = nullptr;

/* Per-thread CPU & guest stack cleanup */
static thread_local newminhh_cpu_t tls_cpu;
static thread_local uint32_t tls_stack_base = 0;
static thread_local uint32_t tls_stack_size = 0;
static thread_local uint32_t tls_gs_alloc_base = 0;
static thread_local uint32_t tls_gs_alloc_size = 0;
static thread_local int tls_stack_key_set = 0;
static pthread_key_t g_tls_stack_key;

typedef struct {
    uint32_t base;
    uint32_t size;
    uint32_t gs_alloc_base;
    uint32_t gs_alloc_size;
} tls_stack_cleanup_t;

static thread_local tls_stack_cleanup_t *tls_cleanup_rec = nullptr;

static void tls_stack_destructor(void *ptr) {
    tls_stack_cleanup_t *c = (tls_stack_cleanup_t *)ptr;
    if (c) {
        if (c->gs_alloc_base && c->gs_alloc_size) {
            syscall(__NR_arch_prctl, ARCH_SET_GS, 0UL);
            munmap((void *)(uintptr_t)c->gs_alloc_base, c->gs_alloc_size);
        }
        if (c->base && c->size) {
            munmap((void *)(uintptr_t)c->base, c->size);
        }
        free(c);
    }
}

static void register_tls_cleanup_if_needed(void) {
    if (!tls_cleanup_rec) {
        tls_cleanup_rec = (tls_stack_cleanup_t *)calloc(1, sizeof(*tls_cleanup_rec));
    }
    if (tls_cleanup_rec) {
        tls_cleanup_rec->base = tls_stack_base;
        tls_cleanup_rec->size = tls_stack_size;
        tls_cleanup_rec->gs_alloc_base = tls_gs_alloc_base;
        tls_cleanup_rec->gs_alloc_size = tls_gs_alloc_size;
        if (!tls_stack_key_set) {
            pthread_setspecific(g_tls_stack_key, tls_cleanup_rec);
            tls_stack_key_set = 1;
        }
    }
}

void dbt_init_cpu_fxsave(newminhh_cpu_t *cpu) {
    memset(cpu->fxsave_area, 0, sizeof(cpu->fxsave_area));
    uint16_t fcw = 0x037Fu;
    uint32_t mxcsr = 0x1F80u;
    memcpy(cpu->fxsave_area + 0, &fcw, sizeof(fcw));
    memcpy(cpu->fxsave_area + 24, &mxcsr, sizeof(mxcsr));
}

uint32_t dbt_ensure_thread_tls_and_stack(newminhh_cpu_t *cpu, uint32_t min_stack_size) {
    if (cpu->gs_base == 0) {
        uint64_t cur_gs = 0;
        if (syscall(__NR_arch_prctl, ARCH_GET_GS, &cur_gs) == 0 && cur_gs != 0) {
            cpu->gs_base = (uint32_t)cur_gs;
        } else {
            uint32_t gs = dbt_init_tls_block(nullptr);
            cpu->gs_base = gs;
            if (gs >= 8192u && tls_gs_alloc_base == 0) {
                tls_gs_alloc_base = gs - 8192u;
                tls_gs_alloc_size = 16384u;
                register_tls_cleanup_if_needed();
            }
        }
    }
    if (cpu->gpr[NM_REG_ESP] == 0) {
        uint32_t sz = min_stack_size ? min_stack_size : DBT_THREAD_STACK_SZ;
        if (tls_stack_base == 0) {
            void *stk = mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (stk != MAP_FAILED) {
                tls_stack_base = (uint32_t)(uintptr_t)stk;
                tls_stack_size = sz;
                register_tls_cleanup_if_needed();
            }
        }
        if (tls_stack_base != 0) {
            cpu->gpr[NM_REG_ESP] = tls_stack_base + tls_stack_size - 64u;
        }
    }
    uint16_t fcw = 0;
    memcpy(&fcw, cpu->fxsave_area, sizeof(fcw));
    if (fcw == 0) {
        dbt_init_cpu_fxsave(cpu);
    }
    return cpu->gpr[NM_REG_ESP];
}

void *dbt_alloc_jit_mem(size_t size) {
    size_t aligned = (size + 15u) & ~(size_t)15u;
    if (aligned == 0) aligned = 16;

    pthread_mutex_lock(&g_jit_lock);
    if (!g_jit_cur || g_jit_rem < aligned) {
        size_t chunk = (aligned > DBT_JIT_CHUNK_SIZE) ? ((aligned + 4095u) & ~(size_t)4095u) : DBT_JIT_CHUNK_SIZE;
        void *mem = mmap(nullptr, chunk, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            pthread_mutex_unlock(&g_jit_lock);
            NM_LOG_ERROR("dbt", "JIT mmap(%zu) failed: errno=%d", chunk, errno);
            return nullptr;
        }
        g_jit_cur = (uint8_t *)mem;
        g_jit_rem = chunk;
    }
    void *res = g_jit_cur;
    g_jit_cur += aligned;
    g_jit_rem -= aligned;
    pthread_mutex_unlock(&g_jit_lock);
    return res;
}

static inline uint32_t fast_hash(uint32_t eip) {
    return (eip ^ (eip >> 12)) & DBT_FAST_CACHE_MASK;
}

static inline uint64_t pack_fast_entry(uint32_t guest_eip, void *host_code) {
    return ((uint64_t)(uint32_t)(uintptr_t)host_code << 32) | (uint64_t)guest_eip;
}

void dbt_invalidate_cache_range(uint32_t start_va, uint32_t size) {
    if (size == 0) return;
    uint64_t start64 = (uint64_t)start_va;
    uint64_t end64 = start64 + (uint64_t)size;
    pthread_mutex_lock(&g_jit_lock);
    for (uint32_t i = 0; i < DBT_FAST_CACHE_SIZE; i++) {
        uint64_t val = __atomic_load_n(&g_dbt_fast_cache[i].raw, __ATOMIC_ACQUIRE);
        uint32_t eip = (uint32_t)(val & 0xFFFFFFFFULL);
        if ((uint64_t)eip >= start64 && (uint64_t)eip < end64) {
            __atomic_store_n(&g_dbt_fast_cache[i].raw, 0x00000000FFFFFFFFULL, __ATOMIC_RELEASE);
        }
    }
    for (uint32_t b = 0; b < DBT_BLOCK_MAP_SIZE; b++) {
        for (dbt_block_node_t *n = g_block_buckets[b]; n; n = n->next) {
            if (n->valid && (uint64_t)n->guest_eip < end64 && (uint64_t)n->guest_end > start64) {
                n->valid = 0;
            }
        }
    }
    for (uint32_t eb = 0; eb < DBT_EDGE_MAP_SIZE; eb++) {
        for (dbt_patched_edge_t *e = g_edge_buckets[eb]; e; e = e->next) {
            if (e->patched && (uint64_t)e->target_guest_eip >= start64 &&
                (uint64_t)e->target_guest_eip < end64) {
                __atomic_store_n((int32_t *)(uintptr_t)e->patch_site_va,
                                 e->orig_stub_rel, __ATOMIC_RELEASE);
                e->patched = 0;
            }
        }
    }
    pthread_mutex_unlock(&g_jit_lock);

    for (int i = 0; i < DBT_SEGV_CB_CAP; i++) {
        uint32_t gva = atomic_load_explicit(&g_segv_vas[i], memory_order_acquire);
        if (gva != 0 && (uint64_t)gva >= start64 && (uint64_t)gva < end64) {
            atomic_compare_exchange_strong_explicit(&g_segv_vas[i], &gva, 0u,
                                                    memory_order_acq_rel, memory_order_acquire);
        }
    }
}

static void *dbt_lookup_or_translate(uint32_t guest_eip, int is_stub, uint32_t stub_id) {
    uint32_t fidx = fast_hash(guest_eip);
    uint64_t entry = __atomic_load_n(&g_dbt_fast_cache[fidx].raw, __ATOMIC_ACQUIRE);
    if ((uint32_t)(entry & 0xFFFFFFFFULL) == guest_eip) {
        uint32_t hc = (uint32_t)(entry >> 32);
        if (hc != 0) {
            return (void *)(uintptr_t)hc;
        }
    }

    uint32_t bidx = guest_eip & DBT_BLOCK_MAP_MASK;
    pthread_mutex_lock(&g_jit_lock);
    for (dbt_block_node_t *n = g_block_buckets[bidx]; n; n = n->next) {
        if (n->valid && n->guest_eip == guest_eip) {
            __atomic_store_n(&g_dbt_fast_cache[fidx].raw,
                             pack_fast_entry(guest_eip, n->host_code),
                             __ATOMIC_RELEASE);
            pthread_mutex_unlock(&g_jit_lock);
            return n->host_code;
        }
    }
    pthread_mutex_unlock(&g_jit_lock);

    void *host_code = nullptr;
    uint32_t guest_end = guest_eip;
    size_t host_size = 0;
    if (dbt_translate_block(guest_eip, is_stub, stub_id,
                            &host_code, &guest_end, &host_size) != NM_OK) {
        return nullptr;
    }

    pthread_mutex_lock(&g_jit_lock);
    dbt_block_node_t *reuse_node = nullptr;
    for (dbt_block_node_t *n = g_block_buckets[bidx]; n; n = n->next) {
        if (n->valid && n->guest_eip == guest_eip) {
            void *existing = n->host_code;
            __atomic_store_n(&g_dbt_fast_cache[fidx].raw,
                             pack_fast_entry(guest_eip, existing),
                             __ATOMIC_RELEASE);
            pthread_mutex_unlock(&g_jit_lock);
            return existing;
        }
        if (!n->valid && !reuse_node) {
            reuse_node = n;
        }
    }
    if (reuse_node) {
        reuse_node->guest_eip = guest_eip;
        reuse_node->guest_end = guest_end;
        reuse_node->host_code = host_code;
        reuse_node->host_size = host_size;
        reuse_node->valid = 1;
    } else {
        dbt_block_node_t *node = (dbt_block_node_t *)calloc(1, sizeof(*node));
        if (!node) {
            pthread_mutex_unlock(&g_jit_lock);
            return host_code;
        }
        node->guest_eip = guest_eip;
        node->guest_end = guest_end;
        node->host_code = host_code;
        node->host_size = host_size;
        node->valid = 1;
        node->next = g_block_buckets[bidx];
        g_block_buckets[bidx] = node;
    }
    __atomic_store_n(&g_dbt_fast_cache[fidx].raw,
                     pack_fast_entry(guest_eip, host_code),
                     __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_jit_lock);
    return host_code;
}

uint64_t dbt_segv_cb_dispatch(uint32_t slot_id,
                              const uint64_t *gprs,
                              const uint64_t *xmms,
                              const uint64_t *caller_stack,
                              double *out_fp) {
    if (slot_id >= DBT_SEGV_CB_CAP) {
        return 0;
    }
    uint32_t gva = atomic_load_explicit(&g_segv_vas[slot_id], memory_order_acquire);
    if (gva == 0) {
        return 0;
    }
    return newminhh_in_bridge(gva, nullptr, gprs, xmms, caller_stack, NM_CB_MODE_DBT, out_fp);
}

static void emit_segv_tramp_slot(uint8_t *slot, uint32_t slot_id, uintptr_t target) {
    /* movl $slot_id, %r11d (6B: 41 bb <u32>) */
    slot[0] = 0x41;
    slot[1] = 0xBB;
    memcpy(&slot[2], &slot_id, 4);

    int64_t rel = (int64_t)target - (int64_t)((uintptr_t)slot + 11);
    if (rel >= INT32_MIN && rel <= INT32_MAX) {
        int32_t rel32 = (int32_t)rel;
        slot[6] = 0xE9;
        memcpy(&slot[7], &rel32, 4);
        slot[11] = 0x90;
        slot[12] = 0x90;
        slot[13] = 0x90;
        slot[14] = 0x90;
        slot[15] = 0x90;
    } else {
        uint32_t addr32 = (uint32_t)target;
        slot[6] = 0x41;
        slot[7] = 0xBA;
        memcpy(&slot[8], &addr32, 4);
        slot[12] = 0x41;
        slot[13] = 0xFF;
        slot[14] = 0xE2;
        slot[15] = 0x90;
    }
}

static void init_segv_tramp_pool(void) {
    size_t sz = (size_t)DBT_SEGV_CB_CAP * 16u;
    size_t page_sz = (sz + 4095u) & ~(size_t)4095u;
    uintptr_t target = (uintptr_t)dbt_segv_cb_entry;
    void *hint = (void *)((target + 0x100000u) & ~(uintptr_t)0xFFFu);
    uint8_t *mem = (uint8_t *)mmap(hint, page_sz, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        mem = (uint8_t *)mmap(nullptr, page_sz, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (mem == MAP_FAILED) {
        NM_LOG_ERROR("dbt", "SIGSEGV trampoline pool mmap(%zu) failed: errno=%d", page_sz, errno);
        return;
    }
    for (uint32_t i = 0; i < DBT_SEGV_CB_CAP; i++) {
        emit_segv_tramp_slot(mem + (size_t)i * 16u, i, target);
    }
    if (mprotect(mem, page_sz, PROT_READ | PROT_EXEC) != 0) {
        NM_LOG_ERROR("dbt", "SIGSEGV trampoline pool mprotect failed: errno=%d", errno);
        munmap(mem, page_sz);
        return;
    }
    atomic_store_explicit(&g_segv_tramp_page, mem, memory_order_release);
}

static void dbt_sigsegv_handler(int sig, siginfo_t *si, void *uctx_raw) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)uctx_raw;
    if (si && uc && si->si_code == SEGV_ACCERR) {
        uint64_t rip64 = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
        uint64_t faddr = (uint64_t)(uintptr_t)si->si_addr;
        uint8_t *tramp_page = atomic_load_explicit(&g_segv_tramp_page, memory_order_acquire);
        if (tramp_page && rip64 == faddr && rip64 < 0x100000000ULL &&
            dbt_is_guest_rx_va((uint32_t)rip64)) {
            uint32_t gva = (uint32_t)rip64;
            int slot = -1;
            for (int i = 0; i < DBT_SEGV_CB_CAP; i++) {
                if (atomic_load_explicit(&g_segv_vas[i], memory_order_acquire) == gva) {
                    slot = i;
                    break;
                }
            }
            if (slot < 0) {
                for (int i = 0; i < DBT_SEGV_CB_CAP; i++) {
                    uint32_t expected = 0;
                    if (atomic_compare_exchange_strong_explicit(&g_segv_vas[i], &expected, gva,
                                                                memory_order_acq_rel, memory_order_acquire)) {
                        slot = i;
                        break;
                    }
                    if (expected == gva) {
                        slot = i;
                        break;
                    }
                }
            }
            if (slot >= 0) {
                void *tramp = tramp_page + (size_t)slot * 16u;
                uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)tramp;
                return;
            }
        }
    }

    /* Non-guest segfault: restore previous/default handler */
    if ((g_prev_segv.sa_flags & SA_SIGINFO) && g_prev_segv.sa_sigaction) {
        g_prev_segv.sa_sigaction(SIGSEGV, si, uctx_raw);
        return;
    }
    if (g_prev_segv.sa_handler == SIG_IGN) {
        return;
    }
    if (g_prev_segv.sa_handler != SIG_DFL && g_prev_segv.sa_handler != nullptr) {
        g_prev_segv.sa_handler(SIGSEGV);
        return;
    }
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(SIGSEGV, &dfl, nullptr);
}

static void dbt_init_once(void) {
    for (uint32_t i = 0; i < DBT_FAST_CACHE_SIZE; i++) {
        __atomic_store_n(&g_dbt_fast_cache[i].raw, 0x00000000FFFFFFFFULL, __ATOMIC_RELEASE);
    }
    pthread_key_create(&g_tls_stack_key, tls_stack_destructor);
    init_segv_tramp_pool();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = dbt_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_prev_segv);
}

void dbt_ensure_initialized(void) {
    pthread_once(&g_init_once, dbt_init_once);
}

static int dbt_guest_invoker_cb(uint32_t guest_fn_va,
                                const nm_fn_sig_t *sig,
                                const uint32_t *cdecl_words,
                                int nwords,
                                uint64_t *out_gpr,
                                double *out_fp) {
    dbt_ensure_initialized();
    newminhh_cpu_t *cpu = &tls_cpu;
    newminhh_cpu_t saved_cpu = *cpu;

    if (cpu->gpr[NM_REG_ESP] != 0) {
        /* Re-entrant invocation on active thread: leave headroom below caller ESP */
        cpu->gpr[NM_REG_ESP] = (cpu->gpr[NM_REG_ESP] - 64u) & ~0xFu;
    }
    dbt_ensure_thread_tls_and_stack(cpu, DBT_THREAD_STACK_SZ);
    dbt_init_cpu_fxsave(cpu);

    uint32_t sp = cpu->gpr[NM_REG_ESP];
    if (nwords > 0 && cdecl_words) {
        sp -= (uint32_t)nwords * 4u;
    }
    sp &= ~0xFu;
    /* Place return sentinel at [sp - 4], args at [sp + 0 ..] so sp-4 is final guest ESP */
    for (int i = 0; i < nwords; i++) {
        ((uint32_t *)(uintptr_t)sp)[i] = cdecl_words ? cdecl_words[i] : 0u;
    }
    sp -= 4u;
    *(uint32_t *)(uintptr_t)sp = DBT_MAGIC_RET_TO_HOST;

    cpu->gpr[NM_REG_ESP] = sp;
    cpu->eip = guest_fn_va;
    cpu->exit_reason = NM_EXIT_NONE;
    cpu->exit_arg = 0;

    int rc = dbt_run_cpu_loop(cpu, 0);

    if (out_gpr) {
        *out_gpr = ((uint64_t)cpu->gpr[NM_REG_EDX] << 32) | (uint64_t)cpu->gpr[NM_REG_EAX];
    }
    if (out_fp && sig) {
        if (sig->ret_kind == NM_RET_F64) {
            *out_fp = dbt_fxsave_pop_f64(cpu->fxsave_area);
        } else if (sig->ret_kind == NM_RET_F32) {
            *out_fp = (double)dbt_fxsave_pop_f32(cpu->fxsave_area);
        }
    }

    *cpu = saved_cpu;
    return rc;
}

uint32_t newminhh_dbt_invoke_guest(uint32_t guest_fn_va, int nargs, const uint32_t *args) {
    uint64_t res = 0;
    dbt_guest_invoker_cb(guest_fn_va, nullptr, args, nargs, &res, nullptr);
    return (uint32_t)res;
}

static int is_guest_elf_file(const char *path) {
    if (!path) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    Elf32_Ehdr eh;
    ssize_t n = read(fd, &eh, sizeof(eh));
    close(fd);
    if (n != (ssize_t)sizeof(eh)) return 0;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return 0;
    return (eh.e_ident[EI_CLASS] == ELFCLASS32 && eh.e_machine == EM_386);
}

NM_CONSTRUCTOR
static void dbt_register_backends(void) {
    nm_dl_backend_t dl_be = {
        .dlopen_fn = newminhh_dbt_dlopen,
        .dlsym_fn = newminhh_dbt_dlsym,
        .dlclose_fn = newminhh_dbt_dlclose,
        .dlerror_fn = newminhh_dbt_dlerror,
        .is_guest_elf_fn = is_guest_elf_file
    };
    newminhh_register_dl_backend(&dl_be);
    newminhh_register_guest_invoker(dbt_guest_invoker_cb);
}

static void report_unsupported_insn(uint32_t eip) {
    csh h = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &h) == CS_ERR_OK) {
        cs_insn *insn = nullptr;
        size_t n = cs_disasm(h, (const uint8_t *)(uintptr_t)eip, 15, eip, 1, &insn);
        if (n == 1) {
            char hex[64] = {0};
            size_t pos = 0;
            for (uint16_t i = 0; i < insn[0].size && pos + 4 < sizeof(hex); i++) {
                pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos, "%s%02x",
                                        i ? " " : "", insn[0].bytes[i]);
            }
            NM_LOG_ERROR("dbt",
                         "unsupported/privileged i386 instruction at guest_eip=0x%08x: '%s %s' (bytes: %s)",
                         eip, insn[0].mnemonic, insn[0].op_str, hex);
            cs_free(insn, 1);
            cs_close(&h);
            return;
        }
        cs_close(&h);
    }
    const uint8_t *raw = (const uint8_t *)(uintptr_t)eip;
    NM_LOG_ERROR("dbt", "unsupported/invalid i386 instruction at guest_eip=0x%08x (byte0=0x%02x)",
                 eip, raw[0]);
}

extern char **environ;

static int dbt_handle_compat_stub(newminhh_cpu_t *cpu, uint32_t stub_id,
                                  int *out_should_stop, int *out_exit_code) {
    *out_should_stop = 0;
    *out_exit_code = 0;

    const dbt_stub_entry_t *se = dbt_get_stub(stub_id);
    if (!se) {
        NM_LOG_ERROR("dbt", "invalid compat stub_id=%u at eip=0x%08x", stub_id, cpu->eip);
        return NM_ERR_ABI;
    }

    uint32_t *esp_ptr = (uint32_t *)(uintptr_t)cpu->gpr[NM_REG_ESP];
    uint32_t ret_eip = esp_ptr[0];
    uint32_t *cdecl_args = &esp_ptr[1];

    switch (se->kind) {
    case DBT_STUB_DLOPEN: {
        const char *fn = (const char *)(uintptr_t)cdecl_args[0];
        int flags = (int)cdecl_args[1];
        cpu->gpr[NM_REG_EAX] = dbt_guest_dlopen(fn, flags);
        break;
    }
    case DBT_STUB_DLSYM: {
        uint32_t handle = cdecl_args[0];
        const char *sym = (const char *)(uintptr_t)cdecl_args[1];
        cpu->gpr[NM_REG_EAX] = dbt_guest_dlsym(handle, sym);
        break;
    }
    case DBT_STUB_DLERROR: {
        const char *err = dbt_guest_dlerror();
        cpu->gpr[NM_REG_EAX] = (uint32_t)(uintptr_t)err;
        break;
    }
    case DBT_STUB_DLCLOSE: {
        uint32_t handle = cdecl_args[0];
        cpu->gpr[NM_REG_EAX] = (uint32_t)dbt_guest_dlclose(handle);
        break;
    }
    case DBT_STUB_LIBC_START_MAIN: {
        uint32_t main_va = cdecl_args[0];
        int argc = (int)cdecl_args[1];
        uint32_t argv_va = cdecl_args[2];
        uint32_t init_va = cdecl_args[3];
        uint32_t fini_va = cdecl_args[4];

        if (fini_va) {
            compat_atexit(fini_va);
        }
        uint32_t margs[3] = {
            (uint32_t)argc,
            argv_va,
            argv_va + (uint32_t)(argc + 1) * 4u
        };
        if (init_va) {
            newminhh_dbt_invoke_guest(init_va, 3, margs);
        }
        uint32_t ret = newminhh_dbt_invoke_guest(main_va, 3, margs);
        newminhh_run_guest_atexits();
        dbt_run_all_module_finis();
        fflush(nullptr);
        *out_should_stop = 1;
        *out_exit_code = (int)(int32_t)ret;
        return NM_OK;
    }
    case DBT_STUB_EXIT: {
        int status = (int)cdecl_args[0];
        newminhh_run_guest_atexits();
        dbt_run_all_module_finis();
        fflush(nullptr);
        exit(status);
    }
    case DBT_STUB_ATEXIT:
        cpu->gpr[NM_REG_EAX] = (uint32_t)compat_atexit(cdecl_args[0]);
        break;
    case DBT_STUB_CXA_ATEXIT:
        cpu->gpr[NM_REG_EAX] = (uint32_t)compat___cxa_atexit(
            cdecl_args[0], cdecl_args[1], cdecl_args[2]);
        break;
    case DBT_STUB_CXA_FINALIZE:
        compat___cxa_finalize(cdecl_args[0]);
        break;
    case DBT_STUB_NORMAL:
    default: {
        const nm_sym_entry_t *sym = &se->sym;
        if (sym->flags & NM_SYM_FLAG_CDECL_DIRECT) {
            typedef int (*cdecl_direct_t)(const uint32_t *);
            cdecl_direct_t fn = NM_VOIDP_TO_FN(cdecl_direct_t, sym->wrapper_fn);
            int r = fn(cdecl_args);
            cpu->gpr[NM_REG_EAX] = (uint32_t)r;
        } else {
            uint64_t fp_bits = 0;
            uint64_t r = newminhh_call_x32_sig(sym->wrapper_fn, &sym->sig, cdecl_args, &fp_bits);
            uint8_t rk = sym->sig.ret_kind;
            if (rk == NM_RET_I64 || rk == NM_RET_U64) {
                cpu->gpr[NM_REG_EAX] = (uint32_t)(r & 0xFFFFFFFFULL);
                cpu->gpr[NM_REG_EDX] = (uint32_t)(r >> 32);
            } else if (rk == NM_RET_F32) {
                float f = 0.0f;
                memcpy(&f, &fp_bits, sizeof(f));
                dbt_fxsave_push_f32(cpu->fxsave_area, f);
            } else if (rk == NM_RET_F64) {
                double d = 0.0;
                memcpy(&d, &fp_bits, sizeof(d));
                dbt_fxsave_push_f64(cpu->fxsave_area, d);
            } else if (rk != NM_RET_VOID) {
                cpu->gpr[NM_REG_EAX] = (uint32_t)r;
            }
        }
        NM_LOG_INFO("dbt", "compat stub '%s' ret=0x%08x esp=0x%08x", se->name, ret_eip, cpu->gpr[NM_REG_ESP]);
        break;
    }
    }

    cpu->gpr[NM_REG_ESP] += 4u;
    cpu->eip = ret_eip;
    return NM_OK;
}

int dbt_run_cpu_loop(newminhh_cpu_t *cpu, int allow_unregistered_va) {
    dbt_ensure_initialized();

    for (;;) {
        if (cpu->eip == DBT_MAGIC_RET_TO_HOST) {
            return NM_OK;
        }

        uint32_t stub_id = 0;
        int is_stub = dbt_is_stub_va(cpu->eip, &stub_id);
        int is_rx = is_stub ? 0 : dbt_is_guest_rx_va(cpu->eip);
        NM_LOG_INFO("dbt", "loop eip=0x%08x esp=0x%08x eax=0x%08x is_stub=%d is_rx=%d",
                    cpu->eip, cpu->gpr[NM_REG_ESP], cpu->gpr[NM_REG_EAX], is_stub, is_rx);

        if (!is_stub && !is_rx && !allow_unregistered_va) {
            if (cpu->eip < 0x1000u) {
                NM_LOG_ERROR("dbt", "invalid guest control transfer to 0x%08x", cpu->eip);
                return NM_ERR_INSN;
            }
            /* Target is outside guest RX segments & stub table -> native x32 callback */
            uint32_t *esp_ptr = (uint32_t *)(uintptr_t)cpu->gpr[NM_REG_ESP];
            uint32_t ret_eip = esp_ptr[0];
            uint32_t a0 = esp_ptr[1];
            uint32_t a1 = esp_ptr[2];
            uint32_t a2 = esp_ptr[3];
            uint32_t a3 = esp_ptr[4];
            uint32_t a4 = esp_ptr[5];
            uint32_t a5 = esp_ptr[6];
            uint64_t res = dbt_call_native_x32_6((void *)(uintptr_t)cpu->eip,
                                                 a0, a1, a2, a3, a4, a5);
            cpu->gpr[NM_REG_EAX] = (uint32_t)(res & 0xFFFFFFFFULL);
            cpu->gpr[NM_REG_EDX] = (uint32_t)(res >> 32);
            cpu->gpr[NM_REG_ESP] += 4u;
            cpu->eip = ret_eip;
            continue;
        }

        void *host_code = dbt_lookup_or_translate(cpu->eip, is_stub, stub_id);
        if (!host_code) {
            NM_LOG_ERROR("dbt", "failed to translate block at eip=0x%08x", cpu->eip);
            return NM_ERR_INSN;
        }

        cpu->exit_reason = NM_EXIT_NONE;
        cpu->exit_arg = 0;
        dbt_enter_block(cpu, host_code);
        NM_LOG_INFO("dbt", "exit reason=%u next_eip=0x%08x arg=0x%08x esp=0x%08x",
                    cpu->exit_reason, cpu->eip, cpu->exit_arg, cpu->gpr[NM_REG_ESP]);

        switch (cpu->exit_reason) {
        case NM_EXIT_NONE:
            /* Indirect branch cache miss; next loop iteration dispatches cpu->eip */
            break;

        case NM_EXIT_CHAIN_RESOLVE: {
            uint32_t patch_site_va = cpu->exit_arg;
            uint32_t target_eip = cpu->eip;
            uint32_t t_stub_id = 0;
            int t_is_stub = dbt_is_stub_va(target_eip, &t_stub_id);
            int t_is_rx = t_is_stub ? 0 : dbt_is_guest_rx_va(target_eip);
            if (t_is_stub || t_is_rx || allow_unregistered_va) {
                void *target_host = dbt_lookup_or_translate(target_eip, t_is_stub, t_stub_id);
                if (target_host && patch_site_va) {
                    uint32_t eb = (patch_site_va >> 2) & DBT_EDGE_MAP_MASK;
                    uint32_t bidx = target_eip & DBT_BLOCK_MAP_MASK;
                    pthread_mutex_lock(&g_jit_lock);
                    int target_valid = 0;
                    for (dbt_block_node_t *n = g_block_buckets[bidx]; n; n = n->next) {
                        if (n->valid && n->guest_eip == target_eip && n->host_code == target_host) {
                            target_valid = 1;
                            break;
                        }
                    }
                    if (target_valid) {
                        dbt_patched_edge_t *edge = nullptr;
                        for (dbt_patched_edge_t *it = g_edge_buckets[eb]; it; it = it->next) {
                            if (it->patch_site_va == patch_site_va) {
                                edge = it;
                                break;
                            }
                        }
                        if (!edge) {
                            edge = (dbt_patched_edge_t *)malloc(sizeof(*edge));
                            if (edge) {
                                edge->patch_site_va = patch_site_va;
                                edge->orig_stub_rel = __atomic_load_n(
                                    (int32_t *)(uintptr_t)patch_site_va, __ATOMIC_ACQUIRE);
                                edge->target_guest_eip = target_eip;
                                edge->patched = 0;
                                edge->next = g_edge_buckets[eb];
                                g_edge_buckets[eb] = edge;
                            }
                        }
                        if (edge) {
                            int32_t rel = (int32_t)((intptr_t)target_host - ((intptr_t)patch_site_va + 4));
                            edge->target_guest_eip = target_eip;
                            edge->patched = 1;
                            __atomic_store_n((int32_t *)(uintptr_t)patch_site_va, rel, __ATOMIC_RELEASE);
                        }
                    }
                    pthread_mutex_unlock(&g_jit_lock);
                }
            }
            break;
        }

        case NM_EXIT_SYSCALL: {
            uint32_t sys_nr = cpu->gpr[NM_REG_EAX];
            uint32_t s_addr = cpu->gpr[NM_REG_EBX];
            uint32_t s_len = cpu->gpr[NM_REG_ECX];
            newminhh_compat_syscall_cpu(cpu);
            if ((sys_nr == 91u || sys_nr == 125u) && s_len > 0) {
                dbt_invalidate_cache_range(s_addr, s_len);
            }
            break;
        }

        case NM_EXIT_COMPAT_CALL: {
            int should_stop = 0;
            int exit_code = 0;
            int rc = dbt_handle_compat_stub(cpu, cpu->exit_arg, &should_stop, &exit_code);
            if (rc != NM_OK) return rc;
            if (should_stop) return exit_code;
            break;
        }

        case NM_EXIT_UNSUPPORTED:
            report_unsupported_insn(cpu->eip);
            return NM_ERR_INSN;

        case NM_EXIT_RET_TO_HOST:
            return NM_OK;

        default:
            NM_LOG_ERROR("dbt", "unexpected exit_reason=%u at eip=0x%08x",
                         cpu->exit_reason, cpu->eip);
            return NM_ERR_INSN;
        }
    }
}

static int exec_loaded_main(dbt_module_t *mod, uint32_t override_va,
                            int argc, char **argv, char **envp) {
    dbt_ensure_initialized();

    newminhh_cpu_t *cpu = &tls_cpu;
    memset(cpu, 0, sizeof(*cpu));
    dbt_init_cpu_fxsave(cpu);
    cpu->eflags = 0x202u;
    cpu->gs_base = dbt_init_tls_block(mod);

    uint32_t guest_esp = 0;
    uint32_t stack_base = 0;
    uint32_t stack_sz = 0;
    int rc = dbt_setup_guest_stack(mod, argc, argv, envp, &guest_esp, &stack_base, &stack_sz);
    if (rc != NM_OK) {
        return rc;
    }
    tls_stack_base = stack_base;
    tls_stack_size = stack_sz;
    cpu->gpr[NM_REG_ESP] = guest_esp;

    /* Run DT_INIT / DT_INIT_ARRAY for deps and main executable before e_entry */
    dbt_run_module_inits(mod, argc, argv, envp);

    uint32_t start_va = override_va ? override_va : mod->entry_va;
    if (start_va == 0) {
        NM_LOG_ERROR("elf", "'%s': entry point is 0", mod->path);
        return NM_ERR_ELF;
    }
    if (override_va != 0) {
        /* Calling a specific entry/function directly: push sentinel return address */
        cpu->gpr[NM_REG_ESP] -= 4u;
        *(uint32_t *)(uintptr_t)cpu->gpr[NM_REG_ESP] = DBT_MAGIC_RET_TO_HOST;
    }
    cpu->eip = start_va;

    return dbt_run_cpu_loop(cpu, 0);
}

int newminhh_dbt_exec_file(const char *path, int argc, char **argv, char **envp) {
    dbt_ensure_initialized();
    if (!path || path[0] == '\0') {
        NM_LOG_ERROR("dbt", "exec_file: NULL or empty path");
        return NM_ERR_ELF;
    }
    dbt_module_t *mod = nullptr;
    int rc = dbt_load_main_file(path, &mod);
    if (rc != NM_OK) {
        return rc;
    }
    return exec_loaded_main(mod, 0, argc, argv, envp ? envp : environ);
}

int newminhh_dbt_exec_embedded(const void *orig_elf_blob, size_t blob_size,
                               uint32_t guest_va, int argc, char **argv, char **envp) {
    dbt_ensure_initialized();
    if (!orig_elf_blob || blob_size == 0) {
        NM_LOG_ERROR("dbt", "exec_embedded: NULL or empty ELF blob");
        return NM_ERR_ELF;
    }
    dbt_module_t *mod = nullptr;
    errno = 0;
    int rc = dbt_load_main_memory(orig_elf_blob, blob_size, "<embedded>", &mod);
    if (rc != NM_OK) {
        if (errno == EEXIST && blob_size >= sizeof(Elf32_Ehdr) &&
            ((const Elf32_Ehdr *)orig_elf_blob)->e_type == ET_EXEC) {
            NM_LOG_ERROR("dbt",
                         "exec_embedded: ET_EXEC image collided at fixed load address (EEXIST); "
                         "use newminhh_dbt_enter_at(0x%08x, cpu) for in-place patched ET_EXEC execution",
                         guest_va);
        }
        return rc;
    }
    uint32_t target_va = 0;
    if (guest_va != 0) {
        target_va = (mod->e_type == ET_EXEC) ? guest_va : (mod->load_bias + guest_va);
    }
    return exec_loaded_main(mod, target_va, argc, argv, envp ? envp : environ);
}

int newminhh_dbt_enter_at(uint32_t guest_va, newminhh_cpu_t *NM_NULLABLE_PTR cpu) {
    dbt_ensure_initialized();
    if (guest_va == 0) {
        NM_LOG_ERROR("dbt", "enter_at: NULL guest_va");
        return NM_ERR_INSN;
    }
    if (cpu != nullptr) {
        int had_esp = (cpu->gpr[NM_REG_ESP] != 0);
        dbt_ensure_thread_tls_and_stack(cpu, DBT_THREAD_STACK_SZ);
        if (!had_esp) {
            cpu->gpr[NM_REG_ESP] -= 4u;
            *(uint32_t *)(uintptr_t)cpu->gpr[NM_REG_ESP] = DBT_MAGIC_RET_TO_HOST;
        }
        cpu->eip = guest_va;
        cpu->exit_reason = NM_EXIT_NONE;
        cpu->exit_arg = 0;
        return dbt_run_cpu_loop(cpu, 1);
    }

    newminhh_cpu_t *tcpu = &tls_cpu;
    newminhh_cpu_t saved_cpu = *tcpu;
    if (tcpu->gpr[NM_REG_ESP] != 0) {
        tcpu->gpr[NM_REG_ESP] = (tcpu->gpr[NM_REG_ESP] - 64u) & ~0xFu;
    }
    dbt_ensure_thread_tls_and_stack(tcpu, DBT_THREAD_STACK_SZ);
    dbt_init_cpu_fxsave(tcpu);
    tcpu->gpr[NM_REG_ESP] -= 4u;
    *(uint32_t *)(uintptr_t)tcpu->gpr[NM_REG_ESP] = DBT_MAGIC_RET_TO_HOST;
    tcpu->eip = guest_va;
    tcpu->exit_reason = NM_EXIT_NONE;
    tcpu->exit_arg = 0;

    int rc = dbt_run_cpu_loop(tcpu, 1);
    int ret_eax = (int)(int32_t)tcpu->gpr[NM_REG_EAX];
    *tcpu = saved_cpu;
    return (rc == NM_OK) ? ret_eax : rc;
}
