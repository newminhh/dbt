#ifndef NEWMINHH_DBT_INTERNAL_H
#define NEWMINHH_DBT_INTERNAL_H

#include "../common/newminhh_abi.h"
#include "../common/newminhh_log.h"

/* Extra DBT-internal exit reasons (in addition to NM_EXIT_* in newminhh_abi.h) */
#define NM_EXIT_CHAIN_RESOLVE 16

/* Magic sentinel return address pushed onto guest stack for host->guest calls */
#define DBT_MAGIC_RET_TO_HOST 0xFFFF0000u

/* Block cache parameters */
#define DBT_FAST_CACHE_BITS   16u
#define DBT_FAST_CACHE_SIZE   (1u << DBT_FAST_CACHE_BITS)
#define DBT_FAST_CACHE_MASK   (DBT_FAST_CACHE_SIZE - 1u)

#ifndef __ASSEMBLER__

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

NM_ASSUME_NONNULL_BEGIN

/* --- Public libnewminhh_dbt.so API (PROJECT.md §4) --- */
[[nodiscard]] int newminhh_dbt_exec_file(const char *path, int argc,
                                         char *NM_NULLABLE_PTR *NM_NULLABLE_PTR argv,
                                         char *NM_NULLABLE_PTR *NM_NULLABLE_PTR envp);
[[nodiscard]] int newminhh_dbt_enter_at(uint32_t guest_va, newminhh_cpu_t *NM_NULLABLE_PTR cpu);
[[nodiscard]] int newminhh_dbt_exec_embedded(const void *orig_elf_blob, size_t blob_size,
                                             uint32_t guest_va, int argc,
                                             char *NM_NULLABLE_PTR *NM_NULLABLE_PTR argv,
                                             char *NM_NULLABLE_PTR *NM_NULLABLE_PTR envp);
[[nodiscard]] void *NM_NULLABLE_PTR newminhh_dbt_dlopen(const char *NM_NULLABLE_PTR path, int flags);
[[nodiscard]] void *NM_NULLABLE_PTR newminhh_dbt_dlsym(void *NM_NULLABLE_PTR handle, const char *sym);
int newminhh_dbt_dlclose(void *NM_NULLABLE_PTR handle);
[[nodiscard]] const char *NM_NULLABLE_PTR newminhh_dbt_dlerror(void);
uint32_t newminhh_dbt_invoke_guest(uint32_t guest_fn_va, int nargs, const uint32_t *NM_NULLABLE_PTR args);

/* --- Fast 64K indirect-branch cache entry (8 bytes for x32 ILP32) --- */
typedef union {
    struct {
        uint32_t guest_eip;
        uint32_t host_code;
    };
    alignas(8) uint64_t raw;
} dbt_fast_entry_t;

static_assert(sizeof(dbt_fast_entry_t) == 8, "dbt_fast_entry_t must be 8 bytes");
static_assert(alignof(dbt_fast_entry_t) == 8, "dbt_fast_entry_t must be 8-byte aligned");

/* --- Compat stub descriptor (0xCC 'N' 'M' <stub_id:u32>) --- */
typedef enum {
    DBT_STUB_NORMAL = 0,
    DBT_STUB_DLOPEN,
    DBT_STUB_DLSYM,
    DBT_STUB_DLERROR,
    DBT_STUB_DLCLOSE,
    DBT_STUB_LIBC_START_MAIN,
    DBT_STUB_EXIT,
    DBT_STUB_ATEXIT,
    DBT_STUB_CXA_ATEXIT,
    DBT_STUB_CXA_FINALIZE
} dbt_stub_kind_t;

typedef struct {
    char name[128];
    nm_sym_entry_t sym;
    dbt_stub_kind_t kind;
    uint32_t stub_va;
} dbt_stub_entry_t;

/* --- Guest ELF module representation --- */
#define DBT_MAX_RX_RANGES 8
#define DBT_MAX_MODULES   64
#define DBT_MAX_DEPS      32

typedef struct {
    uint32_t start;
    uint32_t end;
} dbt_va_range_t;

typedef struct dbt_module {
    _Atomic int in_use;
    int refcount;
    int unloading;
    int is_main;
    _Atomic int init_done;
    _Atomic int fini_done;
    char path[512];

    uint32_t e_type;        /* ET_EXEC / ET_DYN */
    uint32_t e_entry;
    uint32_t load_bias;
    uint32_t min_vaddr;
    uint32_t max_vaddr;
    uint32_t entry_va;

    /* Program headers (for auxv) */
    uint32_t phdr_va;
    uint16_t phent;
    uint16_t phnum;

    /* Mappings for cleanup */
    uint32_t map_base;
    uint32_t map_size;

    /* Executable guest code ranges (mapped PROT_READ only!) */
    dbt_va_range_t rx_ranges[DBT_MAX_RX_RANGES];
    _Atomic int num_rx_ranges;

    /* Dynamic linking metadata (already biased) */
    uint32_t dynamic_va;
    const char *NM_NULLABLE_PTR strtab;
    uint32_t strsz;
    const void *NM_NULLABLE_PTR symtab;     /* Elf32_Sym * */
    uint32_t nsyms;
    const uint32_t *NM_NULLABLE_PTR hash_tbl;
    const uint32_t *NM_NULLABLE_PTR gnu_hash_tbl;

    uint32_t init_va;
    uint32_t fini_va;
    uint32_t init_array_va;
    uint32_t init_array_sz;
    uint32_t fini_array_va;
    uint32_t fini_array_sz;

    /* PT_TLS */
    int has_tls;
    uint32_t tls_image_va;
    uint32_t tls_filesz;
    uint32_t tls_memsz;
    uint32_t tls_align;

    /* Guest .so dependencies */
    struct dbt_module *NM_NULLABLE_PTR deps[DBT_MAX_DEPS];
    int num_deps;
} dbt_module_t;

/* --- Shared globals & module/stub helpers (elf_loader.c) --- */
NM_PRINTF_FMT(1, 2) void dbt_set_dlerror(const char *fmt, ...);
[[nodiscard]] int dbt_is_guest_rx_va(uint32_t va);
[[nodiscard]] int dbt_is_stub_va(uint32_t va, uint32_t *NM_NULLABLE_PTR out_stub_id);
[[nodiscard]] const dbt_stub_entry_t *NM_NULLABLE_PTR dbt_get_stub(uint32_t stub_id);
[[nodiscard]] uint32_t dbt_alloc_stub_for_sym(const char *name, const nm_sym_entry_t *entry);

[[nodiscard]] int dbt_load_main_file(const char *path, dbt_module_t *NM_NULLABLE_PTR *NM_NONNULL_PTR out_mod);
[[nodiscard]] int dbt_load_main_memory(const void *blob, size_t blob_size, const char *NM_NULLABLE_PTR name,
                                       dbt_module_t *NM_NULLABLE_PTR *NM_NONNULL_PTR out_mod);
[[nodiscard]] int dbt_setup_guest_stack(dbt_module_t *NM_NULLABLE_PTR main_mod, int argc,
                                        char *NM_NULLABLE_PTR *NM_NULLABLE_PTR argv,
                                        char *NM_NULLABLE_PTR *NM_NULLABLE_PTR envp,
                                        uint32_t *out_esp,
                                        uint32_t *NM_NULLABLE_PTR out_stack_base,
                                        uint32_t *NM_NULLABLE_PTR out_stack_size);
[[nodiscard]] uint32_t dbt_init_tls_block(dbt_module_t *NM_NULLABLE_PTR mod);
void dbt_run_module_inits(dbt_module_t *NM_NULLABLE_PTR mod, int argc,
                          char *NM_NULLABLE_PTR *NM_NULLABLE_PTR argv,
                          char *NM_NULLABLE_PTR *NM_NULLABLE_PTR envp);
void dbt_run_module_finis(dbt_module_t *NM_NULLABLE_PTR mod);
void dbt_run_all_module_finis(void);

[[nodiscard]] uint32_t dbt_guest_dlopen(const char *NM_NULLABLE_PTR filename, int flags);
[[nodiscard]] uint32_t dbt_guest_dlsym(uint32_t handle, const char *symbol);
[[nodiscard]] const char *NM_NULLABLE_PTR dbt_guest_dlerror(void);
int dbt_guest_dlclose(uint32_t handle);

/* --- Engine & JIT interfaces (dbt_engine.c / dbt_x86_emitter.c) --- */
extern dbt_fast_entry_t g_dbt_fast_cache[DBT_FAST_CACHE_SIZE];

void dbt_ensure_initialized(void);
void dbt_invalidate_cache_range(uint32_t start_va, uint32_t size);
void dbt_init_cpu_fxsave(newminhh_cpu_t *cpu);
uint32_t dbt_ensure_thread_tls_and_stack(newminhh_cpu_t *cpu, uint32_t min_stack_size);
[[nodiscard]] int dbt_run_cpu_loop(newminhh_cpu_t *cpu, int allow_unregistered_va);
[[nodiscard]] void *NM_NULLABLE_PTR dbt_alloc_jit_mem(size_t size);
uint64_t dbt_segv_cb_dispatch(uint32_t slot_id,
                              const uint64_t *NM_NULLABLE_PTR gprs,
                              const uint64_t *NM_NULLABLE_PTR xmms,
                              const uint64_t *NM_NULLABLE_PTR caller_stack,
                              double *NM_NULLABLE_PTR out_fp);

[[nodiscard]] int dbt_translate_block(uint32_t guest_eip, int is_stub, uint32_t stub_id,
                                      void *NM_NULLABLE_PTR *NM_NONNULL_PTR out_host_code,
                                      uint32_t *out_guest_end,
                                      size_t *out_host_size);

/* --- Assembly trampolines (dbt_trampolines.S) --- */
void dbt_enter_block(newminhh_cpu_t *cpu, void *host_code);
void dbt_trampoline_exit(void);
void dbt_segv_cb_entry(void);
void dbt_fxsave_push_f32(void *fxsave_area, float val);
void dbt_fxsave_push_f64(void *fxsave_area, double val);
double dbt_fxsave_pop_f64(void *fxsave_area);
float dbt_fxsave_pop_f32(void *fxsave_area);
uint64_t dbt_call_native_x32_6(void *fn, uint32_t a0, uint32_t a1, uint32_t a2,
                               uint32_t a3, uint32_t a4, uint32_t a5);

NM_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif /* !__ASSEMBLER__ */

#endif /* NEWMINHH_DBT_INTERNAL_H */
