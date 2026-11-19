#define _GNU_SOURCE
#include "dbt_internal.h"

#include <asm/prctl.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef R_386_IRELATIVE
#define R_386_IRELATIVE 42
#endif
#ifndef R_386_TLS_TPOFF
#define R_386_TLS_TPOFF 14
#endif
#ifndef R_386_TLS_DTPMOD32
#define R_386_TLS_DTPMOD32 35
#endif
#ifndef R_386_TLS_DTPOFF32
#define R_386_TLS_DTPOFF32 36
#endif
#ifndef R_386_TLS_TPOFF32
#define R_386_TLS_TPOFF32 37
#endif

#define DBT_MAX_STUBS       2048
#define DBT_STUB_STRIDE     8u
#define DBT_BRK_ARENA_SIZE  (16u * 1024u * 1024u)
#define DBT_GUEST_STACK_SZ  (8u * 1024u * 1024u)
#define DBT_MAX_DL_HANDLES  128

static pthread_mutex_t g_loader_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stub_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_brk_lock = PTHREAD_MUTEX_INITIALIZER;
static dbt_module_t g_modules[DBT_MAX_MODULES];
static dbt_module_t *g_main_mod = NULL;
static uint32_t g_next_dyn_hint = 0x10000000u;

/* Guest brk arena */
static uint32_t g_brk_base = 0;
static uint32_t g_brk_cur = 0;
static uint32_t g_brk_limit = 0;

/* Synthetic compat stub arena: each stub is 8 bytes: 0xCC, 'N', 'M', 0x90, <stub_id:u32> */
static uint8_t *g_stub_arena = NULL;
static dbt_stub_entry_t g_stubs[DBT_MAX_STUBS];
static uint32_t g_num_stubs = 0;

/* Guest-side dlopen handle table */
typedef struct {
    int in_use;
    int is_native;
    void *compat_handle;
    dbt_module_t *guest_mod;
    /* Cache guest dlsym stubs for native libs */
} dbt_guest_dl_handle_t;

static dbt_guest_dl_handle_t g_guest_dl_handles[DBT_MAX_DL_HANDLES];
static __thread char tls_dbt_dlerror[512];
static __thread int tls_dbt_dlerror_pending = 0;

void dbt_set_dlerror(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tls_dbt_dlerror, sizeof(tls_dbt_dlerror), fmt, ap);
    va_end(ap);
    tls_dbt_dlerror_pending = 1;
    NM_LOG_ERROR("dbt-dl", "%s", tls_dbt_dlerror);
}

const char *newminhh_dbt_dlerror(void) {
    if (!tls_dbt_dlerror_pending) {
        return NULL;
    }
    tls_dbt_dlerror_pending = 0;
    return tls_dbt_dlerror;
}

const char *dbt_guest_dlerror(void) {
    return newminhh_dbt_dlerror();
}

static inline uint32_t page_down(uint32_t v) {
    return v & ~0xFFFu;
}

static inline uint32_t page_up(uint32_t v) {
    return (v + 0xFFFu) & ~0xFFFu;
}

static uint32_t align_up(uint32_t v, uint32_t align) {
    if (align <= 1u) return v;
    return (v + align - 1u) & ~(align - 1u);
}

static int ensure_stub_arena(void) {
    if (g_stub_arena) return 0;
    size_t sz = page_up(DBT_MAX_STUBS * DBT_STUB_STRIDE);
    void *mem = mmap((void *)0x5F000000u, sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        mem = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (mem == MAP_FAILED) {
        NM_LOG_ERROR("elf", "failed to map synthetic stub arena: errno=%d", errno);
        return -1;
    }
    g_stub_arena = (uint8_t *)mem;
    return 0;
}

static dbt_stub_kind_t classify_stub_kind(const char *name) {
    if (strcmp(name, "dlopen") == 0) return DBT_STUB_DLOPEN;
    if (strcmp(name, "dlsym") == 0) return DBT_STUB_DLSYM;
    if (strcmp(name, "dlerror") == 0) return DBT_STUB_DLERROR;
    if (strcmp(name, "dlclose") == 0) return DBT_STUB_DLCLOSE;
    if (strcmp(name, "__libc_start_main") == 0) return DBT_STUB_LIBC_START_MAIN;
    if (strcmp(name, "exit") == 0) return DBT_STUB_EXIT;
    if (strcmp(name, "atexit") == 0) return DBT_STUB_ATEXIT;
    if (strcmp(name, "__cxa_atexit") == 0) return DBT_STUB_CXA_ATEXIT;
    if (strcmp(name, "__cxa_finalize") == 0) return DBT_STUB_CXA_FINALIZE;
    return DBT_STUB_NORMAL;
}

uint32_t dbt_alloc_stub_for_sym(const char *name, const nm_sym_entry_t *entry) {
    pthread_mutex_lock(&g_stub_lock);
    if (ensure_stub_arena() != 0) {
        pthread_mutex_unlock(&g_stub_lock);
        return 0;
    }
    for (uint32_t i = 0; i < g_num_stubs; i++) {
        if (strcmp(g_stubs[i].name, name) == 0) {
            uint32_t va = g_stubs[i].stub_va;
            pthread_mutex_unlock(&g_stub_lock);
            return va;
        }
    }
    if (g_num_stubs >= DBT_MAX_STUBS) {
        pthread_mutex_unlock(&g_stub_lock);
        NM_LOG_ERROR("elf", "synthetic stub table exhausted (%u)", DBT_MAX_STUBS);
        return 0;
    }
    uint32_t id = g_num_stubs;
    uint8_t *slot = g_stub_arena + (size_t)id * DBT_STUB_STRIDE;
    slot[0] = 0xCC;
    slot[1] = 'N';
    slot[2] = 'M';
    slot[3] = 0x90;
    memcpy(slot + 4, &id, 4);

    dbt_stub_entry_t *se = &g_stubs[id];
    snprintf(se->name, sizeof(se->name), "%s", name);
    se->sym = *entry;
    se->kind = classify_stub_kind(name);
    se->stub_va = (uint32_t)(uintptr_t)slot;
    __atomic_store_n(&g_num_stubs, id + 1u, __ATOMIC_RELEASE);
    uint32_t va = se->stub_va;
    pthread_mutex_unlock(&g_stub_lock);
    return va;
}

int dbt_is_stub_va(uint32_t va, uint32_t *out_stub_id) {
    uint8_t *arena = __atomic_load_n(&g_stub_arena, __ATOMIC_ACQUIRE);
    if (!arena) return 0;
    uint32_t count = __atomic_load_n(&g_num_stubs, __ATOMIC_ACQUIRE);
    uint32_t base = (uint32_t)(uintptr_t)arena;
    uint32_t end = base + count * DBT_STUB_STRIDE;
    if (va < base || va >= end) return 0;
    uint32_t off = va - base;
    if ((off % DBT_STUB_STRIDE) != 0) return 0;
    uint32_t id = off / DBT_STUB_STRIDE;
    const uint8_t *slot = arena + off;
    if (slot[0] != 0xCC || slot[1] != 'N' || slot[2] != 'M') return 0;
    if (out_stub_id) *out_stub_id = id;
    return 1;
}

const dbt_stub_entry_t *dbt_get_stub(uint32_t stub_id) {
    uint32_t count = __atomic_load_n(&g_num_stubs, __ATOMIC_ACQUIRE);
    if (stub_id >= count) return NULL;
    return &g_stubs[stub_id];
}

int dbt_is_guest_rx_va(uint32_t va) {
    for (int i = 0; i < DBT_MAX_MODULES; i++) {
        if (!__atomic_load_n(&g_modules[i].in_use, __ATOMIC_ACQUIRE)) continue;
        int nr = __atomic_load_n(&g_modules[i].num_rx_ranges, __ATOMIC_ACQUIRE);
        for (int r = 0; r < nr; r++) {
            if (va >= g_modules[i].rx_ranges[r].start &&
                va < g_modules[i].rx_ranges[r].end) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t dbt_brk_hook(uint32_t requested_brk) {
    pthread_mutex_lock(&g_brk_lock);
    if (g_brk_base == 0) {
        pthread_mutex_unlock(&g_brk_lock);
        return 0;
    }
    if (requested_brk == 0 || requested_brk < g_brk_base || requested_brk > g_brk_limit) {
        uint32_t cur = g_brk_cur;
        pthread_mutex_unlock(&g_brk_lock);
        return cur;
    }
    uint32_t old_top = page_up(g_brk_cur);
    uint32_t new_top = page_up(requested_brk);
    if (new_top > old_top) {
        if (mprotect((void *)(uintptr_t)old_top, (size_t)(new_top - old_top),
                     PROT_READ | PROT_WRITE) != 0) {
            uint32_t cur = g_brk_cur;
            pthread_mutex_unlock(&g_brk_lock);
            return cur;
        }
    }
    g_brk_cur = requested_brk;
    uint32_t cur = g_brk_cur;
    pthread_mutex_unlock(&g_brk_lock);
    return cur;
}

static void init_brk_arena(uint32_t map_base, uint32_t map_size) {
    uint32_t brk_hint = page_up(map_base + map_size);
    pthread_mutex_lock(&g_brk_lock);
    if (g_brk_base != 0) {
        munmap((void *)(uintptr_t)g_brk_base, DBT_BRK_ARENA_SIZE);
        g_brk_base = 0;
        g_brk_cur = 0;
        g_brk_limit = 0;
    }
    void *brk_mem = mmap((void *)(uintptr_t)brk_hint, DBT_BRK_ARENA_SIZE, PROT_NONE,
                         MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (brk_mem == MAP_FAILED) {
        brk_mem = mmap((void *)(uintptr_t)0x30000000u, DBT_BRK_ARENA_SIZE, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (brk_mem != MAP_FAILED) {
        g_brk_base = (uint32_t)(uintptr_t)brk_mem;
        g_brk_cur = g_brk_base;
        g_brk_limit = g_brk_base + DBT_BRK_ARENA_SIZE;
    }
    int ok = (g_brk_base != 0);
    pthread_mutex_unlock(&g_brk_lock);
    if (ok) {
        newminhh_register_brk_hook(dbt_brk_hook);
    }
}

static void cleanup_brk_arena(void) {
    pthread_mutex_lock(&g_brk_lock);
    if (g_brk_base != 0) {
        munmap((void *)(uintptr_t)g_brk_base, DBT_BRK_ARENA_SIZE);
        g_brk_base = 0;
        g_brk_cur = 0;
        g_brk_limit = 0;
    }
    pthread_mutex_unlock(&g_brk_lock);
}

static int is_canonical_system_lib(const char *name) {
    if (!name) return 0;
    const char *base = strrchr(name, '/');
    base = base ? (base + 1) : name;
    static const char *const sys_libs[] = {
        "libc.so.6", "libc.so",
        "libm.so.6", "libm.so",
        "libpthread.so.0", "libpthread.so",
        "libdl.so.2", "libdl.so",
        "librt.so.1", "librt.so",
        "libgcc_s.so.1",
        "libstdc++.so.6",
        "ld-linux.so.2"
    };
    for (size_t i = 0; i < sizeof(sys_libs) / sizeof(sys_libs[0]); i++) {
        if (strcmp(base, sys_libs[i]) == 0) return 1;
    }
    return 0;
}

static int strip_sym_ver(const char *name, char *out, size_t out_sz) {
    const char *at = strchr(name, '@');
    size_t len = at ? (size_t)(at - name) : strlen(name);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, name, len);
    out[len] = '\0';
    return 0;
}

static int va_in_phdrs(const Elf32_Phdr *phdrs, uint16_t phnum, uint32_t raw_va, uint32_t size) {
    uint64_t end = (uint64_t)raw_va + (uint64_t)size;
    if (end > 0xFFFFFFFFULL) return 0;
    for (uint16_t i = 0; i < phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t s = phdrs[i].p_vaddr;
        uint64_t e = s + phdrs[i].p_memsz;
        if ((uint64_t)raw_va >= s && end <= e) {
            return 1;
        }
    }
    return 0;
}

static uint32_t compute_gnu_hash_nsyms(const uint32_t *gh, const Elf32_Phdr *phdrs,
                                       uint16_t phnum, uint32_t gh_raw_va) {
    if (!va_in_phdrs(phdrs, phnum, gh_raw_va, 16)) return 0;
    uint32_t nbuckets = gh[0];
    uint32_t symbias = gh[1];
    uint32_t bloom_size = gh[2];
    if (nbuckets == 0 || nbuckets > 65536u || bloom_size == 0 || bloom_size > 65536u) {
        return 0;
    }
    uint64_t buckets_off = 16ULL + (uint64_t)bloom_size * 4ULL;
    uint64_t chains_off = buckets_off + (uint64_t)nbuckets * 4ULL;
    if (chains_off > 0x1000000ULL ||
        !va_in_phdrs(phdrs, phnum, gh_raw_va, (uint32_t)chains_off)) {
        return 0;
    }
    const uint32_t *buckets = gh + 4 + bloom_size;
    const uint32_t *chains = buckets + nbuckets;
    uint32_t max_sym = symbias > 0 ? symbias - 1u : 0;
    for (uint32_t b = 0; b < nbuckets; b++) {
        uint32_t idx = buckets[b];
        if (idx < symbias) continue;
        while (1) {
            uint64_t elem_va = (uint64_t)gh_raw_va + chains_off + (uint64_t)(idx - symbias) * 4ULL;
            if (elem_va > 0xFFFFFFFFULL || !va_in_phdrs(phdrs, phnum, (uint32_t)elem_va, 4)) {
                return 0;
            }
            if (idx > max_sym) max_sym = idx;
            uint32_t ch = chains[idx - symbias];
            if (ch & 1u) break;
            idx++;
            if (idx > 1000000u) return 0;
        }
    }
    return max_sym + 1u;
}

static uint32_t elf_sysv_hash(const char *s) {
    uint32_t h = 0, g;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (h << 4) + *p;
        g = h & 0xF0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uint32_t elf_gnu_hash(const char *s) {
    uint32_t h = 5381u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (h << 5) + h + *p;
    }
    return h;
}

static int lookup_in_module(const dbt_module_t *mod, const char *name,
                            uint32_t *out_va, uint32_t *out_size) {
    if (!mod || !mod->in_use || !mod->symtab || !mod->strtab || mod->nsyms == 0) {
        return 0;
    }
    const Elf32_Sym *syms = (const Elf32_Sym *)mod->symtab;

    if (mod->gnu_hash_tbl) {
        const uint32_t *gh = mod->gnu_hash_tbl;
        uint32_t nbuckets = gh[0];
        uint32_t symbias = gh[1];
        uint32_t bloom_size = gh[2];
        const uint32_t *buckets = gh + 4 + bloom_size;
        const uint32_t *chains = buckets + nbuckets;
        uint32_t h = elf_gnu_hash(name);
        uint32_t idx = buckets[h % nbuckets];
        if (idx >= symbias) {
            while (idx < mod->nsyms) {
                uint32_t ch = chains[idx - symbias];
                if (((ch ^ h) & ~1u) == 0) {
                    const Elf32_Sym *s = &syms[idx];
                    if (s->st_name < mod->strsz &&
                        s->st_shndx != SHN_UNDEF &&
                        ELF32_ST_BIND(s->st_info) != STB_LOCAL &&
                        strcmp(mod->strtab + s->st_name, name) == 0) {
                        *out_va = mod->load_bias + s->st_value;
                        if (out_size) *out_size = s->st_size;
                        return 1;
                    }
                }
                if (ch & 1u) break;
                idx++;
            }
        }
        return 0;
    }

    if (mod->hash_tbl) {
        uint32_t nbucket = mod->hash_tbl[0];
        uint32_t nchain = mod->hash_tbl[1];
        const uint32_t *buckets = mod->hash_tbl + 2;
        const uint32_t *chains = buckets + nbucket;
        uint32_t h = elf_sysv_hash(name);
        for (uint32_t idx = buckets[h % nbucket]; idx != 0 && idx < nchain && idx < mod->nsyms; idx = chains[idx]) {
            const Elf32_Sym *s = &syms[idx];
            if (s->st_name < mod->strsz &&
                s->st_shndx != SHN_UNDEF &&
                ELF32_ST_BIND(s->st_info) != STB_LOCAL &&
                strcmp(mod->strtab + s->st_name, name) == 0) {
                *out_va = mod->load_bias + s->st_value;
                if (out_size) *out_size = s->st_size;
                return 1;
            }
        }
        return 0;
    }

    for (uint32_t i = 1; i < mod->nsyms; i++) {
        const Elf32_Sym *s = &syms[i];
        if (s->st_name < mod->strsz &&
            s->st_shndx != SHN_UNDEF &&
            ELF32_ST_BIND(s->st_info) != STB_LOCAL &&
            strcmp(mod->strtab + s->st_name, name) == 0) {
            *out_va = mod->load_bias + s->st_value;
            if (out_size) *out_size = s->st_size;
            return 1;
        }
    }
    return 0;
}

static int resolve_guest_symbol_global(const char *raw_name, const dbt_module_t *skip_mod,
                                       uint32_t *out_va, uint32_t *out_size) {
    char clean[256];
    strip_sym_ver(raw_name, clean, sizeof(clean));
    for (int i = 0; i < DBT_MAX_MODULES; i++) {
        if (!g_modules[i].in_use || g_modules[i].unloading) continue;
        if (&g_modules[i] == skip_mod) continue;
        if (lookup_in_module(&g_modules[i], clean, out_va, out_size)) {
            return 1;
        }
    }
    return 0;
}

static int load_guest_blob(const uint8_t *blob, size_t blob_size, const char *path,
                           int is_main, dbt_module_t **out_mod);

static dbt_module_t *find_loaded_module_by_name(const char *path) {
    const char *base = strrchr(path, '/');
    base = base ? (base + 1) : path;
    for (int i = 0; i < DBT_MAX_MODULES; i++) {
        if (!g_modules[i].in_use || g_modules[i].unloading) continue;
        const char *mbase = strrchr(g_modules[i].path, '/');
        mbase = mbase ? (mbase + 1) : g_modules[i].path;
        if (strcmp(g_modules[i].path, path) == 0 || strcmp(mbase, base) == 0) {
            return &g_modules[i];
        }
    }
    return NULL;
}

static int find_so_path(const char *soname, const char *requester_path, char *out_path, size_t out_sz) {
    if (strchr(soname, '/')) {
        if (access(soname, R_OK) == 0) {
            snprintf(out_path, out_sz, "%s", soname);
            return 0;
        }
        return -1;
    }
    if (requester_path && requester_path[0]) {
        char req_copy[512];
        snprintf(req_copy, sizeof(req_copy), "%s", requester_path);
        const char *dir = dirname(req_copy);
        snprintf(out_path, out_sz, "%s/%s", dir, soname);
        if (access(out_path, R_OK) == 0) return 0;
    }
    const char *ld_path = getenv("LD_LIBRARY_PATH");
    if (ld_path) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", ld_path);
        char *save = NULL;
        for (char *tok = strtok_r(buf, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
            snprintf(out_path, out_sz, "%s/%s", tok, soname);
            if (access(out_path, R_OK) == 0) return 0;
        }
    }
    snprintf(out_path, out_sz, "./%s", soname);
    if (access(out_path, R_OK) == 0) return 0;
    return -1;
}

static int read_entire_file(const char *path, uint8_t **out_buf, size_t *out_sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        NM_LOG_ERROR("elf", "cannot open '%s': %s", path, strerror(errno));
        return NM_ERR_ELF;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        NM_LOG_ERROR("elf", "fstat('%s') failed: %s", path, strerror(errno));
        return NM_ERR_ELF;
    }
    if (st.st_size <= 0 || st.st_size > 256LL * 1024LL * 1024LL) {
        close(fd);
        NM_LOG_ERROR("elf", "invalid ELF file size (%lld) for '%s'",
                     (long long)st.st_size, path);
        return NM_ERR_ELF;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) {
        close(fd);
        return NM_ERR_ELF;
    }
    size_t off = 0;
    while (off < sz) {
        ssize_t n = read(fd, buf + off, sz - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NM_ERR_ELF;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    if (off != sz) {
        free(buf);
        NM_LOG_ERROR("elf", "short read on '%s' (%zu / %zu)", path, off, sz);
        return NM_ERR_ELF;
    }
    *out_buf = buf;
    *out_sz = sz;
    return NM_OK;
}

static int apply_reloc_table(dbt_module_t *mod, const void *tbl_ptr, uint32_t tbl_sz,
                             int is_rela, const Elf32_Phdr *phdrs, uint16_t phnum) {
    uint32_t ent_sz = is_rela ? sizeof(Elf32_Rela) : sizeof(Elf32_Rel);
    if (tbl_sz % ent_sz != 0) {
        NM_LOG_ERROR("elf", "misaligned relocation table size %u in '%s'", tbl_sz, mod->path);
        return NM_ERR_ELF;
    }
    uint32_t count = tbl_sz / ent_sz;
    const Elf32_Sym *syms = (const Elf32_Sym *)mod->symtab;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t r_offset, r_info;
        int32_t r_addend = 0;
        if (is_rela) {
            const Elf32_Rela *r = &((const Elf32_Rela *)tbl_ptr)[i];
            r_offset = r->r_offset;
            r_info = r->r_info;
            r_addend = r->r_addend;
        } else {
            const Elf32_Rel *r = &((const Elf32_Rel *)tbl_ptr)[i];
            r_offset = r->r_offset;
            r_info = r->r_info;
        }
        uint32_t type = ELF32_R_TYPE(r_info);
        uint32_t sym_idx = ELF32_R_SYM(r_info);

        if (type == R_386_NONE) continue;
        if (!va_in_phdrs(phdrs, phnum, r_offset, 4)) {
            NM_LOG_ERROR("elf", "relocation offset 0x%08x out of segment bounds in '%s'",
                         r_offset, mod->path);
            return NM_ERR_ELF;
        }
        uint32_t P_va = mod->load_bias + r_offset;
        uint32_t *P = (uint32_t *)(uintptr_t)P_va;
        uint32_t A = is_rela ? (uint32_t)r_addend : *P;

        if (type == R_386_RELATIVE) {
            *P = mod->load_bias + A;
            continue;
        }
        if (type == R_386_IRELATIVE) {
            uint32_t resolver_va = mod->load_bias + A;
            *P = newminhh_dbt_invoke_guest(resolver_va, 0, NULL);
            continue;
        }
        if (type == R_386_TLS_DTPMOD32) {
            *P = 1u;
            continue;
        }
        if (type == R_386_TLS_DTPOFF32 || type == R_386_TLS_TPOFF || type == R_386_TLS_TPOFF32) {
            if (sym_idx >= mod->nsyms) {
                NM_LOG_ERROR("elf", "TLS reloc sym_idx=%u out of bounds (%u) in '%s'",
                             sym_idx, mod->nsyms, mod->path);
                return NM_ERR_ELF;
            }
            const Elf32_Sym *sym = &syms[sym_idx];
            uint32_t tls_sz = mod->has_tls ? align_up(mod->tls_memsz, mod->tls_align ? mod->tls_align : 4) : 0;
            if (type == R_386_TLS_DTPOFF32) {
                *P = sym->st_value;
            } else if (type == R_386_TLS_TPOFF) {
                *P = (uint32_t)(-(int32_t)tls_sz + (int32_t)sym->st_value) + A;
            } else {
                *P = (uint32_t)((int32_t)tls_sz - (int32_t)sym->st_value) + A;
            }
            continue;
        }

        if (sym_idx >= mod->nsyms || !syms || !mod->strtab) {
            NM_LOG_ERROR("elf", "reloc sym_idx=%u >= nsyms=%u in '%s'",
                         sym_idx, mod->nsyms, mod->path);
            return NM_ERR_ELF;
        }
        const Elf32_Sym *sym = &syms[sym_idx];
        if (sym->st_name >= mod->strsz) {
            NM_LOG_ERROR("elf", "reloc st_name=%u >= strsz=%u in '%s'",
                         sym->st_name, mod->strsz, mod->path);
            return NM_ERR_ELF;
        }
        const char *raw_name = mod->strtab + sym->st_name;
        char clean_name[256];
        strip_sym_ver(raw_name, clean_name, sizeof(clean_name));
        uint8_t bind = ELF32_ST_BIND(sym->st_info);

        /* Resolve target S */
        uint32_t S = 0;
        uint32_t S_size = 0;
        int resolved = 0;
        int is_compat_data = 0;
        void *compat_data_ptr = NULL;

        if (sym_idx == 0) {
            resolved = 1;
            S = 0;
        } else if (type == R_386_COPY) {
            /* R_386_COPY must look in dependencies / compat, NOT self */
            if (resolve_guest_symbol_global(clean_name, mod, &S, &S_size)) {
                resolved = 1;
            } else {
                nm_sym_entry_t ce;
                if (newminhh_compat_lookup_wrapper(clean_name, &ce) == NM_OK &&
                    (ce.flags & NM_SYM_FLAG_DATA)) {
                    resolved = 1;
                    is_compat_data = 1;
                    compat_data_ptr = ce.wrapper_fn;
                    /* Ensure stdio globals are initialized */
                    FILE *fi = NULL, *fo = NULL, *fe = NULL;
                    newminhh_get_stdio_streams(&fi, &fo, &fe);
                }
            }
        } else {
            /* Prefer local/self definition if defined, else global guest modules, else compat */
            if (sym->st_shndx != SHN_UNDEF) {
                S = mod->load_bias + sym->st_value;
                S_size = sym->st_size;
                resolved = 1;
            } else if (resolve_guest_symbol_global(clean_name, NULL, &S, &S_size)) {
                resolved = 1;
            } else if (bind == STB_WEAK &&
                       (strcmp(clean_name, "_ITM_deregisterTMCloneTable") == 0 ||
                        strcmp(clean_name, "_ITM_registerTMCloneTable") == 0 ||
                        strcmp(clean_name, "__gmon_start__") == 0 ||
                        strcmp(clean_name, "_Jv_RegisterClasses") == 0)) {
                resolved = 1;
                S = 0;
            } else {
                nm_sym_entry_t ce;
                if (newminhh_compat_lookup_wrapper(clean_name, &ce) == NM_OK) {
                    resolved = 1;
                    if (ce.flags & NM_SYM_FLAG_DATA) {
                        S = (uint32_t)(uintptr_t)ce.wrapper_fn;
                        FILE *fi = NULL, *fo = NULL, *fe = NULL;
                        newminhh_get_stdio_streams(&fi, &fo, &fe);
                    } else {
                        S = dbt_alloc_stub_for_sym(clean_name, &ce);
                        if (S == 0) return NM_ERR_DLSYM;
                    }
                }
            }
        }

        if (!resolved) {
            if (bind == STB_WEAK) {
                S = 0;
            } else {
                NM_LOG_ERROR("elf", "undefined strong external symbol '%s' in '%s'",
                             clean_name, mod->path);
                dbt_set_dlerror("undefined strong external symbol '%s' in '%s'",
                                clean_name, mod->path);
                return NM_ERR_DLSYM;
            }
        }

        switch (type) {
        case R_386_32:
            *P = S + A;
            break;
        case R_386_PC32:
            *P = S + A - P_va;
            break;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
            *P = S;
            break;
        case R_386_COPY:
            if (sym->st_size > 0) {
                const void *src = is_compat_data ? compat_data_ptr : (const void *)(uintptr_t)S;
                if (!src) {
                    NM_LOG_ERROR("elf", "R_386_COPY NULL source for '%s' in '%s'",
                                 clean_name, mod->path);
                    return NM_ERR_DLSYM;
                }
                memcpy(P, src, (size_t)sym->st_size);
            }
            break;
        default:
            NM_LOG_ERROR("elf", "unsupported relocation type %u for '%s' in '%s'",
                         type, clean_name, mod->path);
            return NM_ERR_ELF;
        }
    }
    return NM_OK;
}

static int load_guest_blob(const uint8_t *blob, size_t blob_size, const char *path,
                           int is_main, dbt_module_t **out_mod) {
    if (!blob || blob_size < sizeof(Elf32_Ehdr)) {
        NM_LOG_ERROR("elf", "'%s': file truncated (%zu bytes < Elf32_Ehdr %zu bytes)",
                     path, blob_size, sizeof(Elf32_Ehdr));
        return NM_ERR_ELF;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)blob;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        NM_LOG_ERROR("elf", "'%s': invalid ELF magic bytes", path);
        return NM_ERR_ELF;
    }
    if (eh->e_ident[EI_CLASS] != ELFCLASS32) {
        NM_LOG_ERROR("elf", "'%s': expected ELFCLASS32 (got %u)", path, eh->e_ident[EI_CLASS]);
        return NM_ERR_ELF;
    }
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB || eh->e_ident[EI_VERSION] != EV_CURRENT) {
        NM_LOG_ERROR("elf", "'%s': unsupported ELF data encoding/version", path);
        return NM_ERR_ELF;
    }
    if (eh->e_machine != EM_386) {
        NM_LOG_ERROR("elf", "'%s': expected EM_386 (%u), got e_machine=%u",
                     path, EM_386, eh->e_machine);
        return NM_ERR_ELF;
    }
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
        NM_LOG_ERROR("elf", "'%s': unsupported e_type=%u (expected ET_EXEC or ET_DYN)",
                     path, eh->e_type);
        return NM_ERR_ELF;
    }
    if (eh->e_phentsize != sizeof(Elf32_Phdr) || eh->e_phnum == 0 || eh->e_phnum > 1024) {
        NM_LOG_ERROR("elf", "'%s': invalid program header table (phentsize=%u phnum=%u)",
                     path, eh->e_phentsize, eh->e_phnum);
        return NM_ERR_ELF;
    }
    uint64_t ph_end = (uint64_t)eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf32_Phdr);
    if (eh->e_phoff > blob_size || ph_end > blob_size) {
        NM_LOG_ERROR("elf", "'%s': program header table out of file bounds", path);
        return NM_ERR_ELF;
    }

    const Elf32_Phdr *phdrs = (const Elf32_Phdr *)(blob + eh->e_phoff);
    int has_load = 0;
    uint32_t min_vaddr = 0xFFFFFFFFu;
    uint32_t max_vaddr = 0u;
    const Elf32_Phdr *dyn_ph = NULL;
    const Elf32_Phdr *tls_ph = NULL;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf32_Phdr *ph = &phdrs[i];
        if (ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC ||
            ph->p_type == PT_TLS || ph->p_type == PT_INTERP) {
            if ((uint64_t)ph->p_offset > blob_size ||
                (uint64_t)ph->p_offset + (uint64_t)ph->p_filesz > blob_size) {
                NM_LOG_ERROR("elf", "'%s': phdr[%u] (type=%u) p_offset/p_filesz out of bounds",
                             path, i, ph->p_type);
                return NM_ERR_ELF;
            }
            if ((ph->p_type == PT_LOAD || ph->p_type == PT_TLS) && ph->p_filesz > ph->p_memsz) {
                NM_LOG_ERROR("elf", "'%s': phdr[%u] p_filesz (%u) > p_memsz (%u)",
                             path, i, ph->p_filesz, ph->p_memsz);
                return NM_ERR_ELF;
            }
            if ((uint64_t)ph->p_vaddr + (uint64_t)ph->p_memsz > 0xFFFFFFFFULL) {
                NM_LOG_ERROR("elf", "'%s': phdr[%u] overflows 32-bit address space", path, i);
                return NM_ERR_ELF;
            }
        }
        if (ph->p_type == PT_LOAD) {
            if (ph->p_memsz == 0) continue;
            has_load = 1;
            uint32_t s = page_down(ph->p_vaddr);
            uint32_t e = page_up(ph->p_vaddr + ph->p_memsz);
            if (s < min_vaddr) min_vaddr = s;
            if (e > max_vaddr) max_vaddr = e;
        } else if (ph->p_type == PT_DYNAMIC) {
            dyn_ph = ph;
        } else if (ph->p_type == PT_TLS) {
            tls_ph = ph;
        }
    }

    if (!has_load || max_vaddr <= min_vaddr) {
        NM_LOG_ERROR("elf", "'%s': no valid PT_LOAD segments", path);
        return NM_ERR_ELF;
    }

    if (eh->e_type == ET_EXEC && is_main && eh->e_entry != 0) {
        if (!va_in_phdrs(phdrs, eh->e_phnum, eh->e_entry, 1)) {
            NM_LOG_ERROR("elf", "'%s': ET_EXEC e_entry=0x%08x not in any PT_LOAD segment",
                         path, eh->e_entry);
            return NM_ERR_ELF;
        }
    }

    /* Validate PT_DYNAMIC before mapping */
    if (dyn_ph) {
        if (!va_in_phdrs(phdrs, eh->e_phnum, dyn_ph->p_vaddr, dyn_ph->p_memsz) ||
            dyn_ph->p_filesz < sizeof(Elf32_Dyn)) {
            NM_LOG_ERROR("elf", "'%s': PT_DYNAMIC out of PT_LOAD bounds", path);
            return NM_ERR_ELF;
        }
    }

    /* Allocate module slot */
    int slot = -1;
    for (int i = 0; i < DBT_MAX_MODULES; i++) {
        if (!g_modules[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        NM_LOG_ERROR("elf", "module table full (%d)", DBT_MAX_MODULES);
        return NM_ERR_ELF;
    }

    uint32_t span = max_vaddr - min_vaddr;
    void *mapped = MAP_FAILED;
    uint32_t load_bias = 0;

    if (eh->e_type == ET_EXEC) {
        mapped = mmap((void *)(uintptr_t)min_vaddr, span, PROT_READ | PROT_WRITE,
                      MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapped == MAP_FAILED) {
            int saved_errno = errno;
            if (saved_errno == EEXIST) {
                NM_LOG_ERROR("elf",
                             "'%s': ET_EXEC fixed mapping 0x%08x..0x%08x collides with existing mapping (EEXIST); "
                             "use newminhh_dbt_enter_at() for in-place execution",
                             path, min_vaddr, max_vaddr);
            } else {
                NM_LOG_ERROR("elf", "'%s': failed to map ET_EXEC at 0x%08x..0x%08x: %s",
                             path, min_vaddr, max_vaddr, strerror(saved_errno));
            }
            errno = saved_errno;
            return NM_ERR_ELF;
        }
        load_bias = 0;
    } else {
        uint32_t hint = g_next_dyn_hint;
        for (int attempt = 0; attempt < 32; attempt++) {
            if (hint + span >= 0x5E000000u) {
                NM_LOG_ERROR("elf", "'%s': no virtual space below 0x60000000 for ET_DYN", path);
                return NM_ERR_ELF;
            }
            mapped = mmap((void *)(uintptr_t)hint, span, PROT_READ | PROT_WRITE,
                          MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mapped != MAP_FAILED) {
                g_next_dyn_hint = page_up(hint + span + 0x10000u);
                break;
            }
            hint += 0x100000u;
        }
        if (mapped == MAP_FAILED) {
            mapped = mmap((void *)(uintptr_t)0x20000000u, span, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
        if (mapped == MAP_FAILED || (uintptr_t)mapped + span >= 0x60000000ULL) {
            if (mapped != MAP_FAILED) munmap(mapped, span);
            NM_LOG_ERROR("elf", "'%s': ET_DYN mapping failed below 0x60000000", path);
            return NM_ERR_ELF;
        }
        load_bias = (uint32_t)(uintptr_t)mapped - min_vaddr;
    }

    dbt_module_t *mod = &g_modules[slot];
    memset(mod, 0, sizeof(*mod));
    mod->refcount = 1;
    mod->is_main = is_main;
    snprintf(mod->path, sizeof(mod->path), "%s", path);
    mod->e_type = eh->e_type;
    mod->e_entry = eh->e_entry;
    mod->load_bias = load_bias;
    mod->min_vaddr = min_vaddr;
    mod->max_vaddr = max_vaddr;
    mod->entry_va = eh->e_entry ? (load_bias + eh->e_entry) : 0;
    mod->phent = eh->e_phentsize;
    mod->phnum = eh->e_phnum;
    mod->map_base = (uint32_t)(uintptr_t)mapped;
    mod->map_size = span;
    mod->phdr_va = load_bias + min_vaddr + eh->e_phoff;

    /* Copy PT_LOAD segments & record RX ranges */
    int num_rx = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf32_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;
        if (ph->p_filesz > 0) {
            memcpy((void *)(uintptr_t)(load_bias + ph->p_vaddr),
                   blob + ph->p_offset, ph->p_filesz);
        }
        if (eh->e_phoff >= ph->p_offset &&
            eh->e_phoff + (uint32_t)eh->e_phnum * sizeof(Elf32_Phdr) <= ph->p_offset + ph->p_filesz) {
            mod->phdr_va = load_bias + ph->p_vaddr + (eh->e_phoff - ph->p_offset);
        }
        if (ph->p_flags & PF_X) {
            if (num_rx < DBT_MAX_RX_RANGES) {
                mod->rx_ranges[num_rx].start = load_bias + ph->p_vaddr;
                mod->rx_ranges[num_rx].end = load_bias + ph->p_vaddr + ph->p_memsz;
                num_rx++;
            }
        }
    }
    __atomic_store_n(&mod->num_rx_ranges, num_rx, __ATOMIC_RELEASE);
    __atomic_store_n(&mod->in_use, 1, __ATOMIC_RELEASE);

    if (tls_ph && tls_ph->p_memsz > 0) {
        mod->has_tls = 1;
        mod->tls_image_va = load_bias + tls_ph->p_vaddr;
        mod->tls_filesz = tls_ph->p_filesz;
        mod->tls_memsz = tls_ph->p_memsz;
        mod->tls_align = tls_ph->p_align ? tls_ph->p_align : 4u;
    }

    /* Setup isolated guest brk arena for main executable */
    if (is_main) {
        init_brk_arena(mod->map_base, mod->map_size);
        g_main_mod = mod;
    }

    /* Parse & strictly validate PT_DYNAMIC */
    if (dyn_ph) {
        mod->dynamic_va = load_bias + dyn_ph->p_vaddr;
        const Elf32_Dyn *dyn = (const Elf32_Dyn *)(uintptr_t)mod->dynamic_va;
        uint32_t max_dyn = dyn_ph->p_memsz / sizeof(Elf32_Dyn);

        uint32_t strtab_raw = 0, strsz = 0;
        uint32_t symtab_raw = 0, syment = sizeof(Elf32_Sym);
        uint32_t hash_raw = 0, gnu_hash_raw = 0;
        uint32_t rel_raw = 0, relsz = 0, relent = sizeof(Elf32_Rel);
        uint32_t rela_raw = 0, relasz = 0, relaent = sizeof(Elf32_Rela);
        uint32_t jmprel_raw = 0, pltrelsz = 0, pltrel = DT_REL;
        uint32_t init_raw = 0, fini_raw = 0;
        uint32_t init_arr_raw = 0, init_arr_sz = 0;
        uint32_t fini_arr_raw = 0, fini_arr_sz = 0;
        uint32_t needed_offs[DBT_MAX_DEPS];
        int num_needed = 0;

        for (uint32_t i = 0; i < max_dyn; i++) {
            int32_t tag = dyn[i].d_tag;
            uint32_t val = dyn[i].d_un.d_val;
            if (tag == DT_NULL) break;
            switch (tag) {
            case DT_NEEDED:
                if (num_needed < DBT_MAX_DEPS) needed_offs[num_needed++] = val;
                break;
            case DT_STRTAB:     strtab_raw = val; break;
            case DT_STRSZ:      strsz = val; break;
            case DT_SYMTAB:     symtab_raw = val; break;
            case DT_SYMENT:     syment = val; break;
            case DT_HASH:       hash_raw = val; break;
            case DT_GNU_HASH:   gnu_hash_raw = val; break;
            case DT_REL:        rel_raw = val; break;
            case DT_RELSZ:      relsz = val; break;
            case DT_RELENT:     relent = val; break;
            case DT_RELA:       rela_raw = val; break;
            case DT_RELASZ:     relasz = val; break;
            case DT_RELAENT:    relaent = val; break;
            case DT_JMPREL:     jmprel_raw = val; break;
            case DT_PLTRELSZ:   pltrelsz = val; break;
            case DT_PLTREL:     pltrel = val; break;
            case DT_INIT:       init_raw = val; break;
            case DT_FINI:       fini_raw = val; break;
            case DT_INIT_ARRAY: init_arr_raw = val; break;
            case DT_INIT_ARRAYSZ: init_arr_sz = val; break;
            case DT_FINI_ARRAY: fini_arr_raw = val; break;
            case DT_FINI_ARRAYSZ: fini_arr_sz = val; break;
            default: break;
            }
        }

        if (syment != sizeof(Elf32_Sym) || relent != sizeof(Elf32_Rel) ||
            relaent != sizeof(Elf32_Rela)) {
            NM_LOG_ERROR("elf", "'%s': corrupt PT_DYNAMIC entry sizes (syment=%u relent=%u relaent=%u)",
                         path, syment, relent, relaent);
            goto fail_cleanup;
        }
        if (strtab_raw != 0) {
            if (strsz == 0 || !va_in_phdrs(phdrs, eh->e_phnum, strtab_raw, strsz)) {
                NM_LOG_ERROR("elf", "'%s': corrupt DT_STRTAB=0x%08x (strsz=%u) out of segment bounds",
                             path, strtab_raw, strsz);
                goto fail_cleanup;
            }
            mod->strtab = (const char *)(uintptr_t)(load_bias + strtab_raw);
            mod->strsz = strsz;
        }
        if (symtab_raw != 0) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, symtab_raw, sizeof(Elf32_Sym))) {
                NM_LOG_ERROR("elf", "'%s': corrupt DT_SYMTAB=0x%08x out of segment bounds",
                             path, symtab_raw);
                goto fail_cleanup;
            }
            mod->symtab = (const void *)(uintptr_t)(load_bias + symtab_raw);
        }
        if (hash_raw != 0) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, hash_raw, 8)) {
                NM_LOG_ERROR("elf", "'%s': corrupt DT_HASH=0x%08x out of segment bounds",
                             path, hash_raw);
                goto fail_cleanup;
            }
            mod->hash_tbl = (const uint32_t *)(uintptr_t)(load_bias + hash_raw);
            mod->nsyms = mod->hash_tbl[1];
        }
        if (gnu_hash_raw != 0) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, gnu_hash_raw, 16)) {
                NM_LOG_ERROR("elf", "'%s': corrupt DT_GNU_HASH=0x%08x out of segment bounds",
                             path, gnu_hash_raw);
                goto fail_cleanup;
            }
            mod->gnu_hash_tbl = (const uint32_t *)(uintptr_t)(load_bias + gnu_hash_raw);
            if (mod->nsyms == 0) {
                mod->nsyms = compute_gnu_hash_nsyms(mod->gnu_hash_tbl, phdrs, eh->e_phnum, gnu_hash_raw);
                if (mod->nsyms == 0) {
                    NM_LOG_ERROR("elf", "'%s': invalid DT_GNU_HASH table at 0x%08x", path, gnu_hash_raw);
                    goto fail_cleanup;
                }
            }
        }
        if (mod->symtab && mod->nsyms > 0) {
            uint64_t sym_bytes = (uint64_t)mod->nsyms * sizeof(Elf32_Sym);
            if (sym_bytes > 0xFFFFFFFFULL ||
                !va_in_phdrs(phdrs, eh->e_phnum, symtab_raw, (uint32_t)sym_bytes)) {
                NM_LOG_ERROR("elf", "'%s': DT_SYMTAB range (nsyms=%u) out of bounds",
                             path, mod->nsyms);
                goto fail_cleanup;
            }
        }

        if (rel_raw && (!va_in_phdrs(phdrs, eh->e_phnum, rel_raw, relsz))) {
            NM_LOG_ERROR("elf", "'%s': corrupt DT_REL=0x%08x", path, rel_raw);
            goto fail_cleanup;
        }
        if (rela_raw && (!va_in_phdrs(phdrs, eh->e_phnum, rela_raw, relasz))) {
            NM_LOG_ERROR("elf", "'%s': corrupt DT_RELA=0x%08x", path, rela_raw);
            goto fail_cleanup;
        }
        if (jmprel_raw && (!va_in_phdrs(phdrs, eh->e_phnum, jmprel_raw, pltrelsz))) {
            NM_LOG_ERROR("elf", "'%s': corrupt DT_JMPREL=0x%08x", path, jmprel_raw);
            goto fail_cleanup;
        }

        if (init_raw) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, init_raw, 1)) goto fail_cleanup;
            mod->init_va = load_bias + init_raw;
        }
        if (fini_raw) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, fini_raw, 1)) goto fail_cleanup;
            mod->fini_va = load_bias + fini_raw;
        }
        if (init_arr_raw) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, init_arr_raw, init_arr_sz)) goto fail_cleanup;
            mod->init_array_va = load_bias + init_arr_raw;
            mod->init_array_sz = init_arr_sz;
        }
        if (fini_arr_raw) {
            if (!va_in_phdrs(phdrs, eh->e_phnum, fini_arr_raw, fini_arr_sz)) goto fail_cleanup;
            mod->fini_array_va = load_bias + fini_arr_raw;
            mod->fini_array_sz = fini_arr_sz;
        }

        /* Load guest DT_NEEDED dependencies */
        for (int i = 0; i < num_needed; i++) {
            if (!mod->strtab || needed_offs[i] >= mod->strsz) {
                NM_LOG_ERROR("elf", "'%s': DT_NEEDED string offset out of bounds", path);
                goto fail_cleanup;
            }
            const char *dep_name = mod->strtab + needed_offs[i];
            if (is_canonical_system_lib(dep_name)) continue;

            dbt_module_t *dep_mod = find_loaded_module_by_name(dep_name);
            if (!dep_mod) {
                char dep_path[512];
                if (find_so_path(dep_name, path, dep_path, sizeof(dep_path)) != 0) {
                    NM_LOG_ERROR("elf", "'%s': missing guest dependency '%s'", path, dep_name);
                    dbt_set_dlerror("missing guest dependency '%s'", dep_name);
                    goto fail_cleanup;
                }
                uint8_t *dep_buf = NULL;
                size_t dep_sz = 0;
                if (read_entire_file(dep_path, &dep_buf, &dep_sz) != NM_OK) {
                    goto fail_cleanup;
                }
                int rc = load_guest_blob(dep_buf, dep_sz, dep_path, 0, &dep_mod);
                free(dep_buf);
                if (rc != NM_OK) goto fail_cleanup;
            } else {
                dep_mod->refcount++;
            }
            if (mod->num_deps < DBT_MAX_DEPS) {
                mod->deps[mod->num_deps++] = dep_mod;
            }
        }

        /* Apply relocations */
        if (rel_raw && relsz > 0) {
            int rc = apply_reloc_table(mod, (const void *)(uintptr_t)(load_bias + rel_raw),
                                       relsz, 0, phdrs, eh->e_phnum);
            if (rc != NM_OK) goto fail_cleanup_dlsym;
        }
        if (rela_raw && relasz > 0) {
            int rc = apply_reloc_table(mod, (const void *)(uintptr_t)(load_bias + rela_raw),
                                       relasz, 1, phdrs, eh->e_phnum);
            if (rc != NM_OK) goto fail_cleanup_dlsym;
        }
        if (jmprel_raw && pltrelsz > 0) {
            int rc = apply_reloc_table(mod, (const void *)(uintptr_t)(load_bias + jmprel_raw),
                                       pltrelsz, (pltrel == DT_RELA), phdrs, eh->e_phnum);
            if (rc != NM_OK) goto fail_cleanup_dlsym;
        }
    }

    /* Enforce page protections: NEVER PROT_EXEC on guest pages! PF_X -> PROT_READ only! */
    for (uint32_t p = min_vaddr; p < max_vaddr; p += 0x1000u) {
        int prot = 0;
        int has_seg = 0;
        for (uint16_t i = 0; i < eh->e_phnum; i++) {
            const Elf32_Phdr *ph = &phdrs[i];
            if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;
            uint32_t s = page_down(ph->p_vaddr);
            uint32_t e = page_up(ph->p_vaddr + ph->p_memsz);
            if (p >= s && p < e) {
                has_seg = 1;
                if (ph->p_flags & (PF_R | PF_X)) prot |= PROT_READ;
                if (ph->p_flags & PF_W) prot |= PROT_WRITE;
            }
        }
        mprotect((void *)(uintptr_t)(load_bias + p), 0x1000u, has_seg ? prot : PROT_NONE);
    }

    *out_mod = mod;
    return NM_OK;

fail_cleanup_dlsym:
    __atomic_store_n(&mod->num_rx_ranges, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&mod->in_use, 0, __ATOMIC_RELEASE);
    if (is_main) {
        g_main_mod = NULL;
        cleanup_brk_arena();
    }
    munmap((void *)(uintptr_t)mod->map_base, mod->map_size);
    memset(mod, 0, sizeof(*mod));
    return NM_ERR_DLSYM;

fail_cleanup:
    __atomic_store_n(&mod->num_rx_ranges, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&mod->in_use, 0, __ATOMIC_RELEASE);
    if (is_main) {
        g_main_mod = NULL;
        cleanup_brk_arena();
    }
    munmap((void *)(uintptr_t)mod->map_base, mod->map_size);
    memset(mod, 0, sizeof(*mod));
    return NM_ERR_ELF;
}

int dbt_load_main_file(const char *path, dbt_module_t **out_mod) {
    uint8_t *buf = NULL;
    size_t sz = 0;
    int rc = read_entire_file(path, &buf, &sz);
    if (rc != NM_OK) return rc;

    pthread_mutex_lock(&g_loader_lock);
    rc = load_guest_blob(buf, sz, path, 1, out_mod);
    pthread_mutex_unlock(&g_loader_lock);
    free(buf);
    return rc;
}

int dbt_load_main_memory(const void *blob, size_t blob_size, const char *name,
                         dbt_module_t **out_mod) {
    pthread_mutex_lock(&g_loader_lock);
    int rc = load_guest_blob((const uint8_t *)blob, blob_size,
                             name ? name : "<embedded>", 1, out_mod);
    pthread_mutex_unlock(&g_loader_lock);
    return rc;
}

uint32_t dbt_init_tls_block(dbt_module_t *mod) {
    size_t area_sz = 16384u;
    uint8_t *mem = (uint8_t *)mmap(NULL, area_sz, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 0;

    uint32_t gs_base = (uint32_t)(uintptr_t)(mem + 8192u);
    if (mod && mod->has_tls && mod->tls_memsz > 0) {
        uint32_t tls_sz = align_up(mod->tls_memsz, mod->tls_align ? mod->tls_align : 4u);
        if (tls_sz <= 8192u) {
            uint8_t *tls_dst = (uint8_t *)(uintptr_t)(gs_base - tls_sz);
            if (mod->tls_filesz > 0 && mod->tls_image_va != 0) {
                memcpy(tls_dst, (const void *)(uintptr_t)mod->tls_image_va, mod->tls_filesz);
            }
        }
    }
    /* TCB self-pointer at gs:[0] and stack canary at gs:[0x14] */
    uint32_t *tcb = (uint32_t *)(uintptr_t)gs_base;
    tcb[0] = gs_base;
    tcb[5] = 0x59a3c100u; /* gs:[0x14] */

    syscall(__NR_arch_prctl, ARCH_SET_GS, (uintptr_t)gs_base);
    return gs_base;
}

int dbt_setup_guest_stack(dbt_module_t *main_mod, int argc, char **argv, char **envp,
                          uint32_t *out_esp, uint32_t *out_stack_base, uint32_t *out_stack_size) {
    uint8_t *stk = (uint8_t *)mmap(NULL, DBT_GUEST_STACK_SZ, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stk == MAP_FAILED) {
        NM_LOG_ERROR("elf", "failed to mmap 8 MiB guest stack: errno=%d", errno);
        return NM_ERR_ELF;
    }
    uint32_t sp = (uint32_t)(uintptr_t)(stk + DBT_GUEST_STACK_SZ);

    /* Push 16 random bytes for AT_RANDOM */
    sp -= 16;
    uint32_t rand_va = sp;
    uint32_t rnd[4] = {0x12345678u, 0x9abcdef0u, (uint32_t)getpid(), 0xa55a5aa5u};
    memcpy((void *)(uintptr_t)rand_va, rnd, 16);

    int envc = 0;
    if (envp) {
        while (envp[envc]) envc++;
    }

    uint32_t *arg_vas = (uint32_t *)calloc((size_t)(argc > 0 ? argc : 1), sizeof(uint32_t));
    uint32_t *env_vas = (uint32_t *)calloc((size_t)(envc > 0 ? envc : 1), sizeof(uint32_t));
    if (!arg_vas || !env_vas) {
        free(arg_vas);
        free(env_vas);
        munmap(stk, DBT_GUEST_STACK_SZ);
        return NM_ERR_ELF;
    }

    for (int i = envc - 1; i >= 0; i--) {
        size_t len = strlen(envp[i]) + 1;
        sp -= (uint32_t)len;
        memcpy((void *)(uintptr_t)sp, envp[i], len);
        env_vas[i] = sp;
    }
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        sp -= (uint32_t)len;
        memcpy((void *)(uintptr_t)sp, argv[i], len);
        arg_vas[i] = sp;
    }

    sp &= ~0xFu;

    Elf32_auxv_t auxv[] = {
        {AT_PHDR,   {.a_val = main_mod ? main_mod->phdr_va : 0}},
        {AT_PHENT,  {.a_val = main_mod ? main_mod->phent : sizeof(Elf32_Phdr)}},
        {AT_PHNUM,  {.a_val = main_mod ? main_mod->phnum : 0}},
        {AT_PAGESZ, {.a_val = 4096}},
        {AT_BASE,   {.a_val = 0}},
        {AT_FLAGS,  {.a_val = 0}},
        {AT_ENTRY,  {.a_val = main_mod ? main_mod->entry_va : 0}},
        {AT_UID,    {.a_val = (uint32_t)getuid()}},
        {AT_EUID,   {.a_val = (uint32_t)geteuid()}},
        {AT_GID,    {.a_val = (uint32_t)getgid()}},
        {AT_EGID,   {.a_val = (uint32_t)getegid()}},
        {AT_RANDOM, {.a_val = rand_va}},
        {AT_NULL,   {.a_val = 0}}
    };

    size_t n_auxv = sizeof(auxv) / sizeof(auxv[0]);
    uint32_t words_needed = 1u + (uint32_t)argc + 1u + (uint32_t)envc + 1u + (uint32_t)(n_auxv * 2u);
    uint32_t bytes_needed = words_needed * 4u;
    uint32_t final_sp = (sp - bytes_needed) & ~0xFu;
    uint32_t *w = (uint32_t *)(uintptr_t)final_sp;
    uint32_t pos = 0;

    w[pos++] = (uint32_t)argc;
    for (int i = 0; i < argc; i++) w[pos++] = arg_vas[i];
    w[pos++] = 0;
    for (int i = 0; i < envc; i++) w[pos++] = env_vas[i];
    w[pos++] = 0;
    for (size_t i = 0; i < n_auxv; i++) {
        w[pos++] = auxv[i].a_type;
        w[pos++] = auxv[i].a_un.a_val;
    }

    free(arg_vas);
    free(env_vas);

    *out_esp = final_sp;
    if (out_stack_base) *out_stack_base = (uint32_t)(uintptr_t)stk;
    if (out_stack_size) *out_stack_size = DBT_GUEST_STACK_SZ;
    return NM_OK;
}

void dbt_run_module_inits(dbt_module_t *mod, int argc, char **argv, char **envp) {
    if (!mod || !__atomic_load_n(&mod->in_use, __ATOMIC_ACQUIRE)) return;
    if (__atomic_exchange_n(&mod->init_done, 1, __ATOMIC_ACQ_REL) != 0) return;

    for (int i = 0; i < mod->num_deps; i++) {
        dbt_run_module_inits(mod->deps[i], argc, argv, envp);
    }

    uint32_t init_args[3] = {
        (uint32_t)argc,
        (uint32_t)(uintptr_t)argv,
        (uint32_t)(uintptr_t)envp
    };
    if (mod->init_va) {
        newminhh_dbt_invoke_guest(mod->init_va, 3, init_args);
    }
    if (mod->init_array_va && mod->init_array_sz >= 4) {
        uint32_t n = mod->init_array_sz / 4u;
        const uint32_t *arr = (const uint32_t *)(uintptr_t)mod->init_array_va;
        for (uint32_t i = 0; i < n; i++) {
            if (arr[i] != 0 && arr[i] != 0xFFFFFFFFu) {
                newminhh_dbt_invoke_guest(arr[i], 3, init_args);
            }
        }
    }
}

void dbt_run_module_finis(dbt_module_t *mod) {
    if (!mod || !__atomic_load_n(&mod->in_use, __ATOMIC_ACQUIRE)) return;
    if (__atomic_exchange_n(&mod->fini_done, 1, __ATOMIC_ACQ_REL) != 0) return;

    if (mod->fini_array_va && mod->fini_array_sz >= 4) {
        uint32_t n = mod->fini_array_sz / 4u;
        const uint32_t *arr = (const uint32_t *)(uintptr_t)mod->fini_array_va;
        for (uint32_t i = n; i > 0; i--) {
            uint32_t fn = arr[i - 1];
            if (fn != 0 && fn != 0xFFFFFFFFu) {
                newminhh_dbt_invoke_guest(fn, 0, NULL);
            }
        }
    }
    if (mod->fini_va) {
        newminhh_dbt_invoke_guest(mod->fini_va, 0, NULL);
    }
}

void dbt_run_all_module_finis(void) {
    for (int i = DBT_MAX_MODULES - 1; i >= 0; i--) {
        if (__atomic_load_n(&g_modules[i].in_use, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&g_modules[i].fini_done, __ATOMIC_ACQUIRE)) {
            dbt_run_module_finis(&g_modules[i]);
        }
    }
}

/* --- Public & Guest dlopen / dlsym / dlclose --- */

extern char **environ;

void *newminhh_dbt_dlopen(const char *path, int flags) {
    (void)flags;
    dbt_ensure_initialized();
    if (!path || path[0] == '\0') {
        dbt_set_dlerror("newminhh_dbt_dlopen: NULL or empty path");
        return NULL;
    }

    pthread_mutex_lock(&g_loader_lock);
    dbt_module_t *mod = find_loaded_module_by_name(path);
    if (mod) {
        mod->refcount++;
        pthread_mutex_unlock(&g_loader_lock);
        return mod;
    }
    pthread_mutex_unlock(&g_loader_lock);

    uint8_t *buf = NULL;
    size_t sz = 0;
    if (read_entire_file(path, &buf, &sz) != NM_OK) {
        dbt_set_dlerror("newminhh_dbt_dlopen: failed to read '%s'", path);
        return NULL;
    }

    pthread_mutex_lock(&g_loader_lock);
    mod = find_loaded_module_by_name(path);
    if (mod) {
        mod->refcount++;
        pthread_mutex_unlock(&g_loader_lock);
        free(buf);
        return mod;
    }
    int rc = load_guest_blob(buf, sz, path, 0, &mod);
    pthread_mutex_unlock(&g_loader_lock);
    free(buf);
    if (rc != NM_OK) {
        dbt_set_dlerror("newminhh_dbt_dlopen: failed to load '%s' (err=%d)", path, rc);
        return NULL;
    }

    dbt_run_module_inits(mod, 0, NULL, environ);
    return mod;
}

typedef struct {
    dbt_module_t *mod;
    uint32_t guest_va;
    void *trampoline;
} dbt_dlsym_cache_entry_t;

#define DBT_DLSYM_CACHE_CAP 256
static dbt_dlsym_cache_entry_t g_dlsym_cache[DBT_DLSYM_CACHE_CAP];
static int g_dlsym_cache_n = 0;

static int lookup_guest_export_any(dbt_module_t *mod, const char *sym,
                                   uint32_t *out_va, int *out_is_func) {
    if (!mod || !mod->in_use || mod->unloading || !mod->symtab || !mod->strtab) return 0;
    const Elf32_Sym *syms = (const Elf32_Sym *)mod->symtab;
    for (uint32_t i = 1; i < mod->nsyms; i++) {
        const Elf32_Sym *s = &syms[i];
        if (s->st_name < mod->strsz &&
            s->st_shndx != SHN_UNDEF &&
            ELF32_ST_BIND(s->st_info) != STB_LOCAL &&
            strcmp(mod->strtab + s->st_name, sym) == 0) {
            *out_va = mod->load_bias + s->st_value;
            *out_is_func = (ELF32_ST_TYPE(s->st_info) != STT_OBJECT);
            return 1;
        }
    }
    for (int d = 0; d < mod->num_deps; d++) {
        if (lookup_guest_export_any(mod->deps[d], sym, out_va, out_is_func)) return 1;
    }
    return 0;
}

void *newminhh_dbt_dlsym(void *handle, const char *sym) {
    dbt_ensure_initialized();
    if (!sym || sym[0] == '\0') {
        dbt_set_dlerror("newminhh_dbt_dlsym: empty symbol name");
        return NULL;
    }

    dbt_module_t *mod = (dbt_module_t *)handle;
    pthread_mutex_lock(&g_loader_lock);
    if (!mod || mod < g_modules || mod >= g_modules + DBT_MAX_MODULES ||
        !mod->in_use || mod->unloading) {
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("newminhh_dbt_dlsym: invalid module handle %p for '%s'",
                        handle, sym);
        return NULL;
    }

    uint32_t va = 0;
    int is_func = 1;
    if (!lookup_guest_export_any(mod, sym, &va, &is_func)) {
        char mod_path[512];
        snprintf(mod_path, sizeof(mod_path), "%s", mod->path);
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("newminhh_dbt_dlsym: symbol '%s' not found in '%s'", sym, mod_path);
        return NULL;
    }
    if (!is_func) {
        pthread_mutex_unlock(&g_loader_lock);
        return (void *)(uintptr_t)va;
    }

    for (int i = 0; i < g_dlsym_cache_n; i++) {
        if (g_dlsym_cache[i].mod == mod && g_dlsym_cache[i].guest_va == va) {
            void *tr = g_dlsym_cache[i].trampoline;
            pthread_mutex_unlock(&g_loader_lock);
            return tr;
        }
    }
    void *tramp = newminhh_alloc_cb_trampoline(va, NULL, NM_CB_MODE_DBT, NM_CB_FLAG_UNTYPED);
    if (tramp && g_dlsym_cache_n < DBT_DLSYM_CACHE_CAP) {
        g_dlsym_cache[g_dlsym_cache_n++] = (dbt_dlsym_cache_entry_t){mod, va, tramp};
    }
    pthread_mutex_unlock(&g_loader_lock);
    if (!tramp) {
        dbt_set_dlerror("newminhh_dbt_dlsym: failed to allocate trampoline for '%s'", sym);
        return NULL;
    }
    return tramp;
}

int newminhh_dbt_dlclose(void *handle) {
    dbt_module_t *mod = (dbt_module_t *)handle;
    pthread_mutex_lock(&g_loader_lock);
    if (!mod || mod < g_modules || mod >= g_modules + DBT_MAX_MODULES ||
        !mod->in_use || mod->unloading) {
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("newminhh_dbt_dlclose: invalid handle %p", handle);
        return -1;
    }
    if (--mod->refcount > 0) {
        pthread_mutex_unlock(&g_loader_lock);
        return 0;
    }
    mod->unloading = 1;
    uint32_t map_base = mod->map_base;
    uint32_t map_size = mod->map_size;
    pthread_mutex_unlock(&g_loader_lock);

    dbt_run_module_finis(mod);
    dbt_invalidate_cache_range(map_base, map_size);

    pthread_mutex_lock(&g_loader_lock);
    __atomic_store_n(&mod->num_rx_ranges, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&mod->in_use, 0, __ATOMIC_RELEASE);
    for (int i = 0; i < g_dlsym_cache_n; i++) {
        if (g_dlsym_cache[i].mod == mod) {
            g_dlsym_cache[i].mod = NULL;
            g_dlsym_cache[i].guest_va = 0;
            g_dlsym_cache[i].trampoline = NULL;
        }
    }
    if (map_base && map_size) {
        munmap((void *)(uintptr_t)map_base, map_size);
    }
    memset(mod, 0, sizeof(*mod));
    pthread_mutex_unlock(&g_loader_lock);
    return 0;
}

/* Guest-code dlopen/dlsym/dlclose (returns guest-callable stubs or raw guest VAs!) */
uint32_t dbt_guest_dlopen(const char *filename, int flags) {
    (void)flags;
    if (filename == NULL) {
        /* Main executable handle */
        pthread_mutex_lock(&g_loader_lock);
        for (int i = 0; i < DBT_MAX_DL_HANDLES; i++) {
            if (!g_guest_dl_handles[i].in_use) {
                g_guest_dl_handles[i].in_use = 1;
                g_guest_dl_handles[i].is_native = 0;
                g_guest_dl_handles[i].guest_mod = g_main_mod;
                g_guest_dl_handles[i].compat_handle = NULL;
                if (g_main_mod) g_main_mod->refcount++;
                uint32_t h = (uint32_t)(uintptr_t)&g_guest_dl_handles[i];
                pthread_mutex_unlock(&g_loader_lock);
                return h;
            }
        }
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("dbt_guest_dlopen: handle table full");
        return 0;
    }

    if (filename[0] == '\0') {
        dbt_set_dlerror("dbt_guest_dlopen: empty filename");
        return 0;
    }

    if (is_canonical_system_lib(filename)) {
        void *ch = compat_dlopen(filename, flags);
        if (!ch) {
            const char *ce = compat_dlerror();
            dbt_set_dlerror("%s", ce ? ce : "compat_dlopen failed");
            return 0;
        }
        pthread_mutex_lock(&g_loader_lock);
        for (int i = 0; i < DBT_MAX_DL_HANDLES; i++) {
            if (!g_guest_dl_handles[i].in_use) {
                g_guest_dl_handles[i].in_use = 1;
                g_guest_dl_handles[i].is_native = 1;
                g_guest_dl_handles[i].compat_handle = ch;
                g_guest_dl_handles[i].guest_mod = NULL;
                uint32_t h = (uint32_t)(uintptr_t)&g_guest_dl_handles[i];
                pthread_mutex_unlock(&g_loader_lock);
                return h;
            }
        }
        pthread_mutex_unlock(&g_loader_lock);
        compat_dlclose(ch);
        dbt_set_dlerror("dbt_guest_dlopen: handle table full");
        return 0;
    }

    void *gm = newminhh_dbt_dlopen(filename, flags);
    if (!gm) {
        return 0;
    }
    pthread_mutex_lock(&g_loader_lock);
    for (int i = 0; i < DBT_MAX_DL_HANDLES; i++) {
        if (!g_guest_dl_handles[i].in_use) {
            g_guest_dl_handles[i].in_use = 1;
            g_guest_dl_handles[i].is_native = 0;
            g_guest_dl_handles[i].guest_mod = (dbt_module_t *)gm;
            g_guest_dl_handles[i].compat_handle = NULL;
            uint32_t h = (uint32_t)(uintptr_t)&g_guest_dl_handles[i];
            pthread_mutex_unlock(&g_loader_lock);
            return h;
        }
    }
    pthread_mutex_unlock(&g_loader_lock);
    newminhh_dbt_dlclose(gm);
    dbt_set_dlerror("dbt_guest_dlopen: handle table full");
    return 0;
}

uint32_t dbt_guest_dlsym(uint32_t handle, const char *symbol) {
    if (!symbol || symbol[0] == '\0') {
        dbt_set_dlerror("dbt_guest_dlsym: NULL or empty symbol");
        return 0;
    }

    dbt_guest_dl_handle_t *dh = (dbt_guest_dl_handle_t *)(uintptr_t)handle;
    pthread_mutex_lock(&g_loader_lock);
    if (!dh || dh < g_guest_dl_handles || dh >= g_guest_dl_handles + DBT_MAX_DL_HANDLES || !dh->in_use) {
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("dbt_guest_dlsym: invalid handle 0x%x for '%s'", handle, symbol);
        return 0;
    }

    if (dh->is_native) {
        pthread_mutex_unlock(&g_loader_lock);
        nm_sym_entry_t entry;
        if (newminhh_compat_lookup_wrapper(symbol, &entry) != NM_OK) {
            dbt_set_dlerror("dbt_guest_dlsym: unsupported native symbol '%s' (no i386<->x32 ABI wrapper)",
                            symbol);
            return 0;
        }
        if (entry.flags & NM_SYM_FLAG_DATA) {
            return (uint32_t)(uintptr_t)entry.wrapper_fn;
        }
        uint32_t stub_va = dbt_alloc_stub_for_sym(symbol, &entry);
        if (stub_va == 0) {
            dbt_set_dlerror("dbt_guest_dlsym: stub allocation failed for '%s'", symbol);
        }
        return stub_va;
    }

    uint32_t va = 0;
    int is_func = 1;
    dbt_module_t *gm = dh->guest_mod;
    if (!lookup_guest_export_any(gm, symbol, &va, &is_func)) {
        char mod_path[512];
        snprintf(mod_path, sizeof(mod_path), "%s", gm ? gm->path : "(null)");
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("dbt_guest_dlsym: symbol '%s' not found in '%s'", symbol, mod_path);
        return 0;
    }
    pthread_mutex_unlock(&g_loader_lock);
    return va;
}

int dbt_guest_dlclose(uint32_t handle) {
    dbt_guest_dl_handle_t *dh = (dbt_guest_dl_handle_t *)(uintptr_t)handle;
    pthread_mutex_lock(&g_loader_lock);
    if (!dh || dh < g_guest_dl_handles || dh >= g_guest_dl_handles + DBT_MAX_DL_HANDLES || !dh->in_use) {
        pthread_mutex_unlock(&g_loader_lock);
        dbt_set_dlerror("dbt_guest_dlclose: invalid handle 0x%x", handle);
        return -1;
    }
    int is_native = dh->is_native;
    void *ch = dh->compat_handle;
    dbt_module_t *gm = dh->guest_mod;
    dh->in_use = 0;
    dh->compat_handle = NULL;
    dh->guest_mod = NULL;
    pthread_mutex_unlock(&g_loader_lock);

    if (is_native) {
        int rc = compat_dlclose(ch);
        if (rc != 0) {
            const char *ce = compat_dlerror();
            dbt_set_dlerror("%s", ce ? ce : "compat_dlclose failed");
        }
        return rc;
    }
    return newminhh_dbt_dlclose(gm);
}
