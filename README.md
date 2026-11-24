# newminhh/dbt

In-process Capstone-based Dynamic Binary Translator (`libnewminhh_dbt.so`) and standalone runner CLI (`newminhh-run`) for the [`newminhh`](https://github.com/newminhh/newminhh) i386-on-x32 compatibility system.

Executes unmodified i386 (`ELFCLASS32`, `EM_386`) executables and shared libraries directly inside an x32 process without containers, `:i386` packages, or kernel `ia32_emulation`. Also serves as the runtime fallback backend for [`newminhh/patcher`](https://github.com/newminhh/patcher) when `--hybrid-fallback` or `REQUIRES_DBT_FALLBACK` functions are used.

---

## Source Files

| File | Role |
| :--- | :--- |
| `Makefile` | Builds `libnewminhh_dbt.so` (linked against `libnewminhh_compat.so` and `libcapstone`) and `newminhh-run` (linked `-no-pie -Wl,-Ttext-segment=0x70000000`) |
| `dbt_internal.h` | Public `libnewminhh_dbt.so` API, `dbt_fast_entry_t`, `dbt_module_t`, `dbt_stub_entry_t`, and internal engine/loader interfaces |
| `dbt_trampolines.S` | `dbt_enter_block` / `dbt_trampoline_exit` (GPR + `EFLAGS` + `fxsave`/`fxrstor` context switch), `dbt_fxsave_push/pop_f32/f64`, `dbt_call_native_x32_6`, and `dbt_segv_cb_entry` |
| `dbt_x86_emitter.c` | Capstone `CS_ARCH_X86, CS_MODE_32` basic-block JIT compiler (`DBT_MAX_BLOCK_INSNS=128`) generating Long Mode x86-64 code with virtual `%r12d` (`ESP`), `%r14d` (`GS` base), and `%r15` (`cpu`) |
| `dbt_engine.c` | 16 MiB JIT arenas, 64K atomic indirect-branch fast cache (`g_dbt_fast_cache`), direct edge chaining & unchaining (`g_edge_buckets`), cache invalidation on `munmap`/`mprotect`, and async-signal-safe `SIGSEGV` NX-guard handler (`DBT_SEGV_CB_CAP=1024`) |
| `elf_loader.c` | i386 `ET_EXEC`/`ET_DYN` ELF32 loader, recursive `DT_NEEDED` resolution, `REL`/`RELA` relocation (`R_386_32`, `PC32`, `GLOB_DAT`, `JMP_SLOT`, `RELATIVE`, `IRELATIVE`, `COPY`, `TLS_*`), `0x5F000000` synthetic stub arena (`DBT_MAX_STUBS=2048`), 16 MiB isolated `brk` arena, `PT_TLS`, 8 MiB guest stack + `auxv`, and guest/host `dlopen`/`dlsym`/`dlclose` |
| `main_runner.c` | `newminhh-run` CLI entrypoint |

---

## Key Architectural Highlights

- **Strict NX-Guard on Guest Code**: Guest `PF_X` segments are mapped strictly `PROT_READ` (never `PROT_EXEC`). Raw native-to-guest calls into `PROT_READ` guest memory raise `SIGSEGV` (`SEGV_ACCERR`), which `dbt_sigsegv_handler` redirects locklessly to pre-allocated W^X trampolines (`dbt_segv_cb_entry`) while chaining non-guest segfaults to any pre-existing handler.
- **High Link Address (`0x70000000`)**: Keeps `newminhh-run` above all guest `ET_EXEC` (`0x08048000`) and `ET_DYN` (`< 0x60000000`) virtual mappings.
- **Fast Indirect Branch Cache & Direct Chaining**: Direct branches atomically patch `rel32` jumps once target blocks are translated (and unchain cleanly on `dbt_invalidate_cache_range`); indirect jumps/calls/returns probe `g_dbt_fast_cache[65536]` in 1 atomic 64-bit load inline inside JIT code.
- **Lookup-Aware Resolution**: Resolves guest symbols/imports via [`newminhh/lookup`](../lookup/README.md) layered `lookup_table.txt` precedence (static curated/base + optional dynamic cache) for ABI-safe compat stub binding; multi-distro glibc+musl x32 trigger regeneration is non-fatal and runtime falls back to compiled-in base data on stale/missing cache.
- **Automatic Backend Registration**: `__attribute__((constructor))` automatically registers `nm_dl_backend_t` and `dbt_guest_invoker_cb` with [`newminhh/compat`](https://github.com/newminhh/compat).

---

## Build, Install & CLI Usage

Built with **GNU C23 (`-std=gnu23`)** using **Clang (`>= 21`, default `CC ?= clang`)** as primary compiler or **GCC (`>= 15`)** as secondary compiler. Requires [`newminhh/common`](https://github.com/newminhh/common) (`../common`), [`newminhh/compat`](https://github.com/newminhh/compat) (`../compat`), and `libcapstone-dev` on an x32 system:

```bash
make all           # builds libnewminhh_dbt.so and newminhh-run (Clang default)
make CC=gcc all    # builds with GCC 15/16
make analyze       # runs static analysis (scan-build under Clang, -fanalyzer under GCC)
make install       # installs libnewminhh_dbt.so to $(LIBDIR) and newminhh-run to $(BINDIR)
make clean
```

Execute an i386 executable or shared library symbol directly on x32:

```bash
newminhh-run <i386-elf> [args...]
newminhh-run --so <path.so> <symbol> [int_args...]
```

See [`docs/ARCHITECTURE.md`](https://github.com/newminhh/docs/blob/main/ARCHITECTURE.md) for the full JIT and loader specification and [`docs/TESTING_AND_VM.md`](https://github.com/newminhh/docs/blob/main/TESTING_AND_VM.md) for Part 4 verification and multi-threaded stress tests.
