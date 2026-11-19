#define _GNU_SOURCE
#include "dbt_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s <i386-elf> [args...]\n"
            "  %s --so <path.so> <symbol> [int_args...]\n",
            prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--so") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            return 2;
        }
        const char *so_path = argv[2];
        const char *sym_name = argv[3];
        void *handle = newminhh_dbt_dlopen(so_path, 0);
        if (!handle) {
            const char *err = newminhh_dbt_dlerror();
            fprintf(stderr, "newminhh-run: dlopen('%s') failed: %s\n",
                    so_path, err ? err : "unknown error");
            return 1;
        }
        void *fn_ptr = newminhh_dbt_dlsym(handle, sym_name);
        if (!fn_ptr) {
            const char *err = newminhh_dbt_dlerror();
            fprintf(stderr, "newminhh-run: dlsym('%s', '%s') failed: %s\n",
                    so_path, sym_name, err ? err : "unknown error");
            newminhh_dbt_dlclose(handle);
            return 1;
        }

        uint32_t args[6] = {0};
        int nargs = argc - 4;
        if (nargs > 6) nargs = 6;
        for (int i = 0; i < nargs; i++) {
            args[i] = (uint32_t)strtol(argv[4 + i], NULL, 0);
        }

        typedef int (*fn6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
        fn6_t fn = (fn6_t)fn_ptr;
        int ret = fn(args[0], args[1], args[2], args[3], args[4], args[5]);
        newminhh_dbt_dlclose(handle);
        return ret;
    }

    int rc = newminhh_dbt_exec_file(argv[1], argc - 1, argv + 1, environ);
    if (rc < 0) {
        /* Negative NM_ERR_* from loader/translator: propagate non-zero exit code */
        return 1;
    }
    return rc;
}
