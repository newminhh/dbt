ifeq ($(origin CC),default)
  CC := clang
endif
CSTD ?= gnu23

IS_CLANG := $(shell $(CC) -dM -E - < /dev/null 2>/dev/null | grep -c '__clang__')
ifeq ($(IS_CLANG),0)
  CLANG_EXTRA_FLAGS :=
else
  CLANG_EXTRA_FLAGS := -Wnullability-completeness -Wno-nullability-extension -Wno-gcc-compat -Wno-deprecated-octal-literals
endif

COMMON_CFLAGS := -std=$(CSTD) -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wold-style-definition -Wshadow -Wundef -Wformat=2 -fstrict-flex-arrays=3 -Werror -I../common $(CLANG_EXTRA_FLAGS)
CFLAGS := -fPIC -O2 $(COMMON_CFLAGS)
ASFLAGS := -fPIC -I../common

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib/x86_64-linux-gnux32
BINDIR ?= $(PREFIX)/bin

COMPAT_DIR := ../compat
LIB_TARGET := libnewminhh_dbt.so
BIN_TARGET := newminhh-run

LIB_C_SRCS := \
	elf_loader.c \
	dbt_x86_emitter.c \
	dbt_engine.c

LIB_S_SRCS := dbt_trampolines.S
LIB_OBJS := $(LIB_C_SRCS:.c=.o) $(LIB_S_SRCS:.S=.o)

LIB_LDFLAGS := -shared -Wl,-soname,$(LIB_TARGET) -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -L$(COMPAT_DIR) -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)
LIB_LIBS := -lnewminhh_compat -lcapstone -ldl -lpthread -lm

BIN_CFLAGS := -O2 $(COMMON_CFLAGS)
BIN_LDFLAGS := -no-pie -fuse-ld=bfd -Wl,-Ttext-segment=0x70000000 -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -L. -L$(COMPAT_DIR) -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)
BIN_LIBS := -lnewminhh_dbt -lnewminhh_compat -ldl -lpthread

COMMON_HDRS := ../common/newminhh_cstd.h ../common/newminhh_abi.h ../common/newminhh_log.h

.PHONY: all clean install analyze

all: $(LIB_TARGET) $(BIN_TARGET)

%.o: %.c dbt_internal.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S dbt_internal.h ../common/newminhh_abi.h
	$(CC) $(ASFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(LIB_OBJS) $(LIB_LIBS) -o $@

$(BIN_TARGET): main_runner.c $(LIB_TARGET) dbt_internal.h $(COMMON_HDRS)
	$(CC) $(BIN_CFLAGS) main_runner.c $(BIN_LDFLAGS) $(BIN_LIBS) -o $@

analyze:
	@for f in $(LIB_C_SRCS) main_runner.c; do \
		echo "Analyzing $$f ($(CC))..."; \
		if [ "$(IS_CLANG)" != "0" ]; then \
			$(CC) -std=$(CSTD) -Wall -Wextra -Wpedantic -Wshadow -Wundef -Wformat=2 $(CLANG_EXTRA_FLAGS) -I../common --analyze $$f || exit 1; \
		else \
			$(CC) -std=$(CSTD) -Wall -Wextra -Wpedantic -Wshadow -Wundef -Wformat=2 -fanalyzer -I../common -c $$f -o /dev/null || exit 1; \
		fi; \
	done

install: $(LIB_TARGET) $(BIN_TARGET)
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(BINDIR)
	install -m 0755 $(LIB_TARGET) $(DESTDIR)$(LIBDIR)/$(LIB_TARGET)
	install -m 0755 $(BIN_TARGET) $(DESTDIR)$(BINDIR)/$(BIN_TARGET)
	ldconfig || true

clean:
	rm -f $(LIB_OBJS) $(LIB_TARGET) $(BIN_TARGET) *.plist
