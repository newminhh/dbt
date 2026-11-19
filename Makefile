CC := gcc
CFLAGS := -fPIC -O2 -Wall -Wextra -Werror=implicit-function-declaration -I../common
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

LIB_LDFLAGS := -shared -Wl,-soname,$(LIB_TARGET) -L$(COMPAT_DIR) -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)
LIB_LIBS := -lnewminhh_compat -lcapstone -ldl -lpthread -lm

BIN_CFLAGS := -O2 -Wall -Wextra -Werror=implicit-function-declaration -I../common
BIN_LDFLAGS := -no-pie -Wl,-Ttext-segment=0x70000000 -L. -L$(COMPAT_DIR) -L$(LIBDIR) -Wl,-rpath,$(LIBDIR)
BIN_LIBS := -lnewminhh_dbt -lnewminhh_compat -ldl -lpthread

.PHONY: all clean install

all: $(LIB_TARGET) $(BIN_TARGET)

%.o: %.c dbt_internal.h ../common/newminhh_abi.h ../common/newminhh_log.h
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S dbt_internal.h ../common/newminhh_abi.h
	$(CC) $(ASFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(LIB_OBJS) $(LIB_LIBS) -o $@

$(BIN_TARGET): main_runner.c $(LIB_TARGET) dbt_internal.h
	$(CC) $(BIN_CFLAGS) main_runner.c $(BIN_LDFLAGS) $(BIN_LIBS) -o $@

install: $(LIB_TARGET) $(BIN_TARGET)
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(BINDIR)
	install -m 0755 $(LIB_TARGET) $(DESTDIR)$(LIBDIR)/$(LIB_TARGET)
	install -m 0755 $(BIN_TARGET) $(DESTDIR)$(BINDIR)/$(BIN_TARGET)
	ldconfig || true

clean:
	rm -f $(LIB_OBJS) $(LIB_TARGET) $(BIN_TARGET)
