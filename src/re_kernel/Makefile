RK_VERSION := 1.4.0.1

ifndef KP_DIR
    KP_DIR = ../..
endif

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(OS_NAME)-$(MACHINE)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
endif

ifdef TARGET_COMPILE
    CC := $(TARGET_COMPILE)gcc
    LD := $(TARGET_COMPILE)ld
    STRIP := $(TARGET_COMPILE)strip
else ifdef NDK_PATH
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
    STRIP := $(NDK_PATH)/llvm-strip
endif

CC ?= gcc
LD ?= ld
STRIP ?= strip

CFLAGS = -Wall -O3 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DRK_VERSION=\"$(RK_VERSION)$(RK_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include kpm/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := re_kernel.o

all: re_kernel_$(RK_VERSION).kpm

debug: CFLAGS += -DDEBUG
debug: RK_VER := _d
debug: re_kernel_$(RK_VERSION)_debug.kpm

quiet: CFLAGS += -DQUIET
quiet: RK_VER := _q
quiet: re_kernel_$(RK_VERSION)_quiet.kpm

re_kernel_$(RK_VERSION).kpm: ${objs}
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded $@

re_kernel_$(RK_VERSION)_debug.kpm: ${objs}
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded $@

re_kernel_$(RK_VERSION)_quiet.kpm: ${objs}
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded $@

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm
	find . -name "*.o" | xargs rm -f
