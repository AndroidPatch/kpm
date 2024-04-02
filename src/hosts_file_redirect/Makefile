HFR_VERSION := 1.1.8

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

CFLAGS = -Wall -O3 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DHFR_VERSION=\"$(HFR_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include kpm/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := hosts_file_redirect.o

all: hosts_file_redirect_$(HFR_VERSION).kpm

hosts_file_redirect_$(HFR_VERSION).kpm: ${objs}
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^
	${STRIP} -g --strip-unneeded $@

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm
	find . -name "*.o" | xargs rm -f
