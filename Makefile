# kpm_RWBP Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CC = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
LD = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld
STRIP = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -fno-common 
CFLAGS += -Wno-int-conversion

KP_DIR = $(shell pwd)/../KernelPatch

INCLUDE_DIRS := src . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := src/main.o src/kernel_compat.o src/mem_reader.o
out_dir := out

.PHONY: all clean

all: $(out_dir)/kpm_RWBP.kpm
	$(MAKE) -C tests

$(out_dir)/kpm_RWBP.kpm: ${objs}
	mkdir -p $(out_dir)
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

clean:
	rm -rf $(out_dir) src/*.o
	$(MAKE) -C tests clean
