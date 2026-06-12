# kpm_RWBP Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CC = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
LD = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld
STRIP = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -fno-common -mno-outline-atomics
CFLAGS += -Wno-int-conversion -Isrc/core -Isrc/compat -Isrc/memory -Isrc/hwbp -Isrc/ipc

KP_DIR = $(shell pwd)/../KernelPatch

INCLUDE_DIRS := src . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := src/core/main.o src/compat/kernel_compat.o src/memory/mem_reader.o src/ipc/dispatcher.o src/hwbp/hwbp.o
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
	rm -rf $(out_dir) src/core/*.o src/compat/*.o src/memory/*.o src/ipc/*.o src/hwbp/*.o
	$(MAKE) -C tests clean
