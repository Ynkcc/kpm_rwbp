# runner Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CC = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang

CFLAGS = -Wall -O2 -I../include -I../../src/ipc

OUT_DIR = ../../out
TARGET  = $(OUT_DIR)/test_rwbp

SRCS = main.c kpm_ctrl.c case_mem_read.c case_hwbp_self.c case_hwbp_target.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
