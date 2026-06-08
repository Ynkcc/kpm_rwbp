# client Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CC = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
CXX = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++

CFLAGS = -Wall -O2
CXXFLAGS = -Wall -O2 -static-libstdc++

OUT_DIR = ../../out

all: $(OUT_DIR)/test_rwbp $(OUT_DIR)/kpm_test

$(OUT_DIR)/test_rwbp: test_rwbp.cpp
	mkdir -p $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(OUT_DIR)/kpm_test: kpm_test.c
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f $(OUT_DIR)/test_rwbp $(OUT_DIR)/kpm_test
