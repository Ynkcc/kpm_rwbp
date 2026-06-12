# target Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CXX = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++
CXXFLAGS = -Wall -O2 -static-libstdc++

OUT_DIR = ../../out

all: $(OUT_DIR)/target

$(OUT_DIR)/target: target.cpp
	mkdir -p $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f $(OUT_DIR)/target
