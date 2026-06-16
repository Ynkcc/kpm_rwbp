# kpm_RWBP Makefile

ANDROID_NDK ?= /home/ynk/Android/Sdk/ndk/27.0.12077973

CC = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
LD_LLD = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld
STRIP = ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip

RUST_LIB = target/aarch64-linux-android/release/libkpm_rwbp.a
out_dir := out

.PHONY: all clean rust_build

all: $(out_dir)/kpm_RWBP.kpm
	$(MAKE) -C tests

rust_build:
	RUSTFLAGS="-C relocation-model=static -C opt-level=3" rustup run nightly cargo build -Z build-std=core,compiler_builtins --target aarch64-linux-android --release

$(out_dir)/kpm_RWBP.kpm: rust_build
	mkdir -p $(out_dir)
	printf 'SECTIONS { .text : { *(.text .text.* .gnu.linkonce.t.*) } .rodata : { *(.rodata .rodata.* .gnu.linkonce.r.*) } .data : { *(.data .data.* .gnu.linkonce.d.*) } .bss : { *(.bss .bss.* .gnu.linkonce.b.*) } .kpm.info : { *(.kpm.info) } .kpm.init : { *(.kpm.init) } .kpm.exit : { *(.kpm.exit) } }\n' > /tmp/kpm_merge.ld
	$(LD_LLD) -r -T /tmp/kpm_merge.ld -o $@ --undefined __kpm_info_name --undefined __kpm_info_version --undefined __kpm_info_license --undefined __kpm_info_author --undefined __kpm_info_description --undefined __kpm_initcall_rwbp_init --undefined __kpm_exitcall_rwbp_exit --undefined memset --undefined memcpy --undefined memcmp --undefined rust_eh_personality $(RUST_LIB)
	$(STRIP) --remove-section=.eh_frame --strip-debug $@

clean:
	rm -rf $(out_dir)
	cargo clean
	$(MAKE) -C tests clean