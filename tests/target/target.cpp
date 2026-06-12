#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

// 预设固定虚拟地址，页面对齐
const uintptr_t FIXED_ADDRESS = 0x2000000000;
// 异或加密密钥
const uintptr_t XOR_KEY = 0x55AA55AAFF00FF00ULL;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("--- target_process 启动 ---\n");
    printf("当前进程 PID: %d\n", getpid());

    // 1. 使用 mmap 在固定虚拟地址分配内存（页面大小为 4KB）
    size_t page_size = 4096;
    void* mapped_mem = mmap((void*)FIXED_ADDRESS, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (mapped_mem == MAP_FAILED) {
        perror("mmap 失败");
        return 1;
    }

    printf("成功映射固定地址内存: %p (期望: %p)\n", mapped_mem, (void*)FIXED_ADDRESS);

    // 2. 创建 3 个 int 变量
    int var1 = 100;
    int var2 = 200;
    int var3 = 300;

    printf("创建 3 个 int 变量及其初始值与地址:\n");
    printf("var1 = %d, 地址: %p\n", var1, &var1);
    printf("var2 = %d, 地址: %p\n", var2, &var2);
    printf("var3 = %d, 地址: %p\n", var3, &var3);

    // 固定虚拟地址上的数组指针
    uintptr_t* encrypted_array = (uintptr_t*)mapped_mem;

    // 3. 将变量的地址加密并存入数组
    encrypted_array[0] = (uintptr_t)&var1 ^ XOR_KEY;
    encrypted_array[1] = (uintptr_t)&var2 ^ XOR_KEY;
    encrypted_array[2] = (uintptr_t)&var3 ^ XOR_KEY;

    printf("地址指针已加密并存入固定虚拟地址数组:\n");
    printf("encrypted_array[0] = 0x%lx\n", encrypted_array[0]);
    printf("encrypted_array[1] = 0x%lx\n", encrypted_array[1]);
    printf("encrypted_array[2] = 0x%lx\n", encrypted_array[2]);

    printf("开始定期读取、解密并修改变量值...\n");

    // 4. 定期循环读取并修改
    while (true) {
        sleep(2);
        printf("\n----------------------------------------\n");

        // 从固定虚拟地址数组中读取加密地址
        uintptr_t enc1 = encrypted_array[0];
        uintptr_t enc2 = encrypted_array[1];
        uintptr_t enc3 = encrypted_array[2];

        // 解密地址
        int* p1 = (int*)(enc1 ^ XOR_KEY);
        int* p2 = (int*)(enc2 ^ XOR_KEY);
        int* p3 = (int*)(enc3 ^ XOR_KEY);

        // 打印解密地址及当前值
        printf("读取解密地址: p1=%p, p2=%p, p3=%p\n", p1, p2, p3);
        printf("读取当前值: *p1 = %d, *p2 = %d, *p3 = %d\n", *p1, *p2, *p3);

        // 修改这三个 int 变量的值
        *p1 += 1;
        *p2 += 10;
        *p3 += 100;

        printf("修改后的值: *p1 = %d, *p2 = %d, *p3 = %d\n", *p1, *p2, *p3);
    }

    // 释放内存（实际无法到达此处）
    munmap(mapped_mem, page_size);
    return 0;
}
