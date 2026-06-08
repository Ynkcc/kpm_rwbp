#include <iostream>
#include <unistd.h>
#include <cstring>

int main()
{
    // 在栈上分配测试缓冲区，并填入特征字符串
    char test_buffer[64];
    std::strcpy(test_buffer, "Hello, KernelPatch! This is a test memory block.");

    // 获取并打印当前进程 PID
    pid_t my_pid = getpid();
    
    // 打印缓冲区虚拟地址为十六进制
    uintptr_t buffer_addr = reinterpret_cast<uintptr_t>(test_buffer);

    std::cout << "==========================================" << std::endl;
    std::cout << "[+] 测试目标程序运行中..." << std::endl;
    std::cout << "[+] 进程 PID (Target PID): " << my_pid << std::endl;
    std::cout << "[+] 缓存区地址 (Buffer Hex Address): " << std::hex << "0x" << buffer_addr << std::endl;
    std::cout << "[+] 特征内容 (Expected Content): " << test_buffer << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << "[*] 请在客户端程序中使用上述 PID 和地址进行读取。" << std::endl;
    std::cout << "[*] 按 [回车键] 退出目标程序..." << std::endl;

    std::cin.get(); // 阻塞挂起，等待回车退出

    std::cout << "[*] 目标程序退出。" << std::endl;
    return 0;
}
