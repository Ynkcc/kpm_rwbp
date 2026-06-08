#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstdint>
#include "supercall.h"

// 打印字节数据的十六进制
static void print_hex(const unsigned char* buf, size_t len)
{
    std::cout << "读取到的数据 (十六进制):" << std::endl;
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }
    if (len % 16 != 0) {
        std::cout << std::endl;
    }

    // 尝试以 ASCII 文本方式打印出来，方便直接查看 target 的字符串内容
    std::cout << "读取到的数据 (ASCII): ";
    for (size_t i = 0; i < len; ++i) {
        char c = buf[i];
        if (c >= 32 && c <= 126) {
            std::cout << c;
        } else {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc < 6) {
        std::cerr << "用法: " << argv[0] << " <supercall_key> <kpm_path> <target_pid> <target_addr_hex> <size>" << std::endl;
        std::cerr << "示例: " << argv[0] << " 1a2b3c4d /data/local/tmp/kpm_RWBP.kpm 1234 7b12345678 64" << std::endl;
        return 1;
    }

    std::string key = argv[1];
    std::string kpm_path = argv[2];
    uint32_t pid = std::stoul(argv[3]);
    
    // 解析十六进制虚拟地址
    uint64_t addr;
    std::stringstream ss;
    ss << std::hex << argv[4];
    ss >> addr;

    uint64_t size = std::stoul(argv[5]);

    std::cout << "[*] 正在尝试加载 KPM 模块: " << kpm_path << " ..." << std::endl;
    long ret = sc_kpm_load(key.c_str(), kpm_path.c_str(), "");
    if (ret < 0) {
        std::cerr << "[-] 加载 KPM 模块失败, 错误码: " << ret << " (如已加载可忽略此项继续)" << std::endl;
    } else {
        std::cout << "[+] KPM 模块加载成功" << std::endl;
    }

    // 构造读取指令: "read <pid> <addr_hex> <size>"
    char ctl_args[128];
    snprintf(ctl_args, sizeof(ctl_args), "read %u %lx %lu", pid, addr, size);

    std::vector<char> buffer(size);
    std::cout << "[*] 发送读取指令: " << ctl_args << " ..." << std::endl;

    long read_bytes = sc_kpm_control(key.c_str(), "kpm_RWBP", ctl_args, buffer.data(), size);
    if (read_bytes < 0) {
        std::cerr << "[-] 读取内存失败, 错误码: " << read_bytes << std::endl;
    } else {
        std::cout << "[+] 读取内存成功, 实际读取字节数: " << read_bytes << std::endl;
        print_hex(reinterpret_cast<const unsigned char*>(buffer.data()), read_bytes);
    }

    std::cout << "[*] 正在卸载 KPM 模块 ..." << std::endl;
    ret = sc_kpm_unload(key.c_str(), "kpm_RWBP");
    if (ret < 0) {
        std::cerr << "[-] 卸载 KPM 模块失败, 错误码: " << ret << std::endl;
    } else {
        std::cout << "[+] KPM 模块卸载成功" << std::endl;
    }

    return 0;
}
