#include "dispatcher.h"
#include "kernel_compat.h"
#include "mem_reader.h"
#include "hwbp.h"
#include <linux/errno.h>
#include <linux/uaccess.h>

long rwbp_dispatch(unsigned int cmd, unsigned long arg)
{
    pr_info("[kpm_RWBP] rwbp_dispatch entry: cmd=%u, arg=%lx\n", cmd, arg);
    kfunc(msleep)(50);

    // 根据 IOCTL 命令分发处理
    switch (cmd) {
        case OP_READ_MEM: {
            pr_info("[kpm_RWBP] rwbp_dispatch: OP_READ_MEM\n");
            kfunc(msleep)(50);

            copy_memory_t rcmd;
            pr_info("[kpm_RWBP] calling copy_from_user_nofault from user arg=%lx...\n", arg);
            kfunc(msleep)(50);

            long err = kfunc(copy_from_user_nofault)(&rcmd, (void __user *)arg, sizeof(rcmd));
            pr_info("[kpm_RWBP] copy_from_user_nofault copy_memory_t result: %ld\n", err);
            kfunc(msleep)(50);

            if (err != 0) {
                pr_warn("[kpm_RWBP] copy_from_user_nofault failed!\n");
                kfunc(msleep)(50);
                return -EFAULT;
            }

            pr_info("[kpm_RWBP] rcmd fields: pid=%u, addr=%llx, buffer=%llx, size=%llu\n",
                    rcmd.pid, (unsigned long long)rcmd.addr, (unsigned long long)rcmd.buffer, (unsigned long long)rcmd.size);
            kfunc(msleep)(50);

            long read_res = read_process_memory(rcmd.pid, rcmd.addr, rcmd.size, (char __user *)rcmd.buffer);
            pr_info("[kpm_RWBP] read_process_memory return: %ld\n", read_res);
            kfunc(msleep)(50);

            return read_res;
        }
        case OP_SET_HW_BREAKPOINT: {
            pr_info("[kpm_RWBP] rwbp_dispatch: OP_SET_HW_BREAKPOINT\n");
            kfunc(msleep)(50);

            hw_breakpoint_cmd_t bcmd;
            if (kfunc(copy_from_user_nofault)(&bcmd, (void __user *)arg, sizeof(bcmd)) != 0) {
                return -EFAULT;
            }
            return register_hwbp(bcmd.pid, bcmd.addr, bcmd.type, bcmd.len, bcmd.scheme);
        }
        case OP_REMOVE_HW_BREAKPOINT: {
            pr_info("[kpm_RWBP] rwbp_dispatch: OP_REMOVE_HW_BREAKPOINT\n");
            kfunc(msleep)(50);

            hw_breakpoint_cmd_t bcmd;
            if (kfunc(copy_from_user_nofault)(&bcmd, (void __user *)arg, sizeof(bcmd)) != 0) {
                return -EFAULT;
            }
            return unregister_hwbp(bcmd.pid, bcmd.addr);
        }
        case OP_REMOVE_ALL_HW_BREAKPOINT: {
            pr_info("[kpm_RWBP] rwbp_dispatch: OP_REMOVE_ALL_HW_BREAKPOINT\n");
            kfunc(msleep)(50);
            return unregister_all_hwbp();
        }
        case OP_READ_HW_BP_INFO: {
            pr_info("[kpm_RWBP] rwbp_dispatch: OP_READ_HW_BP_INFO\n");
            kfunc(msleep)(50);

            hwbp_info_cmd_t icmd;
            if (kfunc(copy_from_user_nofault)(&icmd, (void __user *)arg, sizeof(icmd)) != 0) {
                return -EFAULT;
            }

            uint64_t actual_count = 0;
            long ret = read_hwbp_info(icmd.pid, icmd.max_count,
                                      (void __user *)icmd.user_buf, &actual_count);
            if (ret == 0) {
                // 将实际数量拷贝回用户空间
                if (kfunc(copy_to_user_nofault)((void __user *)(arg + offsetof(hwbp_info_cmd_t, actual_count)),
                                        &actual_count, sizeof(actual_count)) != 0) {
                    return -EFAULT;
                }
            }
            return ret;
        }
        default:
            pr_warn("[kpm_RWBP] Unknown command: %u\n", cmd);
            kfunc(msleep)(50);
            break;
    }
    return -EINVAL;
}
