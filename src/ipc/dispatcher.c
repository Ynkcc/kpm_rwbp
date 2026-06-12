#include "dispatcher.h"
#include "kernel_compat.h"
#include "mem_reader.h"
#include "hwbp.h"
#include <linux/errno.h>
#include <linux/string.h>

long rwbp_dispatch(shm_channel_t *shm)
{
    if (!shm || shm->magic != SHM_MAGIC) {
        pr_warn("[kpm_RWBP] rwbp_dispatch: Invalid SHM magic or pointer!\n");
        return -EINVAL;
    }

    unsigned int cmd = shm->cmd;
    pr_info("[kpm_RWBP] rwbp_dispatch shm entry: cmd=%u\n", cmd);

    // 根据命令分发处理
    switch (cmd) {
        case OP_READ_MEM: {
            copy_memory_t rcmd;
            // 拷贝入参，防止后续覆盖冲突
            memcpy(&rcmd, shm->payload, sizeof(copy_memory_t));

            pr_info("[kpm_RWBP] shm rcmd fields: pid=%u, addr=%llx, size=%llu\n",
                    rcmd.pid, (unsigned long long)rcmd.addr, (unsigned long long)rcmd.size);

            if (rcmd.size > sizeof(shm->payload)) {
                return -EINVAL;
            }

            long read_res = read_process_memory(rcmd.pid, rcmd.addr, rcmd.size, (char *)shm->payload);
            pr_info("[kpm_RWBP] read_process_memory return: %ld\n", read_res);

            shm->data_size = (read_res >= 0) ? read_res : 0;
            return read_res;
        }
        case OP_SET_HW_BREAKPOINT: {
            hw_breakpoint_cmd_t bcmd;
            memcpy(&bcmd, shm->payload, sizeof(hw_breakpoint_cmd_t));
            return register_hwbp(bcmd.pid, bcmd.addr, bcmd.type, bcmd.len, bcmd.scheme);
        }
        case OP_REMOVE_HW_BREAKPOINT: {
            hw_breakpoint_cmd_t bcmd;
            memcpy(&bcmd, shm->payload, sizeof(hw_breakpoint_cmd_t));
            return unregister_hwbp(bcmd.pid, bcmd.addr);
        }
        case OP_REMOVE_ALL_HW_BREAKPOINT: {
            return unregister_all_hwbp();
        }
        case OP_READ_HW_BP_INFO: {
            hwbp_info_cmd_t icmd;
            memcpy(&icmd, shm->payload, sizeof(hwbp_info_cmd_t));

            uint64_t actual_count = 0;
            // 直接读取命中数据覆盖写入 payload，最大数量由 icmd.max_count 限制，且不能超过 payload 大小
            uint64_t max_allowed = sizeof(shm->payload) / 296; // 296 = sizeof(hwbp_hit_item_t)
            uint64_t request_count = (icmd.max_count > max_allowed) ? max_allowed : icmd.max_count;

            long ret = read_hwbp_info(icmd.pid, request_count, (void *)shm->payload, &actual_count);
            if (ret == 0) {
                shm->data_size = actual_count * 296; // sizeof(hwbp_hit_item_t)
            }
            return ret;
        }
        default:
            pr_warn("[kpm_RWBP] Unknown command: %u\n", cmd);
            break;
    }
    return -EINVAL;
}

