#include "EBPFWrapper.h"
#include "RuntimeUtil.h"
#include <iostream>

using namespace std;

struct conn_data_event_t {

};


#define LOAD_EBPF_FUNC(funcName) \
    { \
        void* funcPtr = mEBPFLib->LoadMethod(#funcName, loadErr); \
        if (funcPtr == NULL) { \
            std::cout << (std::string("load ebpf method failed: ") + #funcName) << std::endl; \
            return false; \
        } \
        g_##funcName##_func = funcName##_func(funcPtr); \
    }

typedef void (*net_data_process_func_t)(void* custom_data, struct conn_data_event_t* event);

typedef void (*ebpf_setup_net_data_process_func_func)(net_data_process_func_t func, void* custom_data);

typedef int32_t (*ebpf_config_func)(
    int32_t opt1, int32_t opt2, int32_t params_count, void** params, int32_t* params_len);

typedef int32_t (*ebpf_poll_events_func)(int32_t max_events, int32_t* stop_flag);

typedef int32_t (*ebpf_init_func)(char* btf,
                                  int32_t btf_size,
                                  char* so,
                                  int32_t so_size);

typedef int32_t (*ebpf_start_func)();

typedef int32_t (*ebpf_stop_func)();


ebpf_setup_net_data_process_func_func g_ebpf_setup_net_data_process_func_func = NULL;
ebpf_config_func g_ebpf_config_func = NULL;
ebpf_poll_events_func g_ebpf_poll_events_func = NULL;
ebpf_init_func g_ebpf_init_func = NULL;
ebpf_start_func g_ebpf_start_func = NULL;
ebpf_stop_func g_ebpf_stop_func = NULL;

static bool EBPFLoadSuccess() {
    return g_ebpf_setup_net_data_process_func_func != NULL ;
}

static void set_ebpf_int_config(int32_t opt, int32_t opt2, int32_t value) {
    if (g_ebpf_config_func == NULL) {
        return;
    }
    int32_t* params[] = {&value};
    int32_t paramsLen[] = {4};
    g_ebpf_config_func(opt, opt2, 1, (void**)params, paramsLen);
}

static void ebpf_data_process_callback(void* custom_data, struct conn_data_event_t* event_data) {
    if (custom_data == NULL || event_data == NULL) {
        return;
    }
    ((EBPFWrapper*)custom_data)->OnData(event_data);
}

// static std::string GetValidBTFPath(const int64_t& kernelVersion, const std::string& kernelRelease) {
//     char* configedBTFPath = getenv("EBPF_BTF_PATH");
//     if (configedBTFPath != nullptr) {
//         return {configedBTFPath};
//     }
//     std::string execDir = GetProcessExecutionDir();
//     fsutil::Dir dir(execDir);
//     if (!dir.Open()) {
//         return "";
//     }
//     std::string lastMatch;
//     fsutil::Entry entry;
//     while (true) {
//         entry = dir.ReadNext();
//         if (!entry) {
//             break;
//         }
//         if (!entry.IsRegFile()) {
//             continue;
//         }
//         if (entry.Name().find(kernelRelease) != std::string::npos) {
//             return execDir + entry.Name();
//         }
//         if (entry.Name().find("vmlinux-") == (size_t)0) {
//             lastMatch = entry.Name();
//         }
//     }
//     if (!lastMatch.empty()) {
//         return execDir + lastMatch;
//     }
//     return "";
// }


bool EBPFWrapper::isSupportedOS(int64_t& kernelVersion, std::string& kernelRelease) {
//    GetKernelInfo(kernelRelease, kernelVersion);

//    LOG_INFO(sLogger, ("kernel version", kernelRelease));
    // if (kernelRelease.empty()) {
    //     return false;
    // }
    // if (kernelVersion >= INT64_FLAG(sls_observer_ebpf_min_kernel_version)) {
    //     return true;
    // }
    // if (kernelVersion / 1000000 != kLowkernelSpecificVersion) {
    //     return false;
    // }
    // std::string os;
    // int64_t osVersion;

    // if (!GetRedHatReleaseInfo(os, osVersion, STRING_FLAG(default_container_host_path))
    //     || GetRedHatReleaseInfo(os, osVersion)) {
    //     return false;
    // }
    // if (os != kLowkernelCentosName || osVersion < kLowkernelCentosMinVersion) {
    //     return false;
    // }
    return true;
}

bool EBPFWrapper::loadEbpfLib(int64_t kernelVersion, std::string& soPath) {
    if (mEBPFLib != nullptr) {
        if (!EBPFLoadSuccess()) {
            return false;
        }
        return true;
    }
    // std::string dlPrefix = GetProcessExecutionDir();
    std::string dlPrefix = "./";
    soPath = dlPrefix + "libebpf.so";
    // if (kernelVersion < INT64_FLAG(sls_observer_ebpf_min_kernel_version)) {
    //     fsutil::PathStat buf;
    //     // overlayfs has a reference bug in low kernel version, so copy docker inner file to host path to avoid using
    //     // overlay fs. detail: https://lore.kernel.org/lkml/20180228004014.445-1-hmclauchlan@fb.com/
    //     if (fsutil::PathStat::stat(STRING_FLAG(default_container_host_path).c_str(), buf)) {
    //         std::string cmd
    //             = std::string("\\cp ").append(soPath).append(" ").append(STRING_FLAG(sls_observer_ebpf_host_path));
    //         system(std::string("mkdir ").append(STRING_FLAG(sls_observer_ebpf_host_path)).c_str());
    //         system(cmd.c_str());
    //         dlPrefix = STRING_FLAG(sls_observer_ebpf_host_path);
    //         soPath = STRING_FLAG(sls_observer_ebpf_host_path) + "libebpf.so";
    //     }
    // }
    mEBPFLib = new DynamicLibLoader;
    std::string loadErr;
    if (!mEBPFLib->LoadDynLib("ebpf", loadErr, dlPrefix)) {
        std::cout << "load ebpf dynamic library path" + soPath << std::endl;
        return false;
    }
    LOAD_EBPF_FUNC(ebpf_setup_net_data_process_func)
    // LOAD_EBPF_FUNC(ebpf_setup_net_event_process_func)
    // LOAD_EBPF_FUNC(ebpf_setup_net_statistics_process_func)
    // LOAD_EBPF_FUNC(ebpf_setup_net_lost_func)
    // LOAD_EBPF_FUNC(ebpf_setup_print_func)
    LOAD_EBPF_FUNC(ebpf_config)
    LOAD_EBPF_FUNC(ebpf_poll_events)
    LOAD_EBPF_FUNC(ebpf_init)
    LOAD_EBPF_FUNC(ebpf_start)
    LOAD_EBPF_FUNC(ebpf_stop)
    // LOAD_EBPF_FUNC(ebpf_get_fd)
    // LOAD_EBPF_FUNC(ebpf_get_next_key)
    // LOAD_EBPF_FUNC(ebpf_delete_map_value)
    // LOAD_EBPF_FUNC(ebpf_cleanup_dog)
    // LOAD_EBPF_FUNC(ebpf_update_conn_addr)
    // LOAD_EBPF_FUNC(ebpf_disable_process)
    // LOAD_EBPF_FUNC(ebpf_update_conn_role)
    return true;
}

bool EBPFWrapper::Init() {
    if (mInitSuccess) {
        return true;
    }
    int64_t kernelVersion;
    std::string kernelRelease;
    if (!isSupportedOS(kernelVersion, kernelRelease)) {
        std::cout << "init ebpf source failed" << std::endl;
        std::cout << "not supported kernel or OS:" + kernelRelease << std::endl;
        return false;
    }

    std::string btfPath = "/sys/kernel/btf/vmlinux";
    // if (kernelVersion < INT64_FLAG(sls_observer_ebpf_nobtf_kernel_version)) {
    //     btfPath = GetValidBTFPath(kernelVersion, kernelRelease);
    //     if (btfPath.empty()) {
    //         std::cout << "not found any btf files:" + kernelRelease << std::endl;
    //         return false;
    //     }
    // }


    std::string soPath;
    if (!loadEbpfLib(kernelVersion, soPath)) {
        return false;
    }
    // mPacketProcessor = processor;

    g_ebpf_setup_net_data_process_func_func(ebpf_data_process_callback, this);

    int err = g_ebpf_init_func(&btfPath.at(0),
                               static_cast<int32_t>(btfPath.size()),
                               &soPath.at(0),
                               static_cast<int32_t>(soPath.size()));
    if (err) {
        std::cout << "ebpf_init func failed" << std::endl;
        return false;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // uint64_t nowTime = GetCurrentTimeInNanoSeconds();
    // mDeltaTimeNs = nowTime - (uint64_t)ts.tv_sec * 1000000000ULL - (uint64_t)ts.tv_nsec;
    // set_ebpf_int_config((int32_t)PROTOCOL_FILTER, 0, -1);
    // set_ebpf_int_config((int32_t)TGID_FILTER, 0, mConfig->mPid);
    // set_ebpf_int_config((int32_t)SELF_FILTER, 0, getpid());
    // set_ebpf_int_config((int32_t)DATA_SAMPLING, 0, mConfig->mSampling);
    // set_ebpf_int_config((int32_t)PERF_BUFFER_PAGE, (int32_t)DATA_HAND, 512);

 //   LOG_INFO(sLogger, ("init ebpf source", "success"));
    mInitSuccess = true;
    return true;
}

bool EBPFWrapper::Start() {
    if (!mInitSuccess) {
        return false;
    }
    if (mStartSuccess) {
        return true;
    }
    // set_ebpf_int_config((int32_t)PROTOCOL_FILTER, 0, mConfig->mProtocolProcessFlag);
    int err = g_ebpf_start_func == NULL ? -100 : g_ebpf_start_func();
    if (err) {
        std::cout << "start epbf failed" + std::to_string(err) << std::endl;
        this->Stop();
        return false;
    }

    std::cout << "start ebpf succeed" << std::endl;
    mStartSuccess = true;
    return true;
}

bool EBPFWrapper::Stop() {
    mStartSuccess = false;
    return true;
    // int err = g_ebpf_stop_func == NULL ? -100 : g_ebpf_stop_func();
    // if (err) {
    //     LOG_INFO(sLogger, ("stop ebpf", "failed")("error", err));
    //     return false;
    // }
    // return true;
}

int32_t EBPFWrapper::ProcessPackets(int32_t maxProcessPackets, int32_t maxProcessDurationMs) {
    if (g_ebpf_poll_events_func == nullptr || !mStartSuccess) {
        return -1;
    }
    auto res = g_ebpf_poll_events_func(maxProcessPackets, &this->holdOnFlag);
    if (res < 0 && res != -100) {
        std::cout << "pull ebpf events failed:" + std::to_string(res) << std::endl;
    }
    return res;
}

void EBPFWrapper::OnData(struct conn_data_event_t* event) {
    // if (event->attr.msg_buf_size > CONN_DATA_MAX_SIZE) {
    //     std::cout << "invalid ebpf data event because the size is over "
    //                                                + std::to_string(CONN_DATA_MAX_SIZE) << std::endl;
    //     return;
    // }
    // convert data event to PacketEvent
 //   auto* header = (PacketEventHeader*)(&mPacketDataBuffer.at(0));

    
    // if (mPacketProcessor) {
    //     mPacketProcessor(StringPiece(mPacketDataBuffer.data(), sizeof(PacketEventHeader) + sizeof(PacketEventData)));
    // }
}

