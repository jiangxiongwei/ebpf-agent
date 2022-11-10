

#include "DynamicLibHelper.h"
#include <atomic>
#include <vector>
#include <functional>
#include <unordered_map>

enum callback_type_e {
    CTRL_HAND = 0,
    DATA_HAND,
    STAT_HAND,
    MAX_HAND,
};

enum ebpf_config_primary_e {
    PROTOCOL_FILTER = 0, // 默认值-1。协议类型过滤器，为-1时代表Trace所有协议，其他只允许某一协议
    TGID_FILTER, // 默认值-1。进程过滤器，为-1时代表Trace所有进程，其他只允许某一进程
    SELF_FILTER, // 默认值-1。是否Disable自身的Trace，为-1代表不Disable，其他情况会传入本进程的ID，这时需要过滤掉该进程所有的数据
    PORT_FILTER, // 默认值-1。端口过滤器，为-1时代表Trace所有端口，其他只允许某一端口
    DATA_SAMPLING, // 默认值100。采样策略，取值0 -> 100，代表采样的百分比(0全部丢弃，100全部上传)
    // 采样的策略：tcp的包，连接建立的ns时间 % 100，
    // 小于采样率即为需要上传，大于的话对该连接进行标记，不上传Data、Ctrl（统计数据还是要上传）
    //           udp的包，接收到数据包的ns时间 % 100， 小于采样率即为需要上传，大于的话不上传Data（统计数据还是要上传
    //           @note 要注意统计数据Map的清理策略）
    PERF_BUFFER_PAGE, // ring buffer page count, 默认128个页，也就是512KB, opt2 的类型是 callback_type_e
};

class EBPFWrapper {
public:
    // explicit EBPFWrapper(NetworkConfig* config) : mConfig(config) {
    //     mPacketDataBuffer.resize(CONN_DATA_MAX_SIZE + 4096);
    // }

    ~EBPFWrapper() { Stop(); }

    static EBPFWrapper* GetInstance() {
        static auto* sWrapper = new EBPFWrapper();
//        sWrapper->mConnectionMetaManager = ConnectionMetaManager::GetInstance();
        return sWrapper;
    }

    bool Init();

    bool Start();

    bool Stop();

    void HoldOn() { holdOnFlag = 1; }

    void Resume() { holdOnFlag = 0; }

    int32_t ProcessPackets(int32_t maxProcessPackets, int32_t maxProcessDurationMs);

//    NetStaticticsMap& GetStatistics() { return mStatistics; }

    void OnData(struct conn_data_event_t* event);
    // void OnCtrl(struct conn_ctrl_event_t* event);
    // void OnStat(struct conn_stats_event_t* event);
    // void OnLost(enum callback_type_e type, uint64_t count);

    // void DisableProcess(uint32_t pid);
    // static uint32_t ConvertConnIdToSockHash(struct connect_id_t* id);
    // void ProbeProcessStat();
    // void CleanAllDisableProcesses();
    // int32_t GetDisablesProcessCount();


private:
    // static uint64_t readStat(uint64_t pid);

private:
    DynamicLibLoader* mEBPFLib = NULL;
    // std::function<int(StringPiece)> mPacketProcessor;
    std::int32_t holdOnFlag{0};
    std::string mPacketDataBuffer;
    bool mInitSuccess = false;
    bool mStartSuccess = false;
    uint64_t mDeltaTimeNs = 0;
    std::unordered_map<uint32_t, uint64_t> mDisabledProcesses;


    // bool isAppendMySQLMsg(conn_data_event_t* pEvent);
    /**
     * @param kernelVersion
     * @param kernelRelease
     * @return true if kernel version >= sls_observer_ebpf_min_kernel_version or kernel version equals to 3.10.x in
     * centos 7.6+.
     */
    bool isSupportedOS(int64_t& kernelVersion, std::string& kernelRelease);
    bool loadEbpfLib(int64_t kernelVersion, std::string& soPath);
};