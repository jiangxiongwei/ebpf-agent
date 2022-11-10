

#include "MetaPacket.h"
#include "FlowItem.h"
#include "SessionAggr.h"
#include<map>


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

const uint32_t CAP_LEN_MAX = 1024;

typedef void (*l7_handle_fn) (void *sd);

class EBPFCollector {

    ~EBPFCollector(){}
    void running_socket_tracer(l7_handle_fn handle,
              int thread_nr,
              uint32_t perf_pages_cnt,
              uint32_t queue_size,
              uint32_t max_socket_entries,
              uint32_t max_trace_entries,
              uint32_t socket_map_max_reclaim);
    
public:
    static EBPFCollector* GetInstance() {
        static auto* sWrapper = new EBPFCollector();
        return sWrapper;
    }
    map<uint64_t, FlowItem> flow_map;
    void process_packet(MetaPacket *packet);
    void process_socket_data(void *sd);
    // void ebpf_callback(struct socket_bpf_data *sd);



};