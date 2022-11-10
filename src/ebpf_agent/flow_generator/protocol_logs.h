#ifndef __BPF_PROTO_LOGS_H__
#define __BPF_PROTO_LOGS_H__
#include <string>
#include <algorithm>

#include "AppProtocolInfo.h"
#include "Enum.h"
#include "MetaPacket.h"

using namespace std;



struct FlowKey {
    uint16_t vtap_id;
    // tap_type: TapType,
    // tap_port: TapPort,
    //     /* L2 */
    // mac_src: MacAddr,
    // mac_dst: MacAddr,
    // /* L3 ipv4 or ipv6 */
    // ip_src: IpAddr,
    // ip_dst: IpAddr,
    /* L4 */
    uint16_t port_src;
    uint16_t port_dst;

    enum IpProtocol proto;
 };

 


struct AppProtoHead
{
    /* data */
    enum L7Protocol l7proto;
    enum LogMessageType msg_type; // HTTP，DNS: request/response
    enum L7ResponseStatus response_status; // 状态描述： 0: 正常, 1:已废弃使用(先前用于表示异常), 2：不存在，3：服务端异常，4：客户端异常
    
    uint16_t response_code; // HTTP状态码: 1xx-5xx, DNS状态码: 0-7

    uint64_t rrt;
    
    unsigned char version;
};


struct AppProtoLogsBaseInfo {
    
    uint64_t start_time;
    
    unsigned long end_time;
    unsigned long long flow_id;
    //not sure
    int tap_port;
    unsigned short vtap_id;
    //not sure
    int tap_type;
    
    bool is_ipv6;
    //not sure
    int tap_side;
    
    struct AppProtoHead head;
    

    /* L2 */
    //not sure
    char mac_src[6];
    char mac_dst[6];
    /* L3 ipv4 or ipv6 */
    //not sure
    uint32_t ip_src;
    uint32_t ip_dst;
    /* L3EpcID */
    int l3_epc_id_src;
    int l3_epc_id_dst;
    /* L4 */
    unsigned short port_src;
    unsigned short port_dst;
    /* First L7 TCP Seq */
    unsigned int req_tcp_seq;
    unsigned int resp_tcp_seq;

    /* EBPF Info */
    
    uint32_t process_id_0;
    
    uint32_t process_id_1;
    
    string process_kname_0;
    string process_kname_1;
    
    uint64_t syscall_trace_id_request;
    
    uint64_t syscall_trace_id_response;
    
    uint32_t syscall_trace_id_thread_0;
    
    uint32_t syscall_trace_id_thread_1;
    
    uint64_t syscall_cap_seq_0;
    
    uint64_t syscall_cap_seq_1;

    //not sure
    IpProtocol protocol;
    
    bool is_vip_interface_src;
    
    bool is_vip_interface_dst;

public:

    int from_ebpf(MetaPacket *packet, AppProtoHead head,
                            uint16_t vtap_id,
                            int32_t local_epc,
                            int32_t remote_epc);//生成关联字段
    void merge(AppProtoLogsBaseInfo log);
};

enum AppProtoLogsInfoType {
    Dns,
    Mysql,
    Redis,
    Kafka,
    Mqtt,
    Dubbo,
    HttpV1,
    HttpV2,
    HttpV1TLS,

};

struct AppProtoLogsData {
    struct AppProtoLogsBaseInfo base_info;
    AppProtocolInfo special_info;
    uint64_t ebpf_flow_session_id(){
        // 取flow_id(即ebpf底层的socket id)的高8位(cpu id)+低24位(socket id的变化增量), 作为聚合id的高32位
        // 
        uint64_t flow_id_part = (base_info.flow_id >> 56 << 56) | (base_info.flow_id << 40 >> 8); 
        uint64_t session_id = special_info.session_id();
        if (session_id != 0) {
            flow_id_part = flow_id_part | ((uint64_t (base_info.head.l7proto)) << 24) | ((uint64_t (session_id)) & 0xffffff);
        } else {
            uint64_t cap_seq = max(base_info.syscall_cap_seq_0, base_info.syscall_cap_seq_1);
            if (base_info.head.msg_type == Request) {
                cap_seq += 1;
            };
            //types |= (uint64_t(1) << type);
            flow_id_part = flow_id_part | ((uint64_t(base_info.head.l7proto) << 24)) | (cap_seq & 0xffffff);
        }

        //Rust 默认将函数中最后一个表达式的结果作为返回值
        return flow_id_part;

    }

    void session_merge(AppProtoLogsData log) {
        base_info.merge(log.base_info);
        special_info.merge(&(log.special_info));
    }

    // delimited by comma, 每个字段用逗号分隔，头尾没有逗号。
    string to_string() {
        string result = "";

        return result;
    }

    
};




#endif /* __BPF_PROTO_LOGS_H__ */
