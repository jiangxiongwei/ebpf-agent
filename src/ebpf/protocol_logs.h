/*
 * Copyright (c) 2022 Perfma Networks
 *
 */

#ifndef __BPF_PROTO_LOGS_H__
#define __BPF_PROTO_LOGS_H__

struct AppProtoHead
{
    /* data */
    //not sure
    int l7proto;
    //not sure
    int msg_type; // HTTP，DNS: request/response
    //not sure
    int response_status; // 状态描述： 0: 正常, 1:已废弃使用(先前用于表示异常), 2：不存在，3：服务端异常，4：客户端异常
    
    unsigned short response_code; // HTTP状态码: 1xx-5xx, DNS状态码: 0-7

    
    unsigned long long rrt;
    
    unsigned char version;
};


struct AppProtoLogsBaseInfo {
    
    unsigned long start_time;
    
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
    int mac_src;
    int mac_dst;
    /* L3 ipv4 or ipv6 */
    //not sure
    int ip_src;
    int ip_dst;
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
    
    unsigned int process_id_0;
    
    unsigned int process_id_1;
    
    char process_kname_0[32];
    char process_kname_1[32];
    
    unsigned long long syscall_trace_id_request;
    
    unsigned long long syscall_trace_id_response;
    
    unsigned int syscall_trace_id_thread_0;
    
    unsigned int syscall_trace_id_thread_1;
    
    unsigned long long syscall_cap_seq_0;
    
    unsigned long long syscall_cap_seq_1;

    //not sure
    int protocol;
    
    bool is_vip_interface_src;
    
    bool is_vip_interface_dst;
};


enum AppProtoLogsInfo {
    Dns,
    Mysql,
    Redis,
    Kafka,
    Mqtt,
    Dubbo,
    HttpV1,
    HttpV2,
    HttpV1TLS
};



struct AppProtoLogsData {
    struct AppProtoLogsBaseInfo base_info;
    enum AppProtoLogsInfo special_info;
    
};



#endif /* __BPF_PROTO_LOGS_H__ */
