#include "MetaPacket.h"
#include <iostream>
#include<algorithm>
#include <string.h>
#include <netinet/in.h>
using namespace std;


uint32_t uchar_to_uint(uint8_t* data_uchar)
{
    uint32_t data_uint;
    data_uint = data_uchar[3];
    data_uint <<= 8;
    data_uint += data_uchar[2];
    data_uint <<= 8;
    data_uint += data_uchar[1];
    data_uint <<= 8;
    data_uint += data_uchar[0];
    return data_uint;
}

void MetaPacket::from_ebpf(struct socket_bpf_data *data, uint32_t capture_size)
{
    cout << "MetaPacket::from_ebpf" << endl;
    uint32_t local_ip, remote_ip;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    if (data->tuple.addr_len == 4) {
        local_ip = uchar_to_uint(data->tuple.rcv_saddr);
        remote_ip = uchar_to_uint(data->tuple.daddr);
        
        // memcpy(&local_ip, data->tuple.rcv_saddr, 4);
        // memcpy(&remote_ip, data->tuple.daddr, 4);
    } else {
        return;

    }

    if (data->direction == 0) {// 出方向
        src_ip = local_ip;
        dst_ip = remote_ip;
        src_port = data->tuple.num;
        dst_port = data->tuple.dport;

    } else {//进方向
        src_ip = remote_ip;
        dst_ip = local_ip;
        src_port = data->tuple.dport;
        dst_port = data->tuple.num;

    }


        // let (src_ip, dst_ip, src_port, dst_port) = if data.direction == SOCK_DIR_SND {
        //     (local_ip, remote_ip, data.tuple.lport, data.tuple.rport)
        // } else {
        //     (remote_ip, local_ip, data.tuple.rport, data.tuple.lport)
        // };
    

    IpProtocol proto = Unknown;
    switch (data->tuple.l4_protocol)
    {
    case IPPROTO_UDP:
        /* code */
        proto = Udp;
        break;
    case IPPROTO_TCP:
        proto = Tcp;
        break;
    
    default:
        break;
    }
    printf("data->tuple.l4_protocol:%d\n", proto);
    printf("data->direction:%d\n", data->direction);

    this->lookup_key = LookupKey {
        .timestamp = data->timestamp,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .l2_end_0 = (data->direction == 0),//SOCK_DIR_SND = 0  出方向
        .l2_end_1 = (data->direction == 1), //SOCK_DIR_RCV = 1 进方向
        .proto = proto, 

    };

    printf("this->lookup_key.proto:%d\n", this->lookup_key.proto);

    int cap_len = min(capture_size, data->cap_len);
    printf("cap_len:%d\n", cap_len);
    // cap_len is 0. to be fixed.

    memcpy(this->raw_from_ebpf, data->cap_data, capture_size);

    free(data->cap_data);


	// printf("%s\n", this->raw_from_ebpf);
    

    // packet.
    //     packet.packet_len = data.syscall_len as usize + 54; // 目前仅支持TCP
    //     packet.payload_len = data.cap_len as u16;
    //     packet.l4_payload_len = data.cap_len as usize;
    //     packet.tap_port = TapPort::from_ebpf(data.process_id);
    this->cap_seq = data->cap_seq;
    this->process_id = data->process_id;
    this->thread_id = data->thread_id;
    this->syscall_trace_id = data->syscall_trace_id_call;
    printf("metapacket->process_id:%d\n", this->process_id);
    printf("metapacket->thread_id:%d\n", this->thread_id);
    printf("metapacket->syscall_trace_id:%llu\n", this->syscall_trace_id);
    char *process_name = (char*)data->process_name;
    this->process_name = string(process_name);
    this->socket_id = data->socket_id;
    printf("metapacket->socket_id:%llu\n", this->socket_id);
    this->tcp_data.seq = (uint32_t)data->tcp_seq;
    L7Protocol l7_protocol = L7_PROTOCOL_UNKNOWN;
    switch (data->l7_protocal_hint)
    {
    case PROTO_HTTP1:
        /* code */
        l7_protocol = L7_PROTOCOL_HTTP1;
        break;
    case PROTO_DUBBO:
        l7_protocol = L7_PROTOCOL_DUBBO;
        break;
    
    default:
        break;
    }

    this->l7_protocol_from_ebpf = l7_protocol; //整型转换成枚举型

    int touch = 0;
    if(data->direction == 0 && data->msg_type == 1) { //出方向的请求
        touch = 1;
        this->direction = ClientToServer;

    } else if (data->direction == 0 && data->msg_type == 2) { //出方向的响应
        touch = 1;
        this->direction = ServerToClient;

    } else if (data->direction == 1 && data->msg_type == 1) { //进方向的请求
        touch = 1;
        this->direction = ClientToServer;
    } else if (data->direction == 1 && data->msg_type == 2) { //进方向的响应
        touch = 1;
        this->direction = ServerToClient;
    }
    if (touch != 1) {
        printf("packet direction is not set. maybe because of data->msg_type is not correct\n");
        printf("data->msg_type:%d\n", data->msg_type);
    }
    cout << "MetaPacket::from_ebpf packet->direction:"<< this->direction << endl;
    
    // this->direction = ClientToServer; //为什么不设置成 data->direction

}

