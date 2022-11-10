#include "protocol_logs.h"
#include "MetaPacket.h"
#include <stdio.h>
#include <string.h>
#include "Enum.h"




int AppProtoLogsBaseInfo::from_ebpf(MetaPacket *packet, AppProtoHead head,
                            uint16_t vtap_id,
                            int32_t local_epc,
                            int32_t remote_epc)
{
    cout << "AppProtoLogsBaseInfo::from_ebpf" << endl;
    bool is_src = packet->lookup_key.l2_end_0;  //出方向，就是src
    PacketDirection direction = packet->direction;
    AppProtoLogsBaseInfo *info = new AppProtoLogsBaseInfo ();
    info->start_time = packet->lookup_key.timestamp;
    info->end_time = packet->lookup_key.timestamp;
    /*   flow_id */
    info->flow_id =  packet->socket_id;
 //   info->tap_port = packet->tap_port;
 //   info->tap_type =             tap_type: TapType::Tor,
   //         is_ipv6: packet.lookup_key.dst_ip.is_ipv6(),
    if (is_src) {

        info->tap_side = ClientProcess;
    } else {
        info->tap_side = ServerProcess;
    }
    strcpy(this->mac_src, packet->lookup_key.src_mac);
    memcpy(this->mac_dst, packet->lookup_key.dst_mac, 6);
    // this->ip_src
    //         ip_src: packet.lookup_key.src_ip,
    //         ip_dst: packet.lookup_key.dst_ip,
    this->ip_src = packet->lookup_key.src_ip;
    this->ip_dst = packet->lookup_key.dst_ip;
    this->port_src = packet->lookup_key.src_port;
    this->port_dst = packet->lookup_key.dst_port;
    this->protocol = packet->lookup_key.proto;
    //process_id_0 表示发出包的进程id，process_id_1表示收到包的进程id
    this->process_id_0 = is_src ? packet->process_id : 0;
    this->process_id_1 = !is_src ? packet->process_id : 0;
    if (is_src) {
        this->process_kname_0 = packet->process_name;
    } else {
        this->process_kname_0 = "";

    }
    if (!is_src) {
        this->process_kname_1 = packet->process_name;
    } else {
        this->process_kname_1 = "";

    }
    if (direction == ClientToServer) {
        this->syscall_trace_id_request = packet->syscall_trace_id;
        this->req_tcp_seq = packet->tcp_data.seq;
        this->syscall_trace_id_thread_0 = packet->thread_id;
        this->syscall_cap_seq_0 = packet->cap_seq;

    } else {
        this->syscall_trace_id_request = 0;
        this->req_tcp_seq = 0;
        this->syscall_trace_id_thread_0 = 0;
        this->syscall_cap_seq_0 = 0;
    }

    if (direction == ServerToClient) {
        this->syscall_trace_id_response = packet->syscall_trace_id;
        this->resp_tcp_seq = packet->tcp_data.seq;
        this->syscall_trace_id_thread_1 = packet->thread_id;
        this->syscall_cap_seq_1 = packet->cap_seq;

    } else {
        this->syscall_trace_id_response = 0;
        this->resp_tcp_seq = 0;
        this->syscall_trace_id_thread_1 = 0;
        this->syscall_cap_seq_1 = 0;
    }

    this->vtap_id = vtap_id;
    this->head = head;

    this->l3_epc_id_src = is_src ? local_epc : remote_epc;
    this->l3_epc_id_dst = is_src ? remote_epc : local_epc;
    this->is_vip_interface_src = false;
    this->is_vip_interface_dst = false;
    if (direction == ServerToClient) {
        swap(info->mac_src, info->mac_dst);
        swap(info->ip_src, info->ip_dst);
        swap(info->l3_epc_id_src, info->l3_epc_id_dst);
        swap(info->port_src, info->port_dst);
        swap(info->process_id_0, info->process_id_1);
        swap(info->process_kname_0, info->process_kname_1);
        if (info->tap_side == ClientProcess) {
            info->tap_side = ServerProcess;
        } else {
            info->tap_side = ClientProcess;
        }
    }

        // return info;
        return 0;

}

void AppProtoLogsBaseInfo::merge(AppProtoLogsBaseInfo log)
{
    if (log.process_id_0 > 0) {
        this->process_id_0 = log.process_id_0;
        this->process_kname_0 = log.process_kname_0;
    }
    if (log.process_id_1 > 0) {
        this->process_id_1 = log.process_id_1;
        this->process_kname_1 = log.process_kname_1;
    }
    this->syscall_trace_id_thread_1 = log.syscall_trace_id_thread_1;
    this->syscall_cap_seq_1 = log.syscall_cap_seq_1;

    //    self.end_time = log.end_time.max(self.start_time);
    this->resp_tcp_seq = log.resp_tcp_seq;
    this->syscall_trace_id_response = log.syscall_trace_id_response;
    this->head.msg_type = LogMessageType::Session;
    this->head.response_code = log.head.response_code;
    //    self.head.code = log.head.code;
    this->head.response_status = log.head.response_status;
    this->head.rrt = log.head.rrt;

}