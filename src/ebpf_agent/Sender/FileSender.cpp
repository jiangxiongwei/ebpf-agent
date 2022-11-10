#include "FileSender.h"
#include <fstream>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include<string>
using namespace std;

void FileSender::send(AppProtoLogsData log)
{

    char saddr_str[64]={'\0'};
	char daddr_str[64]={'\0'};

    cout << "FileSender::send " << endl;
    std::ofstream ofs;
    ofs.open("AppProtoLogsData.txt", std::ios::app);

    AppProtoLogsBaseInfo base_info = log.base_info;
    AppProtoHead head = log.base_info.head;

    int process_id;
    string process_name;

    uint32_t src_ip = base_info.ip_src;
    uint32_t dst_ip = base_info.ip_dst;

    inet_ntop(AF_INET, &src_ip, saddr_str, 64);
	inet_ntop(AF_INET, &dst_ip, daddr_str, 64);
    uint16_t src_port = base_info.port_src;
    uint16_t dst_port = base_info.port_dst;
     
    uint32_t req_tcp_seq = base_info.req_tcp_seq;
    uint32_t resp_tcp_seq = base_info.resp_tcp_seq;
    uint64_t syscall_trace_id_request = base_info.syscall_trace_id_request;
    
    uint64_t syscall_trace_id_response = base_info.syscall_trace_id_response;
    uint16_t protocol = (uint16_t) base_info.protocol;
    uint16_t l7_proto = (uint16_t) head.l7proto;

    LogMessageType msg_type = head.msg_type;

    if(msg_type == Request) {
        process_id = base_info.process_id_0;
        process_name = base_info.process_kname_0;

    } else {
        process_id = base_info.process_id_1;
        process_name = base_info.process_kname_1;
    }
    string output = to_string(process_id) + ",";
    output += process_name + ",";
    output += string(saddr_str) + ",";
    output += to_string(src_port) + ",";
    output += string(daddr_str) + ",";
    output += to_string(dst_port) + ",";
    output += to_string(req_tcp_seq) + ",";
    output += to_string(resp_tcp_seq) + ",";
    output += to_string(syscall_trace_id_request) + ",";
    output += to_string(syscall_trace_id_response) + ",";
    output += to_string(protocol) + ",";
    output += to_string(l7_proto) + ",";
    output += to_string(msg_type);
    
    ofs << output << std::endl;
    ofs.flush();
    ofs.close();

}