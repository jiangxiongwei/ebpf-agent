#include "EBPFCollector.h"
#include <map>
#include <thread>
#include<functional>
#include<string.h>

#include "SessionAggr.h"
#include "Sender.h"
#include "FileSender.h"

using namespace std;


volatile uint64_t sys_boot_time_ns;


// static void handle_packet(MetaPacket *packet) {
//     //应用解析，根据packet，生成ebpf_flow_id, 然后去LRU cache 中找，然后调用flow_item.handle，其中主要是调用parse，
//     //流聚合，
//     //发给app，继续处理。app上的处理逻辑还没有看过。

//     chrono::duration<uint64_t> l7_log_session_timeout(60);
//     l7_log_session_timeout.count();

//     chrono::seconds _l7_log_session_timeout(60);
//     _l7_log_session_timeout.count();

//     FileSender output;

//     SessionAggr aggr(l7_log_session_timeout, output);

    
    
//     uint64_t key = packet->ebpf_flow_id();
//     map<uint64_t, FlowItem>::iterator iter = this->flow_map.find(key);
//     FlowItem flow_item;
//     if (iter != flow_map.end()) {
//         flow_item = (FlowItem)iter->second;
//     } else {
//         AppTable app_table;
//         LogParserConfig log_parser_config;
//         flow_item = FlowItem(app_table, packet, 0, 0, log_parser_config);
//         flow_map.insert(pair<uint64_t, FlowItem>(key, flow_item));
//     }
//     vector<AppProtoLogsData> datas;
//     datas = flow_item.handle(packet, NULL, 0, 0);
//     for(int i = 0; i < datas.size(); i++) {
//         AppProtoLogsData log = datas[i];
//         aggr.handle(log);

//     }

// }



void EBPFCollector::process_socket_data(void *event)
{

	cout << "EBPFCollector::process_socket_data" << endl;

    struct __socket_data_buffer *sdb = (struct __socket_data_buffer *)event;

	int start = 0;
	struct __socket_data *sd;

	// 确定分发到哪个队列上，通过第一个socket_data来确定
	sd = (struct __socket_data *)&sdb->data[start];


    struct socket_bpf_data *submit_data, __submit_data = {};
	submit_data = &__submit_data;

	submit_data->socket_id = sd->socket_id;

	// 数据捕获时间戳，精度为微秒(us)
	submit_data->timestamp =
		    (sd->timestamp + sys_boot_time_ns) / 1000ULL;

	submit_data->tuple = sd->tuple;
	submit_data->direction = sd->direction;
	printf("sd->direction:%d\n", sd->direction);
	submit_data->l7_protocal_hint = sd->data_type;
	submit_data->need_reconfirm = false;		    
	submit_data->process_id = sd->tgid;
	printf("sd->tgid:%d\n", sd->tgid);
	submit_data->thread_id = sd->pid;
	printf("sd->pid:%d\n", sd->pid);
	submit_data->syscall_len = sd->syscall_len;
	submit_data->tcp_seq = sd->tcp_seq;
	submit_data->cap_seq = sd->data_seq;
	submit_data->syscall_trace_id_call = sd->thread_trace_id;
	memcpy(submit_data->process_name,
		       sd->comm, sizeof(submit_data->process_name));
	submit_data->process_name[sizeof(submit_data->process_name) -
					  1] = '\0';
	submit_data->msg_type = sd->msg_type;

	printf("sd->msg_type:%d\n", sd->msg_type);

	//申请堆上的内存
	submit_data->cap_data = (char *)malloc(CAP_LEN_MAX);

	int offset = 0;
	int len = sd->data_len;

	printf("sd->data_len:%d\n", sd->data_len);
	if (len > 0) {
		if (sd->extra_data_count > 0) {
			*(uint32_t *) submit_data->cap_data = sd->extra_data;
			offset = sizeof(sd->extra_data);
		}

		memcpy(submit_data->cap_data + offset, sd->data, len);
		submit_data->cap_data[len + offset] = '\0';
	}
	submit_data->syscall_len += offset;
	submit_data->cap_len = len + offset;

	printf("submit_data->cap_len:%d\n", submit_data->cap_len);

	// memcpy(submit_data->cap_data, sd->data, CAP_LEN_MAX);

	
	// printf("sd->data\n");
	// printf("%s\n", sd->data);
	// printf("submit_data->cap_data\n");
	// printf("%s\n", submit_data->cap_data);

	// submit_data->cap_data =
	// 	    (char *)((void **)&submit_data->cap_data + 1);


	// submit_data->syscall_len = sd->syscall_len;
	// submit_data->tcp_seq = sd->tcp_seq;
	// submit_data->cap_seq = sd->data_seq;
	// submit_data->syscall_trace_id_call = sd->thread_trace_id;
	// memcpy(submit_data->process_name,
	// 	       sd->comm, sizeof(submit_data->process_name));
	// submit_data->process_name[sizeof(submit_data->process_name) -
	// 				  1] = '\0';
	// submit_data->msg_type = sd->msg_type;

	// int offset = 0;
	// int len = sd->data_len;
	// if (len > 0) {
	// 	if (sd->extra_data_count > 0) {
	// 		*(uint32_t *) submit_data->cap_data = sd->extra_data;
	// 		offset = sizeof(sd->extra_data);
	// 	}

	// 	memcpy(submit_data->cap_data + offset, sd->data, len);
	// 	submit_data->cap_data[len + offset] = '\0';
	// }
	// submit_data->syscall_len += offset;
	// submit_data->cap_len = len + offset;

    MetaPacket* packet = new MetaPacket();
    packet->from_ebpf(submit_data, CAP_LEN_MAX); //最多取1024 bytes

    /*TODO 交给线程池去执行
     * thread new_thread(handle_event, packet);
     */
    this->process_packet(packet);



}


void EBPFCollector::process_packet(MetaPacket *packet){
    //应用解析，根据packet，生成ebpf_flow_id, 然后去LRU cache 中找，然后调用flow_item.handle，其中主要是调用parse，
    //流聚合，
    //发给app，继续处理。app上的处理逻辑还没有看过。

	cout << "EBPFCollector::process_packet" << endl;

    chrono::duration<uint64_t> l7_log_session_timeout(60);
    l7_log_session_timeout.count();

    chrono::seconds _l7_log_session_timeout(60);
    _l7_log_session_timeout.count();

    FileSender *output = new FileSender();

    SessionAggr aggr(l7_log_session_timeout, output);

    
    uint64_t key = packet->ebpf_flow_id();
	cout << "packet->ebpf_flow_id:" + to_string(key) << endl; 
    map<uint64_t, FlowItem>::iterator iter = flow_map.find(key);

    FlowItem flow_item;
    if (iter != flow_map.end()) {
		cout << "flow_item is found" << endl;
        flow_item = (FlowItem)iter->second;
    } else {
		cout << "flow_item not found" << endl;
        AppTable app_table;
        LogParserConfig log_parser_config;
        flow_item = FlowItem(app_table, packet, 0, 0, log_parser_config);
        flow_map.insert(pair<uint64_t, FlowItem>(key, flow_item));
    }

    vector<AppProtoLogsData> datas;

    datas = flow_item.handle(packet, NULL, 0, 0);

    for(int i = 0; i < datas.size(); i++) {
        AppProtoLogsData log = datas[i];
        aggr.handle(log);

    }

}