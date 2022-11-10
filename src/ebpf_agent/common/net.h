#ifndef __NET_H__
#define __NET_H__
#include <stdint.h>

#define CAP_DATA_SIZE 1024

struct __tuple_t {
    uint8_t daddr[16];
	uint8_t rcv_saddr[16];
	uint8_t addr_len;
	uint8_t l4_protocol;
	uint16_t dport;
	uint16_t num;
};

struct socket_bpf_data {
	/* session info */
	uint32_t process_id;	   // tgid in kernel struct task_struct
	uint32_t thread_id;	   // pid in kernel struct task_struct, main thread iff pid==tgid
	uint64_t coroutine_id;	   // CoroutineID, i.e., golang goroutine id
	uint8_t  process_name[16]; // 进程名字

	struct __tuple_t tuple;	   // Socket五元组信息
	uint64_t socket_id;	   // Socket的唯一标识，从启动时的时钟开始自增1
	uint16_t l7_protocal_hint; // 应用数据（cap_data）的协议类型，枚举如下：1 SOCK_DATA_HTTP1, 2 SOCK_DATA_DNS, 3 ...
				   // 存在一定误判性（例如标识为A协议但实际上是未知协议，或标识为多种协议），上层应用应继续深入判断
	uint8_t msg_type;	   // 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)
	bool need_reconfirm; 	   // 是否需要上层再确认 

	/* trace info */
	uint64_t tcp_seq;		   // 收发cap_data数据时TCP协议栈将会用到的TCP SEQ，可用于关联eBPF DATA与网络中的TCP Packet
	uint64_t syscall_trace_id_call;    // 应用数据的追踪ID，若应用为协程，L7代理、应用层负载均衡等类型时，可利用此值追踪一个请求或响应
					   // 同一份应用数据（cap_data可能不同）接收、发送的两份cap_data会标记上相同标识

	/* data info */
	uint64_t timestamp;	// cap_data获取的时间戳
	uint8_t  direction;	// 数据的收发方向，枚举如下: 1 SOCK_DIR_SND, 2 SOCK_DIR_RCV
	uint64_t syscall_len;	// 本次系统调用读、写数据的总长度
	uint32_t cap_len;	// 返回的cap_data长度
	uint64_t cap_seq;	// cap_data在Socket中的相对顺序号，从启动时的时钟开始自增1，用于数据乱序排序
	char  *cap_data;        // 返回的应用数据
};

struct __socket_data {
	/* 进程/线程信息 */
	uint32_t pid;  // 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	uint32_t tgid; // 进程号
	uint64_t coroutine_id; // CoroutineID, i.e., golang goroutine id
	uint8_t  comm[16]; // 进程或线程名

	/* 连接（socket）信息 */
	uint64_t socket_id;     /* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	uint32_t extra_data;
	uint32_t extra_data_count;

	/* 追踪信息 */
	uint32_t tcp_seq;
	uint64_t thread_trace_id;

	/* 追踪数据信息 */
	uint64_t timestamp;     // 数据捕获时间戳
	uint8_t  direction: 1;  // bits[0]: 方向，值为T_EGRESS(0), T_INGRESS(1)
	uint8_t  msg_type:  7;  // bits[1-7]: 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)

	uint64_t syscall_len;   // 本次系统调用读、写数据的总长度
	uint64_t data_seq;      // cap_data在Socket中的相对顺序号
	uint16_t data_type;     // HTTP, DNS, MySQL
	uint16_t data_len;      // 数据长度
	char data[CAP_DATA_SIZE];
} __attribute__((packed));

/*
 * 整个结构大小为2^15（强制为2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	uint32_t events_num;
	uint32_t len; // data部分长度
	char data[32760]; // 32760 + len(4bytes) + events_num(4bytes) = 2^15 = 32768
};



#endif //__NET_H__