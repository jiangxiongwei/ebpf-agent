#ifndef __BPF_SOCKET_H__
#define __BPF_SOCKET_H__

#include "common.h"
#include "bpf_base.h"
#include "bpf_endian.h"

#define CAP_DATA_SIZE 1024
#define BUFF_SIZE (1 << 11)
#define BUFF_SIZE_MAX (BUFF_SIZE - 1)

#define PF_INET 2
#define PF_INET6    10

#define SOCK_CHECK_TYPE_ERROR           0
#define SOCK_CHECK_TYPE_UDP             1
#define SOCK_CHECK_TYPE_TCP_ES          2


#ifndef unlikely
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

#define __inline inline __attribute__((__always_inline__))

enum endpoint_role {
	ROLE_UNKNOWN,
	ROLE_CLIENT,
	ROLE_SERVER
};

struct __tuple_t {
	__u8 daddr[16];
	__u8 rcv_saddr[16];
	__u8 addr_len;
	__u8 l4_protocol;
	__u16 dport;
	__u16 num;
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
	__u32 pid;  // 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	__u32 tgid; // 进程号
	__u64 coroutine_id; // CoroutineID, i.e., golang goroutine id
	__u8  comm[16]; // 进程或线程名

	/* 连接（socket）信息 */
	__u64 socket_id;     /* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	__u32 extra_data;
	__u32 extra_data_count;

	/* 追踪信息 */
	__u32 tcp_seq;
	__u64 thread_trace_id;

	/* 追踪数据信息 */
	__u64 timestamp;     // 数据捕获时间戳
	__u8  direction: 1;  // bits[0]: 方向，值为T_EGRESS(0), T_INGRESS(1)
	__u8  msg_type:  7;  // bits[1-7]: 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)

	__u64 syscall_len;   // 本次系统调用读、写数据的总长度
	__u64 data_seq;      // cap_data在Socket中的相对顺序号
	__u16 data_type;     // HTTP, DNS, MySQL
	__u16 data_len;      // 数据长度
	char data[CAP_DATA_SIZE];
} __attribute__((packed));

/*
 * 整个结构大小为2^15（强制为2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	__u32 events_num;
	__u32 len; // data部分长度
	char data[32760]; // 32760 + len(4bytes) + events_num(4bytes) = 2^15 = 32768
};

struct socket_info_t {
	__u64 l7_proto: 8;
	__u64 seq: 56; // socket 读写数据的序列号，用于排序

	/*
	 * mysql, kafka这种类型在读取数据时，先读取4字节
	 * 然后再读取剩下的数据，这里用于对预先读取的数据存储
	 * 用于后续的协议分析。
	 */
	__u8 prev_data[4];
	__u8 direction: 1;
	__u8 msg_type: 2;	// 保存数据类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)
	__u8 role: 5;           // 标识socket角色：ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOWN
	bool need_reconfirm;    // l7协议推断是否需要再次确认。
//	__s32 correlation_id;   // 目前用于kafka协议推断。

	__u32 peer_fd;		// 用于记录socket间数据转移的对端fd。

	/*
	 * 一旦有数据读/写就会更新这个时间，这个时间是从系统开机开始
	 * 到更新时的间隔时间单位是秒。
	 */
	__u32 update_time;
	__u32 prev_data_len;
	__u64 trace_id;
	__u64 uid; // socket唯一标识ID
}  __attribute__((packed));

struct trace_info_t {
	__u32 update_time; // 从系统开机开始到创建/更新时的间隔时间单位是秒
	__u32 peer_fd;	   // 用于socket之间的关联
	__u64 thread_trace_id; // 线程追踪ID
	__u64 socket_id; // Records the socket associated when tracing was created (记录创建追踪时关联的socket)
};

struct trace_uid_t {
	__u64 socket_id;       // 会话标识
	__u64 coroutine_trace_id;  // 同一协程的数据转发关联
	__u64 thread_trace_id; // 同一进程/线程的数据转发关联，用于多事务流转场景
};

struct trace_stats {
	__u64 socket_map_count;     // 对socket 链接表进行统计
	__u64 trace_map_count;     // 对同一进程/线程的多次转发表进行统计
};

struct process_data_extra {
	bool vecs : 1;
	bool go : 1;
	bool tls : 1;
	bool use_tcp_seq : 1;
	__u32 tcp_seq;
	__u64 coroutine_id;
};

enum syscall_src_func {
	SYSCALL_FUNC_UNKNOWN,
	SYSCALL_FUNC_WRITE,
	SYSCALL_FUNC_READ,
	SYSCALL_FUNC_SEND,
	SYSCALL_FUNC_RECV,
	SYSCALL_FUNC_SENDTO,
	SYSCALL_FUNC_RECVFROM,
	SYSCALL_FUNC_SENDMSG,
	SYSCALL_FUNC_RECVMSG,
	SYSCALL_FUNC_SENDMMSG,
	SYSCALL_FUNC_RECVMMSG,
	SYSCALL_FUNC_WRITEV,
	SYSCALL_FUNC_READV,
	SYSCALL_FUNC_SENDFILE
};

struct data_args_t {
	// Represents the function from which this argument group originates.
	enum syscall_src_func source_fn;
	__u32 fd;
	// For send()/recv()/write()/read().
	const char *buf;
	// For sendmsg()/recvmsg()/writev()/readv().
	const struct iovec *iov;
	size_t iovlen;
	union {
		// For sendmmsg()
		unsigned int *msg_len;
		// For clock_gettime()
		struct timespec *timestamp_ptr;
	};
	// Timestamp for enter syscall function.
	__u64 enter_ts;
};



struct conn_info_t {
#ifdef PROBE_CONN
	__u64 id;
#endif
	struct __tuple_t tuple;
	__u16 skc_family;	/* PF_INET, PF_INET6... */
	__u16 sk_type;		/* socket type (SOCK_STREAM, etc) */
	__u8 skc_ipv6only;
	bool need_reconfirm;  // socket l7协议类型是否需要再次确认。
	bool keep_data_seq;   // 保持捕获数据的序列号不变为true，否则为false。
	__u32 fd;
	void *sk;

	// The protocol of traffic on the connection (HTTP, MySQL, etc.).
	enum traffic_protocol protocol;
	// MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE
	enum message_type message_type;

	enum traffic_direction direction; //T_INGRESS or T_EGRESS
	enum endpoint_role role;
	size_t prev_count;
	char prev_buf[4];
//	__s32 correlation_id; // 目前用于kafka判断
	enum traffic_direction prev_direction;
	struct socket_info_t *socket_info_ptr; /* lookup __socket_info_map */
};

struct syscalls_enter_sendto_args {
    unsigned long long unused;
    long syscall_nr;
    int fd; 
    void *buff;
    unsigned long len;
    unsigned int flags;
    struct sockaddr *add;
    int addr_len;
 };

 struct syscalls_enter_recvfrom_args {
 	unsigned long long unused;
 	long syscall_nr;
	int fd;
 	void *ubuf;
 	unsigned long size;
 	unsigned int flags;
 	struct sockaddr *add;
 	int *addr_len;
 };

struct syscalls_enter_write_args {
    unsigned long long unused;
    long syscall_nr;
    int fd; 
    void *buf;
    unsigned long count;
};

struct syscalls_exit_write_args {
 	unsigned long long unused;
 	long syscall_nr;
 	unsigned ret;
 };

 struct syscall_comm_enter_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	union {
		struct {
			__u64 fd;		/*  offset:16   8  */
			char *buf;		/*  offset:24   8  */
		};

		// For clock_gettime()
		struct {
			clockid_t which_clock; /*   offset:16   8  */
			struct timespec * tp;  /*   offset:24   8  */
		};
	};
	size_t count;		/*    32     8 */
};


struct syscall_comm_exit_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	__u64 ret;		/*    offset:16    8 */
};

static __inline __u64 gen_conn_key_id(__u64 param_1, __u64 param_2)
{
	/*
	 * key:
	 *  - param_1 low 32bits as key high bits.
	 *  - param_2 low 32bits as key low bits.
	 */
	return ((param_1 << 32) | (__u32)param_2);
}




#endif /* BPF_SOCKET_H__ */
