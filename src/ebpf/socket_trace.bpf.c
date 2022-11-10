/*
 * Copyright (c) 2022 Perfma
 * Author: Jiang Xiongwei
 * Date: 2022/09/28 
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "socket_trace.h"
#include "protocol_inference.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NS_PER_US		1000ULL
#define NS_PER_SEC		1000000000ULL
#define EVENT_BURST_NUM            1


int target_pid = 0;

/*
 * 向用户态传递数据的专用map
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} __socket_data SEC(".maps");


/*
 * 一个 struct  __socket_data 变量的大小超过了 512 字节，无法放到 BPF 栈上，
 * 因此声明一个 size=1 的 per-CPU array 来存放 struct __socket_data 变量
 */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct __socket_data_buffer);
} __data_buf SEC(".maps");


/*
 * 这是个hashmap，用于记录socket信息，
 * Key is {pid + fd}. value is struct socket_info_t
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct socket_info_t);
} socket_info_map SEC(".maps");

/*
 * 这是个hashmap，用于记录trace_id，
 * Key is {tgid, pid}. value is trace_info_t
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct trace_info_t);
} trace_map SEC(".maps");

/*
 * write() syscall's input argument.
 * Key is {tgid, pid}
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_write_args_map SEC(".maps");

/*
 * read() syscall's input argument.
 * Key is {tgid, pid}
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

/*
 * 记录追踪各种ID值(确保唯一性, pre cpu 没有使用锁）
 * 生成方法：
 *		1、先初始化一个基值（基值 = [CPU IDX: 8bit] + [ sys_boot_time ]）
 *		2、在基值的基础上递增
 */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct trace_uid_t);
} trace_uid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct trace_stats);
} trace_stats_map SEC(".maps");


static __inline void *get_socket_from_fd(int fd_num)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file = NULL;

	struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
	bpf_probe_read(&file, sizeof(file), fd + fd_num);

	if (file == NULL)
		return NULL;
	void *private_data = NULL;

	struct file *__file = file;
	private_data = BPF_CORE_READ(__file, private_data);

	if (private_data == NULL) {
		return NULL;
	}

	struct socket *socket = private_data;
	short socket_type;
	void *check_file;
	void *sk;

	socket_type = BPF_CORE_READ(socket, type);
	check_file = BPF_CORE_READ(socket, file);
	sk = BPF_CORE_READ(socket, sk);

	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file /*&& __socket.state == SS_CONNECTED */ ) {
		return sk;
	}

	return NULL;
}

static __inline void delete_socket_info(u64 conn_key,
					struct socket_info_t *socket_info_ptr)
{
	if (socket_info_ptr == NULL)
		return;

	u32 k0 = 0;

	struct trace_stats *trace_stats = bpf_map_lookup_elem(&trace_stats_map, &k0);
	if (trace_stats == NULL)
		return;
	bpf_map_delete_elem(&socket_info_map, &conn_key);
	trace_stats->socket_map_count--;
}

// check if tcp or udp

static __inline int is_tcp_udp_data(void *sk,
				    struct conn_info_t *conn_info)
{

	struct sock *__sk = (struct sock *)sk;
	struct sock_common  __sk_common;
	struct sock_common *sk_common = sk;


	unsigned short skc_family = 0;
	unsigned char skc_ipv6only = 0;

	bpf_probe_read_kernel(&__sk_common, sizeof(__sk_common), (void *)&__sk->__sk_common);

//	bpf_probe_read_kernel(&skc_family, sizeof(skc_family), &__sk_common.skc_family);

	skc_family = __sk_common.skc_family;


	conn_info->skc_family = skc_family;

	
//	bpf_printk("conn_info->skc_family: %d \n", conn_info->skc_family);

	skc_ipv6only = BPF_CORE_READ_BITFIELD_PROBED(sk_common, skc_ipv6only);

	conn_info->skc_ipv6only = skc_ipv6only;
//	bpf_printk("skc_ipv6only: %d\n", conn_info->skc_ipv6only);


//	bpf_core_read(&conn_info->skc_family, sizeof(conn_info->skc_family),
//		      &__sk->__sk_common.skc_family);


	/*
	 * Without thinking about PF_UNIX.
	 */
	switch (conn_info->skc_family) {
	case PF_INET:
		break;
	case PF_INET6:
		if (conn_info->skc_ipv6only == 0)
			conn_info->skc_family = PF_INET;
		break;
	default:
		return SOCK_CHECK_TYPE_ERROR;
	}

	extern __u32 LINUX_KERNEL_VERSION __kconfig;
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 6, 0))
		bpf_core_read(&conn_info->sk_type, sizeof(conn_info->sk_type), &__sk->sk_type);
	else
		conn_info->sk_type = BPF_CORE_READ_BITFIELD_PROBED(__sk, sk_type);



	if (conn_info->sk_type == SOCK_DGRAM) {
		bpf_printk("SOCK_DGRAM udp\n");
		conn_info->tuple.l4_protocol = IPPROTO_UDP;
		return SOCK_CHECK_TYPE_UDP;
	}

	if (conn_info->sk_type != SOCK_STREAM) {
		bpf_printk("SOCK_STREAM tcp\n");
		return SOCK_CHECK_TYPE_ERROR;
	}

	unsigned char skc_state;


	bpf_core_read(&skc_state, sizeof(unsigned short),
		      &__sk->__sk_common.skc_state);

//	bpf_printk("skc_state: %d\n", skc_state);
	/* 如果连接尚未建立好，不处于ESTABLISHED或者CLOSE_WAIT状态，退出 */
	if ((1 << skc_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
		return SOCK_CHECK_TYPE_ERROR;
	}

	conn_info->tuple.l4_protocol = IPPROTO_TCP;


	return SOCK_CHECK_TYPE_TCP_ES;
}

static __inline void init_conn_info(__u32 tgid, __u32 fd,
				    struct conn_info_t *conn_info,
				    void *sk)
{
//	bpf_printk("init_conn_info \n");
	__be16 inet_dport;
	__u16 inet_sport;

	int saddr;
	int daddr;

	struct sock *__sk = sk;
	bpf_core_read(&inet_dport, sizeof(inet_dport),
		      &__sk->__sk_common.skc_dport);
	bpf_core_read(&inet_sport, sizeof(inet_sport),
		      &__sk->__sk_common.skc_num);

	conn_info->tuple.dport = __bpf_ntohs(inet_dport);
	conn_info->tuple.num = inet_sport;
	conn_info->prev_count = 0;
	conn_info->direction = 0;
	*((__u32 *) conn_info->prev_buf) = 0;
	conn_info->need_reconfirm = false;
//	conn_info->correlation_id = -1; // 当前用于kafka协议推断
	conn_info->fd = fd;
	conn_info->role = ROLE_UNKNOWN;

	conn_info->sk = sk;
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);
	conn_info->socket_info_ptr =
//			socket_info_map__lookup(&conn_key);
			bpf_map_lookup_elem(&socket_info_map, &conn_key);
	conn_info->keep_data_seq = false;
}



static __inline bool get_socket_info(struct __socket_data *v,
				     void *sk,
				     struct conn_info_t* conn_info)
{
	/*
	 * 下面if判断在linux5.2版本会出现指令超限问题
	 * 而去掉下面两个行linux5.13，Linux5.3版本（也可能有其他版本）的内核则会出现指令超限问题。
	 * 目前的解决方案: 保留判断, 为linux5.2内核单独编译。
	 */
#ifndef LINUX_VER_5_2 	
	if (v == NULL || sk == NULL)
		return false;
#endif

	struct sock *__sk = sk;

	/*
	 * Without thinking about PF_UNIX.
	 */

	switch (conn_info->skc_family) {
	case PF_INET:
		bpf_core_read(v->tuple.rcv_saddr, 4,
			      &__sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(v->tuple.daddr, 4,
			      &__sk->__sk_common.skc_daddr);	

		v->tuple.addr_len = 4;
		break;
	case PF_INET6:
		bpf_core_read(v->tuple.rcv_saddr, 16,
			      &__sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(v->tuple.daddr, 16,
			      &__sk->__sk_common.skc_v6_daddr);	

		v->tuple.addr_len = 16;
		break;
	default:
		return false;
	}

	return true;
}

static __inline void infer_l7_class(struct conn_info_t* conn_info,
				    enum traffic_direction direction, const char* buf,
				    size_t count, __u8 sk_type,
				    const struct process_data_extra *extra) {

//	bpf_printk("infer_l7_class \n");
	if (conn_info == NULL) {
		return;
	}

	// 推断应用协议
	struct protocol_message_t inferred_protocol =
		infer_protocol(buf, count, conn_info, sk_type, extra);
	if (inferred_protocol.protocol == PROTO_UNKNOWN &&
	    inferred_protocol.type == MSG_UNKNOWN) {
		conn_info->protocol = PROTO_UNKNOWN;
		return;
	}

	conn_info->protocol = inferred_protocol.protocol;
	conn_info->message_type = inferred_protocol.type;
}

static __inline void trace_process(struct socket_info_t *socket_info_ptr,
				   struct conn_info_t *conn_info,
				   __u64 socket_id, __u64 pid_tgid,
				   struct trace_info_t *trace_info_ptr,
				   struct trace_uid_t *trace_uid,
				   struct trace_stats *trace_stats,
				   __u64 *thread_trace_id,
				   __u64 time_stamp) {
	
	__u64 pre_trace_id = 0;
	if (is_socket_info_valid(socket_info_ptr) &&
	    conn_info->direction == socket_info_ptr->direction &&
	    conn_info->message_type == socket_info_ptr->msg_type) {
		if (trace_info_ptr)
			pre_trace_id = trace_info_ptr->thread_trace_id;
		conn_info->keep_data_seq = true; // 同时这里确保捕获数据的序列号保持不变。
	}

	if (conn_info->direction == T_INGRESS) { //在入方向，创建trace
		struct trace_info_t trace_info = { 0 };
		*thread_trace_id = trace_info.thread_trace_id =
				(pre_trace_id == 0 ? ++trace_uid->thread_trace_id : pre_trace_id);
		
		trace_info.update_time = time_stamp / NS_PER_SEC;
		trace_info.socket_id = socket_id;
	//	trace_map__update(&pid_tgid, &trace_info);
		bpf_map_update_elem(&trace_map, &pid_tgid, &trace_info, BPF_ANY);
		if (!trace_info_ptr)
			trace_stats->trace_map_count++;
	} else { /* direction == T_EGRESS */
		if (trace_info_ptr) {
			/*
			 * 追踪在不同socket之间进行，而对于在同一个socket的情况进行忽略。
			 */
			if (socket_id != trace_info_ptr->socket_id) {
				*thread_trace_id = trace_info_ptr->thread_trace_id;
			} else {
				*thread_trace_id = 0;
			}

			trace_stats->trace_map_count--;
		}

		//trace_map__delete(&pid_tgid);
		bpf_map_delete_elem(&trace_map, &pid_tgid);
	}
}

static __inline int iovecs_copy(struct __socket_data *v,
				struct __socket_data_buffer *v_buff,
				const struct data_args_t* args,
				size_t syscall_len,
				__u32 send_len)
{
#define LOOP_LIMIT 12

	struct copy_data_s {
		char data[CAP_DATA_SIZE];
	};

	__u32 len;
	struct copy_data_s *cp;
	int bytes_sent = 0;
	__u32 iov_size;
	__u32 total_size = 0;

	if (syscall_len >= sizeof(v->data))
		total_size = sizeof(v->data);
	else
		total_size = send_len;

#pragma unroll
	for (unsigned int i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < total_size; ++i) {
		struct iovec iov_cpy;
		bpf_probe_read(&iov_cpy, sizeof(struct iovec), &args->iov[i]);

		const int bytes_remaining = total_size - bytes_sent;
		iov_size = iov_cpy.iov_len < bytes_remaining ? iov_cpy.iov_len : bytes_remaining;

		len = v_buff->len + offsetof(typeof(struct __socket_data), data) + bytes_sent;
		cp = (struct copy_data_s *)(v_buff->data + len);
		if (len > (sizeof(v_buff->data) - sizeof(*cp)))
			return bytes_sent;

		if (iov_size >= sizeof(cp->data)) {
			bpf_probe_read(cp->data, sizeof(cp->data), iov_cpy.iov_base);
			iov_size = sizeof(cp->data);
		} else {
			iov_size = iov_size & (sizeof(cp->data) - 1);
			// 使用'iov_size + 1'代替'iov_size'，来适应inux 4.14.x
			bpf_probe_read(cp->data, iov_size + 1, iov_cpy.iov_base);
		}

		bytes_sent += iov_size;
	}

	return bytes_sent;
}


static __u32 __inline get_tcp_write_seq_from_fd(int fd)
{
	void *sock = get_socket_from_fd(fd);
	__u32 tcp_seq = 0;
	struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
	bpf_core_read(&tcp_seq, sizeof(tcp_seq), &tcp_sock->write_seq);
	return tcp_seq;
}

static __u32 __inline get_tcp_read_seq_from_fd(int fd)
{
	void *sock = get_socket_from_fd(fd);
	__u32 tcp_seq = 0;
	struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
	bpf_core_read(&tcp_seq, sizeof(tcp_seq), &tcp_sock->copied_seq);
	return tcp_seq;
}


static __inline void
data_submit(struct pt_regs *ctx, struct conn_info_t *conn_info,
	    const struct data_args_t *args, const bool vecs, __u32 syscall_len,
	    __u64 time_stamp,
	    const struct process_data_extra *extra)

{
	if (conn_info == NULL) {
		return;
	}

	if (conn_info->sk == NULL || conn_info->message_type == MSG_UNKNOWN) {
		return;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32) (pid_tgid >> 32);
	if (time_stamp == 0)
		time_stamp = bpf_ktime_get_ns();
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);

	if (conn_info->message_type == MSG_CLEAR) {
		delete_socket_info(conn_key, conn_info->socket_info_ptr);
		return;
	}

	__u32 tcp_seq = 0;
	__u64 thread_trace_id = 0;

	if (conn_info->direction == T_INGRESS && conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		tcp_seq = get_tcp_read_seq_from_fd(conn_info->fd);
	} else if (conn_info->direction == T_EGRESS && conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		tcp_seq = get_tcp_write_seq_from_fd(conn_info->fd);
	}

	__u32 k0 = 0;
	struct socket_info_t sk_info = { 0 };
	struct trace_uid_t *trace_uid = bpf_map_lookup_elem(&trace_uid_map, &k0);
	if (trace_uid == NULL)
		return;

	struct trace_stats *trace_stats = bpf_map_lookup_elem(&trace_stats_map, &k0);
	if (trace_stats == NULL)
		return;

	struct trace_info_t *trace_info_ptr = bpf_map_lookup_elem(&trace_map, &pid_tgid);

	struct socket_info_t *socket_info_ptr = conn_info->socket_info_ptr;
	// 'socket_id' used to resolve non-tracing between the same socket
	__u64 socket_id = 0;
	if (!is_socket_info_valid(socket_info_ptr)) {
		// Not use "++trace_uid->socket_id" here,
		// because it did not pass the verification of linux 4.14.x, 4.15.x
		socket_id = trace_uid->socket_id + 1;
	} else {
		socket_id = socket_info_ptr->uid;
	}

	// (jiping) set thread_trace_id = 0 for go process
	if (conn_info->message_type != MSG_PRESTORE &&
	    conn_info->message_type != MSG_RECONFIRM)
		trace_process(socket_info_ptr, conn_info, socket_id, pid_tgid, trace_info_ptr,
			      trace_uid, trace_stats, &thread_trace_id, time_stamp);

	if (!is_socket_info_valid(socket_info_ptr)) {
		if (socket_info_ptr && conn_info->direction == T_EGRESS) {
			sk_info.peer_fd = socket_info_ptr->peer_fd;
			thread_trace_id = socket_info_ptr->trace_id;
		}

		sk_info.uid = trace_uid->socket_id + 1;
		trace_uid->socket_id++; // Ensure that socket_id is incremented.
		sk_info.l7_proto = conn_info->protocol;
		sk_info.direction = conn_info->direction;
		sk_info.role = conn_info->role;
		sk_info.msg_type = conn_info->message_type;
		sk_info.update_time = time_stamp / NS_PER_SEC;
		sk_info.need_reconfirm = conn_info->need_reconfirm;
//		sk_info.correlation_id = conn_info->correlation_id;

		/*
		 * MSG_PRESTORE 目前只用于MySQL, Kafka协议推断
		 */
		if (conn_info->message_type == MSG_PRESTORE) {
			*(__u32 *)sk_info.prev_data = *(__u32 *)conn_info->prev_buf;
			sk_info.prev_data_len = 4;
			sk_info.uid = 0;
		}
		bpf_map_update_elem(&socket_info_map, &conn_key, &sk_info, BPF_ANY);
//		socket_info_map__update(&conn_key, &sk_info);
		if (socket_info_ptr == NULL)
			trace_stats->socket_map_count++;
	}

	/*
	 * 对于预先存储数据或socket l7协议类型需要再次确认(适用于长链接)
	 * 的动作只建立socket_info_map项不会发送数据给用户态程序。
	 */
	if (conn_info->message_type == MSG_PRESTORE ||
	    conn_info->message_type == MSG_RECONFIRM)
		return;

	if (is_socket_info_valid(socket_info_ptr)) {
		sk_info.uid = socket_info_ptr->uid;

		/*
		 * 同方向多个连续请求或回应的场景时，
		 * 保持捕获数据的序列号保持不变。
		 */
		if (conn_info->keep_data_seq)
			sk_info.seq = socket_info_ptr->seq;
		else
			sk_info.seq = ++socket_info_ptr->seq;

		socket_info_ptr->direction = conn_info->direction;
		socket_info_ptr->msg_type = conn_info->message_type;
		socket_info_ptr->update_time = time_stamp / NS_PER_SEC;
		if (socket_info_ptr->peer_fd != 0 && conn_info->direction == T_INGRESS) {
			__u64 peer_conn_key = gen_conn_key_id((__u64)tgid,
							      (__u64)socket_info_ptr->peer_fd);
			struct socket_info_t *peer_socket_info_ptr = bpf_map_lookup_elem(&socket_info_map, &peer_conn_key);
			if (is_socket_info_valid(peer_socket_info_ptr))
				peer_socket_info_ptr->trace_id = thread_trace_id;
		}

		if (conn_info->direction == T_EGRESS && socket_info_ptr->trace_id != 0) {
			thread_trace_id = socket_info_ptr->trace_id;
			socket_info_ptr->trace_id = 0;
		}
	}


	struct __socket_data_buffer *v_buff = bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		return;

	struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];

	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		return;
	v = (struct __socket_data *)(v_buff->data + v_buff->len);
	if (get_socket_info(v, conn_info->sk, conn_info) == false)
		return;

	v->tuple.l4_protocol = conn_info->tuple.l4_protocol;

	v->tuple.dport = conn_info->tuple.dport;
	v->tuple.num = conn_info->tuple.num;
	v->data_type = conn_info->protocol;

	v->socket_id = sk_info.uid;
	v->data_seq = sk_info.seq;
	v->tgid = tgid;
	v->pid = (__u32) pid_tgid;
	v->timestamp = time_stamp;
	v->direction = conn_info->direction;
	v->syscall_len = syscall_len;
	v->msg_type = conn_info->message_type;
	v->tcp_seq = 0;
	if (conn_info->tuple.l4_protocol == IPPROTO_TCP)
		v->tcp_seq = tcp_seq - syscall_len;

	v->thread_trace_id = thread_trace_id;
	bpf_get_current_comm(v->comm, sizeof(v->comm));

	if (conn_info->prev_count > 0) {
		// 注意这里没有调整v->syscall_len和v->len我们会在用户层做。
		v->extra_data = *(__u32 *)conn_info->prev_buf;
		v->extra_data_count = conn_info->prev_count;
		v->tcp_seq -= conn_info->prev_count; // 客户端和服务端的tcp_seq匹配
	} else
		v->extra_data_count = 0;

	if (extra->use_tcp_seq)
		v->tcp_seq = extra->tcp_seq;

	v->coroutine_id = extra->coroutine_id;
	/*
	 * the bitwise AND operation will set the range of possible values for
	 * the UNKNOWN_VALUE register to [0, BUFSIZE)
	 */
	__u32 len = syscall_len & (sizeof(v->data) - 1);
	if (vecs) {
		len = iovecs_copy(v, v_buff, args, syscall_len, len);
	} else {
		if (syscall_len >= sizeof(v->data)) {
			unsigned int size = sizeof(v->data);
			size = size & BUFF_SIZE_MAX;
			bpf_printk("sizeof v->data : %d \n", size);
			if (unlikely(bpf_probe_read(v->data, size, args->buf) != 0))
				return;
			len = sizeof(v->data);
		} else {
			/*
			 * https://elixir.bootlin.com/linux/v4.14/source/kernel/bpf/verifier.c#812
			 * __check_map_access() 触发条件检查（size <= 0）
			 * ```
			 *     if (off < 0 || size <= 0 || off + size > map->value_size)
			 * ```
			 * "invalid access to map value, value_size=10888 off=135 size=0"
			 * 使用'len + 1'代替'len'，来规避（Linux 4.14.x）这个检查。
			 */
			if (unlikely(bpf_probe_read(v->data,
						    len + 1,
						    args->buf) != 0))
				return;
		}
	}

	v->data_len = len;
	v_buff->len += offsetof(typeof(struct __socket_data), data) + v->data_len;
	v_buff->events_num++;

	if (v_buff->events_num == EVENT_BURST_NUM) {
		__u32 buf_size = (v_buff->len + offsetof(typeof(struct __socket_data_buffer), data))
				 & (sizeof(*v_buff) - 1);
		if (buf_size >= sizeof(*v_buff)) {
			// bpf_perf_event_output(ctx, &NAME(socket_data),
			// 		      BPF_F_CURRENT_CPU, v_buff,
			// 		      sizeof(*v_buff));
			bpf_ringbuf_output(&NAME(socket_data), v_buff, sizeof(*v_buff), 0);

		} else {
			/* 使用'buf_size + 1'代替'buf_size'，来规避（Linux 4.14.x）长度检查 */
			// bpf_perf_event_output(ctx, &NAME(socket_data),
			// 		      BPF_F_CURRENT_CPU, v_buff,
			// 		      buf_size + 1);
			bpf_ringbuf_output(&NAME(socket_data), v_buff, buf_size + 1, 0);

		}

		v_buff->events_num = 0;
		v_buff->len = 0;
	}

}

static __inline void process_data(struct pt_regs *ctx, __u64 id,
				  const enum traffic_direction direction,
				  const struct data_args_t *args,
				  ssize_t bytes_count,
				  const struct process_data_extra *extra)
{
	__u32 tgid = id >> 32;

	if (!extra)
		return;

	if (!extra->vecs && args->buf == NULL)
		return;

	if (extra->vecs && (args->iov == NULL || args->iovlen <= 0))
		return;

	if (unlikely(args->fd < 0 || (int)bytes_count <= 0))
		return;

	// 根据配置对进程号进行过滤
	if (tgid != target_pid) {
		return;
	}
	
	void *sk = get_socket_from_fd(args->fd);
	struct conn_info_t *conn_info, __conn_info = {};
	conn_info = &__conn_info;
	__u8 sock_state;
	if (!(sk != NULL &&
	      ((sock_state = is_tcp_udp_data(sk, conn_info))
	       != SOCK_CHECK_TYPE_ERROR))) {
		return;
	}

	init_conn_info(tgid, args->fd, &__conn_info, sk);
	conn_info->direction = direction;

	if (!extra->vecs) {
		infer_l7_class(conn_info, direction, args->buf, bytes_count, sock_state, extra);
	} else {
		struct iovec iov_cpy;
		bpf_probe_read(&iov_cpy, sizeof(struct iovec), &args->iov[0]);
		// Ensure we are not reading beyond the available data.
		const size_t buf_size = iov_cpy.iov_len < bytes_count ? iov_cpy.iov_len : bytes_count;
		infer_l7_class(conn_info, direction, iov_cpy.iov_base, buf_size, sock_state, extra);
	}

	// When at least one of protocol or message_type is valid, 
	// data_submit can be performed, otherwise MySQL data may be lost
	if (conn_info->protocol != PROTO_UNKNOWN ||
	    conn_info->message_type != MSG_UNKNOWN) {
		data_submit(ctx, conn_info, args, extra->vecs,
			    (__u32)bytes_count, args->enter_ts, extra);
	}
}

static __inline void process_syscall_data(struct pt_regs* ctx, __u64 id,
					  const enum traffic_direction direction,
					  const struct data_args_t* args, ssize_t bytes_count) {
	struct process_data_extra extra = {};
	process_data(ctx, id, direction, args, bytes_count, &extra);

}

static __inline void process_syscall_data_vecs(struct pt_regs* ctx, __u64 id,
					       const enum traffic_direction direction,
					       const struct data_args_t* args,
					       ssize_t bytes_count) {
	struct process_data_extra extra = {
		.vecs = true,
	};
	process_data(ctx, id, direction, args, bytes_count, &extra);
}

/***********************************************************
 * BPF syscall probe/tracepoint function entry-points
 ***********************************************************/

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    if(syscall_id != 268)    // 过滤系统调用 id，只处理 fchmodat 系统调用
        return 0;

    struct pt_regs *regs;
    regs = (struct pt_regs *) ctx->args[0];

    char pathname[256];
    u32 mode;

    // 读取第二个参数的值
    char *pathname_ptr = (char *) PT_REGS_PARM2_CORE(regs);
    bpf_core_read_user_str(&pathname, sizeof(pathname), pathname_ptr);

    // 读取第三个参数的值
    mode = (u32) PT_REGS_PARM3_CORE(regs);

    char fmt[] = "fchmodat %s %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), &pathname, mode);
    return 0;
}


SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct syscalls_enter_write_args *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_WRITE;
	write_args.fd = fd;
	write_args.buf = buf;
	write_args.enter_ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

	return 0;

}


SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct syscalls_exit_write_args *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
	// Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
	if (write_args != NULL && write_args->fd > 2) {
		process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}

	bpf_map_delete_elem(&active_write_args_map, &id);
//	active_write_args_map__delete(&id);
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write_1(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
	// Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
	if (write_args != NULL && write_args->fd > 2) {
		process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}

//	active_write_args_map__delete(&id);
	bpf_map_delete_elem(&active_write_args_map, &id);
	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_READ;
	read_args.fd = fd;
	read_args.buf = buf;

	bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

	return 0;

}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
	// Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
	if (read_args != NULL && read_args->fd > 2) {
		struct process_data_extra extra = {};
		process_data((struct pt_regs *)ctx, id, T_INGRESS, read_args,
			     bytes_count, &extra);
	}

	bpf_map_delete_elem(&active_read_args_map, &id);
	return 0;

}


// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
//		const struct sockaddr *dest_addr, socklen_t addrlen);
SEC("tp/syscalls/sys_enter_sendto")
int handle_enter_sendto(struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_SENDTO;
	write_args.fd = sockfd;
	write_args.buf = buf;
	write_args.enter_ts = bpf_ktime_get_ns();
//	active_write_args_map__update(&id, &write_args);
	bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

	bpf_printk("sys_enter_sendto BPF triggered from PID %d. and fd:%d \n", id, sockfd);

	return 0;

}

SEC("tp/syscalls/sys_exit_sendto")
int handle_exit_sendto(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;

	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);

	bpf_printk("sys_exit_sendto BPF triggered from PID %d. and count:%d \n", id, bytes_count);
	if (write_args != NULL) {
		process_syscall_data((struct pt_regs*)ctx, id, T_EGRESS, write_args, bytes_count);
	}

//	active_write_args_map__delete(&id);
	bpf_map_delete_elem(&active_write_args_map, &id);

	
	return 0;

}


// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//		  struct sockaddr *src_addr, socklen_t *addrlen);
SEC("tp/syscalls/sys_enter_recvfrom")
int handle_enter_recvfrom(struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_SENDTO;
	read_args.fd = sockfd;
	read_args.buf = buf;
	read_args.enter_ts = bpf_ktime_get_ns();
//	active_write_args_map__update(&id, &write_args);
	bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

	bpf_printk("sys_enter_recvfrom BPF triggered from PID %d. and fd:%d \n", id, sockfd);

	return 0;

}


// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
SEC("tp/syscalls/sys_exit_recvfrom")
int handle_exit_recvfrom(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);

	bpf_printk("sys_exit_recvfrom BPF triggered from PID %d. and count:%d \n", id, bytes_count);
	if (read_args != NULL) {
		process_syscall_data((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}

	bpf_map_delete_elem(&active_read_args_map, &id);

	
	return 0;

}




SEC("kprobe/__sys_sendmsg")
int BPF_KPROBE(__sys_sendmsg, int fd, struct user_msghdr *msg, unsigned int flags, bool forbid_cmsg_compat)
{
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = fd;
	struct user_msghdr *msghdr_ptr = (struct user_msghdr *)msg;
	if (msghdr_ptr != NULL) {
		// Stash arguments.
		struct user_msghdr *msghdr, __msghdr;
		bpf_probe_read(&__msghdr, sizeof(__msghdr), msghdr_ptr);
		msghdr = &__msghdr;
		// Stash arguments.
		struct data_args_t write_args = {};
		write_args.source_fn = SYSCALL_FUNC_SENDMSG;
		write_args.fd = sockfd;
		write_args.iov = msghdr->msg_iov;
		write_args.iovlen = msghdr->msg_iovlen;
		write_args.enter_ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
	//	active_write_args_map__update(&id, &write_args);
	}

	return 0;

}

SEC("tp/syscalls/sys_exit_sendmsg")
int handle_exit_sendmsg(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
	if (write_args != NULL) {
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}
	bpf_map_delete_elem(&active_write_args_map, &id);
	return 0;

}


SEC("kprobe/__sys_sendmmsg")
int BPF_KPROBE(__sys_sendmmsg, int fd, struct mmsghdr *mmsg, unsigned int vlen,
			unsigned int flags, bool forbid_cmsg_compat)
{
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = fd;
	struct mmsghdr *msgvec_ptr = (struct mmsghdr *)mmsg;
	if (msgvec_ptr != NULL && vlen >= 1) {
		struct mmsghdr *msgvec, __msgvec;
		bpf_probe_read(&__msgvec, sizeof(__msgvec), msgvec_ptr);
		msgvec = &__msgvec;
		// Stash arguments.
		struct data_args_t write_args = {};
		write_args.source_fn = SYSCALL_FUNC_SENDMMSG;
		write_args.fd = sockfd;
		write_args.iov = msgvec[0].msg_hdr.msg_iov;
		write_args.iovlen = msgvec[0].msg_hdr.msg_iovlen;
		write_args.msg_len = (void *)msgvec_ptr + offsetof(typeof(struct mmsghdr), msg_len); //&msgvec[0].msg_len;
		write_args.enter_ts = bpf_ktime_get_ns();
//		active_write_args_map__update(&id, &write_args);
		bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
	}

	return 0;

}


// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendmmsg/format

SEC("tp/syscalls/sys_exit_sendmmsg")
int handle_exit_sendmmsg(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();

	int num_msgs = ctx->ret;

	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
	if (write_args != NULL && num_msgs > 0) {
		ssize_t bytes_count;
		bpf_probe_read(&bytes_count, sizeof(write_args->msg_len), write_args->msg_len);
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}
//	active_write_args_map__delete(&id);
	bpf_map_delete_elem(&active_write_args_map, &id);

	return 0;

}


SEC("kprobe/__sys_recvmsg")
int BPF_KPROBE(__sys_recvmsg, int fd, struct user_msghdr  *msg,
			unsigned int flags, bool forbid_cmsg_compat)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct user_msghdr __msg, *msghdr = (struct user_msghdr *)msg;
	int sockfd = (int) fd;

	if (msghdr != NULL) {
		bpf_probe_read(&__msg, sizeof(__msg), (void *)msghdr);
		msghdr = &__msg;
		// Stash arguments.
		struct data_args_t read_args = {};
		read_args.source_fn = SYSCALL_FUNC_RECVMSG;
		read_args.fd = sockfd;
		read_args.iov = msghdr->msg_iov;
		read_args.iovlen = msghdr->msg_iovlen;

		bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

	}

	return 0;

}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvmsg/format

SEC("tp/syscalls/sys_exit_recvmsg")
int handle_exit_recvmsg(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
	if (read_args != NULL) {
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}
	bpf_map_delete_elem(&active_read_args_map, &id);
	return 0;

}


// int __sys_recvmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen,
//		   unsigned int flags, struct timespec *timeout)
SEC("kprobe/__sys_recvmmsg")
int BPF_KPROBE(__sys_recvmmsg, int fd, struct mmsghdr *mmsg,
			unsigned int vlen, unsigned int flags,
			struct __kernel_timespec  *timeout)
{
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)fd;
	struct mmsghdr *msgvec = (struct mmsghdr *)mmsg;

	if (msgvec != NULL && vlen >= 1) {
		int offset;
		// Stash arguments.
		struct data_args_t read_args = {};
		read_args.source_fn = SYSCALL_FUNC_RECVMMSG;
		read_args.fd = sockfd;

		offset = offsetof(typeof(struct mmsghdr), msg_hdr) +
				offsetof(typeof(struct user_msghdr), msg_iov);

		bpf_probe_read(&read_args.iov, sizeof(read_args.iov), (void *)msgvec + offset);

		offset = offsetof(typeof(struct mmsghdr), msg_hdr) +
				offsetof(typeof(struct user_msghdr), msg_iovlen);

		bpf_probe_read(&read_args.iovlen, sizeof(read_args.iovlen), (void *)msgvec + offset);

		read_args.msg_len = (void *)msgvec + offsetof(typeof(struct mmsghdr), msg_len);

		bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
	}
	
	return 0;


}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvmmsg/format

SEC("tp/syscalls/sys_exit_recvmmsg")
int handle_exit_recvmmsg(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int num_msgs = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
	if (read_args != NULL && num_msgs > 0) {
		ssize_t bytes_count;
		bpf_probe_read(&bytes_count, sizeof(read_args->msg_len), read_args->msg_len);
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}
	bpf_map_delete_elem(&active_read_args_map, &id);

	return 0;
}

//static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,
//			 unsigned long vlen, rwf_t flags)
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
SEC("kprobe/do_writev")
int BPF_KPROBE(do_writev, unsigned long fd, const struct iovec  *vec,
			unsigned long vlen, rwf_t flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct iovec *iov = (struct iovec *)vec;
	int iovlen = (int)vlen;

	// Stash arguments.
	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_WRITEV;
	write_args.fd = fd;
	write_args.iov = iov;
	write_args.iovlen = iovlen;
	write_args.enter_ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
	
	return 0;

}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_writev/format
SEC("tp/syscalls/sys_exit_writev")
int handle_exit_writev(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;

	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
	if (write_args != NULL) {
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}
	bpf_map_delete_elem(&active_write_args_map, &id);
	return 0;


}


// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
SEC("kprobe/do_readv")
int BPF_KPROBE(do_readv, unsigned long fd, const struct iovec  *vec,
			unsigned long vlen, rwf_t flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct iovec *iov = (struct iovec *)vec;
	int iovlen = (int)vlen;

	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_READV;
	read_args.fd = fd;
	read_args.iov = iov;
	read_args.iovlen = iovlen;

	bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

	return 0;


}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_readv/format
SEC("tp/syscalls/sys_exit_readv")
int handle_exit_readv(struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
	if (read_args != NULL) {
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}
	bpf_map_delete_elem(&active_read_args_map, &id);
	return 0;

}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/format
// 为什么不用tcp_fin? 主要原因要考虑UDP场景。
SEC("tp/syscalls/sys_enter_close")
int handle_enter_close(struct syscall_comm_enter_ctx *ctx) {

	int fd = ctx->fd;
//	CHECK_OFFSET_READY(fd);

	__u64 sock_addr = (__u64)get_socket_from_fd(fd);
	if (sock_addr) {
		__u64 conn_key = gen_conn_key_id(bpf_get_current_pid_tgid() >> 32, (__u64)fd);
		struct socket_info_t *socket_info_ptr = bpf_map_lookup_elem(&socket_info_map, &conn_key);
		if (socket_info_ptr != NULL)
			delete_socket_info(conn_key, socket_info_ptr);
	}

	return 0;


}