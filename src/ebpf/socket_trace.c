/*
 * Copyright (c) 2022 Perfma
 * Author: Jiang Xiongwei
 * Date: 2022/10/09
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket_trace.h"
#include "socket_trace.skel.h"


struct socket_trace_bpf *skel;

int u_target_pid = 0;
struct ring_buffer *rb = NULL;

#define MAX_PKT_BURST 16

volatile uint64_t sys_boot_time_ns;

typedef int (*handle_event_func_t)(void *ctx, void *event, size_t size);

handle_event_func_t handle_event_func = NULL;


// typedef void (*sock_data_process_func_t)(void* custom_data, struct conn_data_event_t* event);

// sock_data_process_func_t handle_event_func = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


static int handle_event(void *ctx, void *raw, size_t raw_size)
{

    /*
	 * In the following, the socket data buffer is processed.
	 */

	struct __socket_data_buffer *sdb = (struct __socket_data_buffer *)raw;

	int start = 0;
	struct __socket_data *sd;

	// 确定分发到哪个队列上，通过第一个socket_data来确定
	sd = (struct __socket_data *)&sdb->data[start];


	printf("length:%llu \n",sdb->len);



//	struct socket_bpf_data *burst_data[MAX_PKT_BURST];
	
	struct socket_bpf_data *submit_data, __submit_data = {};
	submit_data = &__submit_data;

	submit_data->socket_id = sd->socket_id;

	// 数据捕获时间戳，精度为微秒(us)
	submit_data->timestamp =
		    (sd->timestamp + sys_boot_time_ns) / 1000ULL;

	submit_data->tuple = sd->tuple;
	submit_data->direction = sd->direction;
	submit_data->l7_protocal_hint = sd->data_type;
	submit_data->need_reconfirm = false;		    
	submit_data->process_id = sd->tgid;
	submit_data->thread_id = sd->pid;
	submit_data->cap_data = sd->data;

	printf("%s \n", submit_data->cap_data);
	int i = 0;
	while(submit_data->cap_data[i++] != '0') {
		printf("%x ", submit_data->cap_data[i++]);
	}

	// submit_data->coroutine_id = sd->coroutine_id;

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
	// printf("data: %s \n", submit_data->cap_data);

#if 0

	struct socket_bpf_data *submit_data;

	int len;
	void *data_buf_ptr;

	// 所有载荷的数据总大小（去掉头）
	int alloc_len = CACHE_LINE_ROUNDUP(sizeof(*submit_data));
	void *socket_data_ptr = malloc(alloc_len);
	if (socket_data_ptr == NULL) {
		ebpf_warning("malloc() error.\n");
	//	atomic64_inc(&q->heap_get_faild);
		return;
	}

	submit_data = (struct socket_bpf_data *)socket_data_ptr;

	submit_data->socket_id = sd->socket_id;

	// 数据捕获时间戳，精度为微秒(us)
	submit_data->timestamp =
		(sd->timestamp + sys_boot_time_ns) / 1000ULL;

	submit_data->tuple = sd->tuple;
	submit_data->direction = sd->direction;
	submit_data->l7_protocal_hint = sd->data_type;
	
	submit_data->need_reconfirm = false;
	submit_data->process_id = sd->tgid;
	submit_data->thread_id = sd->pid;
	submit_data->coroutine_id = sd->coroutine_id;
	submit_data->cap_data =
		    (char *)((void **)&submit_data->cap_data + 1);
	submit_data->syscall_len = sd->syscall_len;
	submit_data->tcp_seq = sd->tcp_seq;
	submit_data->cap_seq = sd->data_seq;
	submit_data->syscall_trace_id_call = sd->thread_trace_id;
	memcpy(submit_data->process_name,
		       sd->comm, sizeof(submit_data->process_name));
	submit_data->process_name[sizeof(submit_data->process_name) -
					  1] = '\0';
	submit_data->msg_type = sd->msg_type;

		
	int offset = 0;
	if (len > 0) {
		if (sd->extra_data_count > 0) {
				*(uint32_t *) submit_data->cap_data =
				    sd->extra_data;
				offset = sizeof(sd->extra_data);
		}

		memcpy_fast(submit_data->cap_data + offset, sd->data,
				    len);
		submit_data->cap_data[len + offset] = '\0';
	}
	submit_data->syscall_len += offset;
	submit_data->cap_len = len + offset;
#endif 
    return 0;
}

int ebpf_init(char *btf, int btf_size, char *so, int so_size)
{
	int err;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
//	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = socket_trace_bpf__open();
 	if (!skel) {
 		fprintf(stderr, "Failed to open BPF skeleton\n");
 		return 1;
 	}

	skel->bss->target_pid = u_target_pid;

	/* Open load and verify BPF application */
	err = socket_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return 1;
	}
	return 0;	

}

int ebpf_start()
{
	int err;
	/* Attach tracepoint handler */
	err = socket_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */

	if (handle_event_func != NULL) {
		rb = ring_buffer__new(bpf_map__fd(skel->maps.__socket_data), handle_event_func, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cleanup;
		}
	} else {
		fprintf(stderr, "handle_event_func is NULL\n");
		goto cleanup;
	}

	return 0;

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	socket_trace_bpf__destroy(skel);
	return -err;

}

int ebpf_stop()
{
	ring_buffer__free(rb);
	socket_trace_bpf__destroy(skel);


	return 0;
}

void ebpf_config_target_pid_func(int target_id)
{

	fprintf(stdout, "target_id is set\n");

	u_target_pid = target_id;

}

void ebpf_setup_handle_event_func(handle_event_func_t func)
{
	handle_event_func = func;
}

void ebpf_setup_net_data_process_func()
{



}


int ebpf_poll_events(int32_t max_events, int32_t* stop_flag)
{
	/* Poll for available data and consume records, if any are available.
 * Returns number of records consumed (or INT_MAX, whichever is less), or
 * negative number, if any of the registered callbacks returned error.
 */
	int err;
	err = ring_buffer__poll(rb, 20000 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
	if (err == -EINTR) {
		err = 0;
		goto out;
	}
	if (err < 0) {
		printf("Error polling perf buffer: %d\n", err);
		printf("errno: %d\n", errno);
		printf("%s\n", strerror(errno));
	}

out:
	return err;


}

int main(int argc, char **argv)
{
	
	struct socket_trace_bpf *skel;
	int err;
	struct ring_buffer *rb = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
//	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = socket_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = socket_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}


	/* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.__socket_data), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

	while (!stop) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }		
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	socket_trace_bpf__destroy(skel);
	return -err;
}
