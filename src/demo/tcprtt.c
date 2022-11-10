
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
#include "tcprtt.h"
#include "tcprtt.skel.h"
//static int handle_event(void *ctx, void *data, size_t size);

struct tcprtt_bpf *skel;

struct ring_buffer *rb = NULL;

typedef int (*handle_event_func_t)(void *ctx, void *event, size_t size);

handle_event_func_t handle_func = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

void print_output_header()
{
	printf("timestamp    pid   saddr:sport   daddr:dport   srtt\n");

}


static int handle_event(void *ctx, void *data, size_t size)
{
	const struct ipv4_data_t *ipv4_data = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char saddr_str[64]={'\0'};
	char daddr_str[64]={'\0'};

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);


	inet_ntop(AF_INET, &ipv4_data->saddr, saddr_str, 64);
	inet_ntop(AF_INET, &ipv4_data->daddr, daddr_str, 64);

	printf("%-8s %-8d %s:%-6d %s:%-6d %-6d \n", 
			ts, ipv4_data->pid, saddr_str, ntohs(ipv4_data->sport), daddr_str,
			ntohs(ipv4_data->dport), ipv4_data->srtt_ms);
//	printf("\n");	

    return 0;
}

void ebpf_setup_handle_event_func(handle_event_func_t func)
{
	handle_func = func;
}

int ebpf_init(char *btf, int btf_size, char *so, int so_size)
{
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = tcprtt_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	return 0;	

}

int ebpf_start()
{
	int err;
	/* Attach tracepoint handler */
	err = tcprtt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	if (handle_func != NULL) {
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_func, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cleanup;
		}
	} else {
		fprintf(stderr, "handle_func is NULL\n");
		goto cleanup;
	}

	return 0;

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	tcprtt_bpf__destroy(skel);
	return -err;

}

int ebpf_stop()
{
	ring_buffer__free(rb);
	tcprtt_bpf__destroy(skel);

	return 0;

}


int ebpf_poll_events(int32_t max_events, int32_t* stop_flag)
{
	/* Poll for available data and consume records, if any are available.
 * Returns number of records consumed (or INT_MAX, whichever is less), or
 * negative number, if any of the registered callbacks returned error.
 */
	int err;
	err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
	if (err == -EINTR) {
		err = 0;
		goto out;
	}
	if (err < 0) {
		printf("Error polling perf buffer: %d\n", err);
	}

out:
	return err;
}


int main(int argc, char **argv)
{
	struct tcprtt_bpf *skel;
	int err;
	struct ring_buffer *rb = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
//	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = tcprtt_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = tcprtt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	print_output_header();

	/* Set up ring buffer polling */
	ebpf_setup_handle_event_func(handle_event);
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_func, NULL, NULL);
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
	tcprtt_bpf__destroy(skel);
	return -err;
}
