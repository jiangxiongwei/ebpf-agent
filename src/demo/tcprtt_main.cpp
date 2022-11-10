#include <iostream>
#include <dlfcn.h>
#include <cstdlib>
#include<arpa/inet.h>
#include<signal.h>
#include<string.h>
#include<stdio.h>


using namespace std;

struct ipv4_data_t {
	unsigned int pid;
	unsigned int  saddr;
	unsigned int  daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned int srtt_ms;
};

typedef int (*handle_event_func_t) (void *ctx, void *event, size_t size);
typedef void (*ebpf_setup_handle_event_func)(handle_event_func_t func);
typedef int (*ebpf_init_func)(char *btf, int btf_size, char *so, int so_size);
typedef int (*ebpf_start_func)();
typedef int (*ebpf_stop_func)();
typedef int (*ebpf_poll_events_func)();

static volatile sig_atomic_t stop = 0;

static void sig_int(int signo)
{
	FILE *out; 
	if ((out = fopen("log.txt", "w+")) == NULL) {
		fprintf(stderr, "Cannot open output file./n");
		return;
	} 

	fprintf(out, "sigint happened! \n");
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct ipv4_data_t *ipv4_data = (struct ipv4_data_t *)data;
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

void* mLibPtr = nullptr;

bool load_dyn_lib(const std::string& libName,
				std::string& error,
                const std::string dlPrefix,
                const std::string dlSuffix) {
	error.clear();

	mLibPtr = dlopen((dlPrefix + "lib" + libName + ".so" + dlSuffix).c_str(), RTLD_LAZY);
	if (mLibPtr != NULL)
        return true;
	auto dlErr = dlerror();
    error = (dlErr != NULL) ? dlErr : "";
    return false;
}

void* load_method(const std::string& methodName, std::string& error)
{
	error.clear();

    dlerror(); // Clear last error.
    auto methodPtr = dlsym(mLibPtr, methodName.c_str());
    auto dlErr = dlerror();
	error = (dlErr != NULL) ? dlErr : "";
    return methodPtr;

}


int main(int argc, char *argv[])
{
    void *libPtr;
	ebpf_setup_handle_event_func p_ebpf_setup_handle_event_func = NULL;
	ebpf_init_func p_ebpf_init_func = NULL;
	ebpf_start_func p_ebpf_start_func = NULL;
	ebpf_stop_func p_ebpf_stop_func = NULL;
	ebpf_poll_events_func p_ebpf_poll_events_func = NULL;

    void (*ebpf_poll_events)();

    libPtr = dlopen("tcprtt.so", RTLD_LAZY);
    string methodName1 = "ebpf_setup_handle_event_func";
	string methodName2 = "ebpf_init";
	string methodName3 = "ebpf_start";
	string methodName4 = "ebpf_poll_events";


	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto out;
	}

	p_ebpf_setup_handle_event_func = ebpf_setup_handle_event_func(dlsym(libPtr, methodName1.c_str()));
	if (p_ebpf_setup_handle_event_func == NULL) {
		printf("ebpf_setup_handle_event_func is NULL\n");
		goto out;
	} else {
		p_ebpf_setup_handle_event_func(handle_event);
	}
	
	p_ebpf_init_func = ebpf_init_func(dlsym(libPtr, methodName2.c_str()));
	if (p_ebpf_init_func == NULL) {
		printf("ebpf_init_func is NULL\n");
		goto out;
	} else {
		p_ebpf_init_func(NULL, 0, NULL, 0);
	}

	p_ebpf_start_func = ebpf_start_func(dlsym(libPtr, methodName3.c_str()));
	if (p_ebpf_start_func == NULL) {
		printf("p_ebpf_start_func is NULL\n");
		goto out;
	} else {
		p_ebpf_start_func();
	}

	p_ebpf_poll_events_func = ebpf_poll_events_func(dlsym(libPtr, methodName4.c_str()));
	if (p_ebpf_poll_events_func == NULL) {
		printf("p_ebpf_poll_events_func is NULL\n");
		goto out;
	} else {
		while (!stop) {
			p_ebpf_poll_events_func();

		}
	}
out:
	return 0;
}
