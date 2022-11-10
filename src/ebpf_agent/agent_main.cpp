#include "EBPFCollector.h"

#include <iostream>
#include <dlfcn.h>
#include <cstdlib>
#include<arpa/inet.h>
#include<signal.h>
#include<string.h>
#include<stdio.h>
#include<vector>
#include<fstream>

using namespace std;

typedef int (*handle_event_func_t) (void *ctx, void *event, size_t size);

typedef void (*ebpf_setup_handle_event_func)(handle_event_func_t func);
typedef void (*ebpf_config_target_execname_func)(char *execname[], int count);
typedef void (*ebpf_config_target_pid_func)(int target_pid);
typedef int (*ebpf_init_func)(char *btf, int btf_size, char *so, int so_size);
typedef int (*ebpf_start_func)();
typedef int (*ebpf_stop_func)();
typedef int (*ebpf_poll_events_func)();

static volatile sig_atomic_t stop = 0;
EBPFCollector* mEBPFCollector = EBPFCollector::GetInstance();

static void sig_int(int signo)
{
	FILE *out; 
	if ((out = fopen("log.txt", "w+")) == NULL) {
		fprintf(stderr, "Cannot open output file./n");
		return;
	} 

	fprintf(out, "sigint happened! \n");
	fclose(out);
	stop = 1;
}

typedef struct entry
{
	string key;
    string value;
} entry;


static vector<string> split_string(const string& str, char delim) {
    size_t previous = 0;
    size_t current = str.find(delim);
    vector<string> elems;
    while (current != string::npos) {
        if (current > previous) {
            elems.push_back(str.substr(previous, current - previous));
        }
        previous = current + 1;
        current = str.find(delim, previous);   
    }
    if (previous != str.size() && previous != 0) {
        elems.push_back(str.substr(previous));
    }
    return elems;
}

static string& trim(string& str) 
{
    if (str.empty()) {
        return str;
    }
 
    str.erase(0,str.find_first_not_of(" "));
    str.erase(str.find_last_not_of(" ") + 1);
    return str;
}

static vector<entry> parse_config_file()
{
	vector<string> raw_entries;
	vector<entry> config_pairs;

	entry _entry;

    ifstream srcFile("ebpf_agent.conf", std::ios::in); //以文本模式打开
	if (!srcFile) {
		cout << "error opening source file." << endl;
		return config_pairs;;
	}
        
    while (!srcFile.eof()) {
		entry _entry;
        string raw_entry;
		srcFile >> raw_entry;
		raw_entries.push_back(raw_entry);
	}

	for (auto x : raw_entries) {
		trim(x);
		cout <<  "x:"  << x << endl;
		if ( x.compare("") !=0 ) {// 去除空行
			vector<string> ret = split_string(x, ':');
			if (ret.size() == 2) {// 只能有一个:
				_entry.key = ret[0];
				_entry.value = ret[1];
				config_pairs.push_back(_entry);
				ret.clear();
				vector<string>().swap(ret);

			}			
		}

	}
	srcFile.close();
	return config_pairs;

}

static int ebpf_data_process_callback(void *ctx, void *event, size_t size) {
    

	if (event == NULL) {
        return -1;
    }

	mEBPFCollector->process_socket_data(event);

	


	// printf("length:%llu \n",sdb->len);



    // ((EBPFCollector*))->OnData(event);
	// MetaPacket packet;
    
    // packet.from_ebpf(sd, CAP_LEN_MAX);
    /*TODO 交给线程池去执行
     * thread new_thread(handle_event, packet);
     */
    // this->process_packet(&packet);
}


int main(int argc, char *argv[])
{

	void *libPtr;
	ebpf_setup_handle_event_func p_ebpf_setup_handle_event_func = NULL;
	ebpf_config_target_execname_func p_ebpf_config_target_execname_func = NULL;
	ebpf_config_target_pid_func p_ebpf_config_target_pid_func = NULL;
	ebpf_init_func p_ebpf_init_func = NULL;
	ebpf_start_func p_ebpf_start_func = NULL;
	ebpf_stop_func p_ebpf_stop_func = NULL;
	ebpf_poll_events_func p_ebpf_poll_events_func = NULL;


    void (*ebpf_poll_events)();


    vector<entry> config_pairs = parse_config_file();
	if (config_pairs.size() == 0) {
		cout << "parse config failed !! " << endl;
	} else {
		for (auto x : config_pairs) {
			cout << x.key << ":" << x.value << endl;

		}

	}

	int target_pid = 0;

	for(int i = 0; i < config_pairs.size(); i++) {
		string key = config_pairs[i].key;
		if ( key == "pid") {
			string value = config_pairs[i].value;
			target_pid = atoi(value.c_str());
			printf("target_pid : %d\n", target_pid);

		}

	}

	

    libPtr = dlopen("ebpf_agent.so", RTLD_LAZY);
	
    string methodName1 = "ebpf_setup_handle_event_func";
	string methodName2 = "ebpf_config_target_pid_func";
	string methodName3 = "ebpf_init";
	string methodName4 = "ebpf_start";
	string methodName5 = "ebpf_poll_events";


	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto out;
	}

	p_ebpf_setup_handle_event_func = ebpf_setup_handle_event_func(dlsym(libPtr, methodName1.c_str()));
	if (p_ebpf_setup_handle_event_func == NULL) {
		printf("ebpf_setup_handle_event_func is NULL\n");
		goto out;
	} else {
		p_ebpf_setup_handle_event_func(ebpf_data_process_callback);
	}

	p_ebpf_config_target_pid_func = ebpf_config_target_pid_func(dlsym(libPtr, methodName2.c_str()));
	if (p_ebpf_config_target_pid_func == NULL) {
		printf("p_ebpf_config_target_pid_func is NULL\n");
		goto out;
	} else {
		p_ebpf_config_target_pid_func(target_pid);
	}
	
	p_ebpf_init_func = ebpf_init_func(dlsym(libPtr, methodName3.c_str()));
	if (p_ebpf_init_func == NULL) {
		printf("ebpf_init_func is NULL\n");
		goto out;
	} else {
		p_ebpf_init_func(NULL, 0, NULL, 0);
	}

	p_ebpf_start_func = ebpf_start_func(dlsym(libPtr, methodName4.c_str()));
	if (p_ebpf_start_func == NULL) {
		printf("p_ebpf_start_func is NULL\n");
		goto out;
	} else {
		p_ebpf_start_func();
	}

	p_ebpf_poll_events_func = ebpf_poll_events_func(dlsym(libPtr, methodName5.c_str()));
	if (p_ebpf_poll_events_func == NULL) {
		printf("p_ebpf_poll_events_func is NULL\n");
		goto out;
	} else {
		// event loop
		while (!stop) {
			p_ebpf_poll_events_func();

		}
	}
out:
	return 0;


}

