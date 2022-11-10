#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <chrono>
#include <string>
using namespace std;


struct L7LogDynamicConfig {
    string proxy_client_origin;
    string proxy_client_lower;
    string proxy_client_with_colon;
    string x_request_id_origin;
    string x_request_id_lower;
    string x_request_id_with_colon;

//    trace_types: Vec<TraceType>,
//    span_types: Vec<TraceType>,
};

struct LogParserConfig {
    uint64_t l7_log_collect_nps_threshold;
    chrono::duration<uint64_t> l7_log_session_aggr_timeout;

    L7LogDynamicConfig l7_log_dynamic;
};


 #endif // __CONFIG_H__