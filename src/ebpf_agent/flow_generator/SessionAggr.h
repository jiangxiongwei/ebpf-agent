#ifndef __SESSIONAGGR_H__
#define __SESSIONAGGR_H__

#include<stdint.h>
#include<map>
#include<chrono>  

#include "protocol_logs.h"
#include "Sender.h"

using namespace std;

// 尽力而为的聚合默认120秒(AppProtoLogs.aggr*SLOT_WIDTH)内的请求和响应
const uint64_t SLOT_WIDTH = 60;  // 每个slot存60秒
const uint64_t SLOT_CACHED_COUNT = 300000; // 每个slot平均缓存的FLOW数

class SessionAggr {

 //   maps: [Option<HashMap<u64, AppProtoLogsData>>; 16], 数组，  元素类型是HashMap，size 是16
    map<uint64_t, struct AppProtoLogsData> maps[16];

    uint64_t start_time; // 秒级时间
    uint64_t cache_count;

    uint64_t last_flush_time; // 秒级时间
    uint64_t slot_count;

    Sender *output;

    // counter: SyncEbpfCounter,

    // log_rate: Arc<LeakyBucket>,
    
    // output: DebugSender<SendItem>,


public:
    SessionAggr(chrono::duration<int64_t> l7_log_session_timeout,
                Sender *output);
    void handle(struct AppProtoLogsData log); 
    void slot_handle(AppProtoLogsData log, int64_t slot_index, int64_t key, int64_t ttl);
    int64_t flush(int64_t count);
    void send(struct AppProtoLogsData log);

};

#endif // __SESSIONAGGR_H__