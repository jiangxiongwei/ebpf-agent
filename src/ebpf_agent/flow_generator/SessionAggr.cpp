#include "SessionAggr.h"
#include <algorithm>
#include<iostream>

using namespace std;


SessionAggr::SessionAggr(chrono::duration<int64_t> l7_log_session_timeout,
                Sender *output)
{
    cout << "SessionAggr::SessionAggr" << endl;
    
    uint64_t _slot_count = l7_log_session_timeout.count() / SLOT_WIDTH;
    _slot_count = max(_slot_count, (uint64_t)1);
    _slot_count = min(_slot_count, (uint64_t)16);

    this->slot_count = _slot_count;
    this->start_time = 0;
    this->cache_count = 0;
    this->last_flush_time = 0;
    this->output = output;
    
    //

}

int64_t SessionAggr::flush(int64_t count)
{





    return 0;
}

void SessionAggr::send(struct AppProtoLogsData log)
{
    // 限流
    // if (!this->log_rate.acquire(1)) {
    //     this->counter.counter().throttle_drop += 1;
    //     return;
    // }

    
    //
    
    // this->output.send(SendItem::L7FlowLog(Box::new(log)));
    this->output->send(log);

}

void SessionAggr::handle(struct AppProtoLogsData log)
{
    cout << "SessionAggr::handle" << endl;
    uint64_t slot_time = log.base_info.start_time;

    cout << "slot_time: " << slot_time << endl;

    if (slot_time < this->start_time) {
        this->send(log);
        return;
    }

    if (this->start_time == 0) {
        this->start_time = slot_time / SLOT_WIDTH * SLOT_WIDTH;
    }

    uint64_t slot_index = (slot_time - this->start_time) / SLOT_WIDTH;
    if (slot_index >= this->slot_count) {
        slot_index = this->flush(slot_index - this->slot_count + 1);
    }

    cout << "before log.ebpf_flow_session_id" << endl;
    uint64_t key = log.ebpf_flow_session_id(); //combine flow_id and session_id

    this->slot_handle(log, slot_index, key, 1);


}

void SessionAggr::slot_handle(AppProtoLogsData log, int64_t slot_index, int64_t key, int64_t ttl)
{
    cout << "SessionAggr::slot_handle with key:" <<  key << "slot_index:" << slot_index << "ttl:" << ttl << endl;
    map<uint64_t, struct AppProtoLogsData> _map = this->maps[slot_index];
    map<uint64_t, struct AppProtoLogsData>::iterator iter, iter_prev;

    // just for test. send the log anyway.
    this->send(log);

    if (log.base_info.head.msg_type == Request) {
        // AppProtoLogsData value = _map[key];
        // map<uint64_t, struct AppProtoLogsData>::iterator iter;
        iter = _map.find(key);
        if (iter == _map.end()) {
            if (this->cache_count >= this->slot_count * SLOT_CACHED_COUNT) {
                this->send(log);
                // self.maps[slot_index as usize].replace(map);
                return;
            }
            _map.insert(pair<uint64_t, AppProtoLogsData>(key, log));
            this->cache_count += 1;
            // self.maps[slot_index as usize].replace(map);
            return;

        }
        AppProtoLogsData item = iter->second;
        // 若乱序，已存在响应，则可以匹配为会话，则聚合响应发送
        if (item.base_info.head.msg_type == Response) {

            uint32_t rrt = (item.base_info.start_time > log.base_info.start_time) ? 
                                (item.base_info.start_time - log.base_info.start_time) : 0;
            log.session_merge(item);
            log.base_info.head.rrt = rrt;   //u64 us
            this->cache_count -= 1;
            this->send(log);
        } else {
            // 对于HTTPV1, requestID总为0, 连续出现多个request时，response匹配最后一个request为session
            _map.insert(pair<uint64_t, AppProtoLogsData>(key, log));
            this->send(log);
        }
        //清除
        _map.erase(iter);

    }

    if (log.base_info.head.msg_type == Response) {

        iter = _map.find(key);
        if (iter == _map.end()) {
            if (ttl > 0 && slot_index != 0) {
                // 响应和请求时间差长的话，不在同一个时间槽里,或者此时请求还未到达，这里继续查询前一个时间槽
                map<uint64_t, struct AppProtoLogsData> _map_prev = this->maps[slot_index - 1];
                iter_prev = _map_prev.find(key);
                if (iter_prev == _map_prev.end()) {
                    // self.maps[slot_index - 1 as usize].replace(pre_map.unwrap());
                    // ebpf的数据存在乱序，回应比请求先到的情况
                    _map.insert(pair<uint64_t, struct AppProtoLogsData>(key, log));
                    this->cache_count += 1;
                    return;

                }    
            } else {
                _map.insert(pair<uint64_t, struct AppProtoLogsData>(key, log));
                this->cache_count += 1;
                // self.maps[slot_index as usize].replace(map);
                return;
            }

        }
        AppProtoLogsData item = iter->second;
        uint32_t rrt = (item.base_info.start_time > log.base_info.start_time) ? 
                                (item.base_info.start_time - log.base_info.start_time) : 0;
        // 若乱序导致map中的也是响应, 则发送响应,继续缓存新的响应
        if (item.base_info.head.msg_type == Response) {
            _map.insert(pair<uint64_t, AppProtoLogsData>(key, log));
            this->send(item);
        } else {
            item.session_merge(log);
            item.base_info.head.rrt = rrt;
            this->cache_count -= 1;
            this->send(item);
        }
        //清除
        _map.erase(iter);

    }

}