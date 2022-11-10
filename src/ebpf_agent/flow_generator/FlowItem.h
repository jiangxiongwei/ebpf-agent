

#include "protocol_logs.h"
#include "MetaPacket.h"
#include "AppTable.h"
#include "L7LogParser.h"
#include "Enum.h"
#include "config.h"
#include <bits/types.h>
#include <stdint.h>

using namespace std;



class FlowItem {
    uint64_t last_policy; // 秒级
    uint64_t last_packet; // 秒级

    int32_t remote_epc;

    // 应用识别

    // __u128 protocol_bitmap_image;
    // __u128 protocol_bitmap;
    IpProtocol l4_protocol;
    L7Protocol l7_protocol;

    uint16_t server_port;

    bool is_from_app;
    bool is_success;
    bool is_skip;

    L7LogParser *parser;
public:
    FlowItem(MetaPacket *packet);
    FlowItem(AppTable app_table, MetaPacket *packet,
                    int32_t local_epc, int32_t remote_epc,
                    LogParserConfig log_parser_config);
    FlowItem(){};
    L7LogParser* get_parser(L7Protocol protocol, LogParserConfig log_parser_config);
    vector<struct AppProtoLogsData> handle(MetaPacket *packet,
                                            AppTable *app_table,
                                            int32_t local_epc,
                                            uint16_t vtap_id
                                            );
    vector<AppProtoHead> parse(MetaPacket *packet);
    vector<AppProtoHead> _parse(MetaPacket *packet, int local_epc, AppTable *app_table);
    void reset(IpProtocol l4_protocol);
    vector<AppProtocolInfo> get_info();

};

