
#include "FlowItem.h"
#include "error.h"
#include "protocol_logs.h"
#include "AppProtocolInfo.h"
#include "HTTPParser.h"

const uint64_t FLOW_ITEM_TIMEOUT = 60;


L7LogParser* FlowItem::get_parser(L7Protocol protocol, LogParserConfig log_parser_config)
{
    L7LogParser *parser = nullptr;
    switch (protocol)
    {
    case L7_PROTOCOL_HTTP1:
        parser = new HTTPParser(protocol, log_parser_config);
        /* code */
        break;
    case L7_PROTOCOL_DUBBO:
        break;
    
    default:
        break;
    }

    return parser;

}


vector<AppProtocolInfo> FlowItem::get_info()
{
    vector<AppProtocolInfo> infos = this->parser->info();
    return infos;

}


vector<struct AppProtoLogsData> FlowItem::handle(MetaPacket *packet,
                                            AppTable *app_table,
                                            int32_t local_epc,
                                            uint16_t vtap_id
                                            )
{
    cout << "FlowItem::handle" << endl;
    vector<AppProtoHead> heads;
    vector<AppProtoLogsData> datas;
    heads = this->parse(packet);
    if (heads.size() != 0) {
        AppProtoLogsBaseInfo log_base_info;
        AppProtoHead head = heads[0];

        log_base_info.from_ebpf(packet, head, vtap_id, local_epc, this->remote_epc);

        AppProtoLogsData data;
        data.base_info = log_base_info;

        data.special_info = this->get_info()[0];
        // vector<AppProtoLogsData> datas;
        datas.push_back(data);


    }
    return datas;
    
    
}

void FlowItem::reset(IpProtocol l4_protocol) {
    this->last_packet = 0;
    this->last_policy = 0;
    this->l7_protocol = L7_PROTOCOL_UNKNOWN;
    this->is_skip = false;
    this->is_success = false;
    this->is_from_app = false;
    this->l4_protocol = l4_protocol;
    this->parser = NULL;
}

vector<AppProtoHead> FlowItem::_parse(MetaPacket *packet, int local_epc, AppTable *app_table)
{
    vector<AppProtoHead> ret;
    if (!this->is_success && this->is_skip) {
        return ret;
    }

    // if (this->server_port == packet->lookup_key.dst_port) {
    //     cout << "packet->lookup_key.dst_port:" << packet->lookup_key.dst_port << endl;
    //     cout << "ClientToServer" << endl;
    //     packet->direction = ClientToServer;
    // } else {
    //     cout << "ServerToClient" << endl;
    //     packet->direction = ServerToClient;
    // }

    printf("FlowItem::_parse packet->direction:%d\n", (uint32_t)packet->direction);
    ret = this->parser->parse(packet->raw_from_ebpf, packet->lookup_key.proto, packet->direction);
    // if (!this->is_success) {
    //     if (ret == 0) {
    //         app_table->set_protocol_from_ebpf(packet, this->l7_protocol, local_epc, this->remote_epc);
    //         this->is_success = true;
    //     } else {
    //         this->is_skip = app_table->set_protocol_from_ebpf(packet, L7_PROTOCOL_UNKNOWN, local_epc, this->remote_epc);
    //     }
    // }
    return ret;

}

vector<AppProtoHead> FlowItem::parse(MetaPacket *packet)
{
    vector<AppProtoHead> ret;
    uint64_t time_in_sec = packet->lookup_key.timestamp;
    // these codes need to be confirmed.
#if 0
    if (this->last_packet + FLOW_ITEM_TIMEOUT < time_in_sec) {
        cout << "enter reset" << endl;
        this->reset(packet->lookup_key.proto);
    }
#endif
    this->last_packet = time_in_sec;
    if (this->parser != NULL) {
        return this->_parse(packet, 0, NULL);
    }

    return ret;
    // return 0;
}

FlowItem::FlowItem(AppTable app_table, MetaPacket *packet,
                    int32_t local_epc, int32_t remote_epc,
                    LogParserConfig log_parser_config)
{
    // 为什么这个没有执行到过。
    cout << "FlowItem::FlowItem with params" << endl;
    uint64_t time_in_sec = packet->lookup_key.timestamp;
    l4_protocol = packet->lookup_key.proto;
    int32_t server_port = 0;
    l7_protocol = app_table.get_protocol_from_ebpf(packet, local_epc, remote_epc, &server_port);
    
    is_from_app = (l7_protocol == L7_PROTOCOL_UNKNOWN) ? false : true;


    last_policy = time_in_sec;
    last_packet = time_in_sec;
    remote_epc = remote_epc;
    l4_protocol = l4_protocol;
    l7_protocol = l7_protocol;
    is_success = false;
    is_from_app = is_from_app;
    is_skip = false;
    server_port = server_port;
    this->parser = this->get_parser(l7_protocol, log_parser_config);

}
