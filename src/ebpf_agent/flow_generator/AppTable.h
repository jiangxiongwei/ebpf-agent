

//记录IP+EPC+PORT对应的应用协议

class AppTable {

    // ipv4: LruCache<AppTable4Key, AppTableValue>,
    // ipv6: LruCache<AppTable6Key, AppTableValue>,
    //
public:
    uint64_t l7_protocol_inference_max_fail_count;
    uint64_t l7_protocol_inference_ttl;

public:

    L7Protocol get_protocol_from_ebpf(MetaPacket *packet, int32_t local_epc, int32_t remote_epc, int32_t *server_port){
        // to be 
        return L7_PROTOCOL_HTTP1;
    }


};