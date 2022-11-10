#ifndef __ENUM_H__
#define __ENUM_H__

#define CAP_DATA_SIZE 1024

enum PacketDirection {
    ClientToServer,
    ServerToClient,
};


enum TapSide {
    Rest = 0,
    Client = 1 << 0,
    Server = 1 << 1,
    Local = 1 << 2,
    ClientNode,
    ServerNode,
    ClientHypervisor,
    ServerHypervisor,
    ClientGatewayHypervisor,
    ServerGatewayHypervisor,
    ClientGateway,
    ServerGateway,
    ClientProcess,
    ServerProcess,
};


 enum L7ResponseStatus {
    Ok,
    Error,
    NotExist,
    ServerError,
    ClientError,
 };


enum L4Protocol {
    L4_PROTOCOL_Unknown = 0,
    L4_PROTOCOL_TCP = 1,
    L4_PROTOCOL_UDP = 2,
};


enum L7Protocol {
    L7_PROTOCOL_UNKNOWN = 0,
    L7_PROTOCOL_OTHER = 1,
    L7_PROTOCOL_HTTP1 = 20,
    L7_PROTOCOL_HTTP2 = 21,
    L7_PROTOCOL_HTTP1_TLS = 22,
    L7_PROTOCOL_HTTP2_TLS = 23,
    L7_PROTOCOL_DUBBO = 40,
    L7_PROTOCOL_MYSQL = 60,
    L7_PROTOCOL_REDIS = 80,
    L7_PROTOCOL_KAFKA = 100,
    L7_PROTOCOL_MQTT = 101,
    L7_PROTOCOL_DNS = 120,
    L7_PROTOCOL_MAX = 255,
};

enum IpProtocol {
    Ipv6HopByHop = 0,
    Icmpv4 = 1,
    Igmp = 2,
    Ipv4 = 4,
    Tcp = 6,
    Udp = 17,
    Rudp = 27,
    Ipv6 = 41,
    Ipv6Routing = 43,
    Ipv6Fragment = 44,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58, 
    NoNextHeader = 59, 
    Ipv6Destination = 60, 
    Ospf = 89, 
    Ipip = 94, 
    EtherIp = 97, 
    Vrrp = 112,
    Sstp = 132,
    UdpLite = 136,
    MplsInIp = 137,
    Unknown = 255,
};

enum LogMessageType {
    Request,
    Response,
    Session,
    Other,
    Max,
};

// 数据协议
enum traffic_protocol {
	PROTO_UNKNOWN = 0,
	PROTO_ORTHER = 1,
	PROTO_HTTP1 = 20,
	PROTO_HTTP2 = 21,
	PROTO_GO_TLS_HTTP1 = 22,
	PROTO_DUBBO = 40,
	PROTO_MYSQL = 60,
	PROTO_REDIS = 80,
	PROTO_KAFKA = 100,
	PROTO_MQTT = 101,
	PROTO_DNS = 120,
	PROTO_NUM = 130
};





#endif /* __ENUM_H__ */
