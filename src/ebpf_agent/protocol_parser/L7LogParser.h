#ifndef __L7LOGPARSER_H__
#define __L7LOGPARSER_H__


#include "protocol_logs.h"
#include "Enum.h"
#include<vector>

using namespace std;


//L7ProtocolParserInterface

class L7LogParser {
public:
    virtual vector<AppProtoHead> parse(char payload[], enum IpProtocol proto, enum PacketDirection direction) {
        vector<AppProtoHead> v;
        return v;
    };
    virtual vector<AppProtocolInfo> info() {
        vector<AppProtocolInfo> v;
        return v;
    };

};

#endif //__L7LOGPARSER_H__