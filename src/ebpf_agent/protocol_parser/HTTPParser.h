#include "L7LogParser.h"
#include "Enum.h"
#include "AppProtocolInfo.h"
#include "config.h"
#include<vector>

using namespace std;

class HttpInfo : public AppProtocolInfo { 

public:
    uint32_t stream_id;
    string version;
    string trace_id;
    string span_id;
    string method;
    string path;
    string host;
    string client_ip;
    string x_request_id;
    uint64_t req_content_length;
    uint64_t resp_content_length;

public:
    uint32_t session_id(){
        return 0;
    }
    void merge(AppProtocolInfo *other) {
        HttpInfo * _other = (HttpInfo *) other;
        this->resp_content_length = _other->resp_content_length;
        if (this->trace_id.size() == 0) {
            this->trace_id = _other->trace_id;
        }
        if (this->span_id.size() == 0) {
            this->span_id = _other->span_id;
        }
        if (this->x_request_id.size() == 0) {
            this->x_request_id = _other->x_request_id;
        }

    }
};

struct L7LogCustomConfig {

};




class HTTPParser : public L7LogParser
{
    uint16_t status_code;
    enum LogMessageType msg_type;
    enum L7Protocol proto;
    enum L7ResponseStatus status;
    struct HttpInfo httpInfo;
    bool is_https;

    struct L7LogDynamicConfig l7_log_dynamic_config;

public:
    HTTPParser(L7Protocol protocol, LogParserConfig log_parser_config);
	virtual vector<AppProtoHead> parse(char payload[], enum IpProtocol proto, enum PacketDirection direction);
    virtual vector<AppProtocolInfo> info();
    int parse_http_v1(char payload[], enum PacketDirection direction);
    enum L7Protocol get_l7_protocol(); 
    void reset_logs();
    bool is_http_v1_payload(char payload[]);
    void parse_lines(char payload[], vector<vector<char>>& lines, int num);
    void find_col_index(vector<char>, int *col_index);
    void get_http_resp_info(char line_info[], int len, char *version, int *status_code);
    void get_http_request_info(char line_info[], int len, char *method, char *path, char *version);

};