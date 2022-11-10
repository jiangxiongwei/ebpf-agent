#include "HTTPParser.h"
#include<vector>
#include<string>
#include<stdio.h>
#include<string.h>

using namespace std;

const char *REQUEST_PREFIXS[9] = {
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH",
};

const char *RESPONSE_PREFIX = "HTTP/";

const char *HTTP_V1_0_VERSION = "HTTP/1.0";
const char *HTTP_V1_1_VERSION = "HTTP/1.1";

HTTPParser::HTTPParser(L7Protocol protocol, LogParserConfig log_parser_config)
{
    //todo 
    // pub fn new(config: &LogParserAccess, is_https: bool) -> Self {
    //     Self {
    //         l7_log_dynamic_config: config.load().l7_log_dynamic.clone(),
    //         is_https,
    //         ..Default::default()
    //     }
    // }

    this->l7_log_dynamic_config = log_parser_config.l7_log_dynamic;



}

vector<AppProtoHead> HTTPParser::parse(char payload[], enum IpProtocol proto, enum PacketDirection direction)
{
    cout << "HTTPParser::parse with direction:" << (uint32_t)direction<< endl;
    vector<AppProtoHead> proto_heads;
    int ret;
    if (proto != Tcp) {
        printf("HTTPParser::parse proto : %d\n", proto);
        
        return proto_heads;
    }
    this->reset_logs();

    ret = this->parse_http_v1(payload, direction);
    if (ret != 0) {
        cout << "parse http_v1 failed" << endl;
        return proto_heads;
    }

    
    cout << "before create proto_head, msg_type:" << this->msg_type << endl;
    struct AppProtoHead proto_head = {
        .l7proto = this->get_l7_protocol(),
        .msg_type = this->msg_type,
        .response_status = this->status,
        .response_code = this->status_code,
        .rrt = 0,
        .version = 0,
    };
    proto_heads.push_back(proto_head);
    return proto_heads;

}

bool  HTTPParser::is_http_v1_payload(char buf[]) {

    int i;
    int failed = 0;
    for (i = 0; i < 5; i++) {
        if (buf[i] != RESPONSE_PREFIX[i]) {
            failed = 1;
            break;
        }
    }
    if (failed == 0)
        return true;
    
    int j, k;
    failed = 0;
    for (j = 0; j < 9; j++) {
        int len = strlen(REQUEST_PREFIXS[j]);
        for (k = 0; k < len; k++) {
            if (buf[k] != REQUEST_PREFIXS[j][k]) {
                failed = 1;
                break;
            }
        }
        if (failed == 0) {
            return true;
        } else {
            failed = 0;
        }        
    }
    
    return false;
}

vector<AppProtocolInfo> HTTPParser::info()
{
    // if (this->info.version == "2") {
    //         return AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::HttpV2(self.info.clone()));
    // }
    // if (this->is_https) {
    //         return AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::HttpV1TLS(self.info.clone()));
    // }
    vector<AppProtocolInfo> infos;
    HttpInfo info = this->httpInfo;
    infos.push_back(info);

    return infos;
}

void HTTPParser::parse_lines(char payload[], vector<vector<char>>& lines, int line_num)
{
    cout << "parse_lines" << endl;
    char *p = payload;

    int size = 1024;
    while (lines.size() < line_num) {
        int next_index = 0;
        for (int i = 0; i < size; i++) {
            //换行时，是连续的'\r'和'\n'
            if (i > 2 && p[i] == '\n' && p[i-1] == '\r') {
                vector<char> _line;
                for(int j = 0; j < i-1; j++) {
                    _line.push_back(p[j]);
                }
                lines.push_back(_line);
                next_index = i + 1;
                break;
            }
        }
        if(next_index == 0) {//没有遇到换行符
            return;
        }

        if(next_index >= size) {//刚好最后两个字符是\r\n
            return;
        }

        //    payload = payload[i..];  //设置为剩余的字节数组。从next_index开始。
        p =  p + next_index;
        size = size - (next_index);
        
    }

}

void HTTPParser::get_http_resp_info(char line_info[], int len, char *version, int *status_code)
{
    char delim[] = " ";//分隔符字符串
    char* tmp = line_info;
    char* p = strtok(line_info, delim);//第一次调用strtok
    if (p != NULL) {
        if (strcmp(HTTP_V1_0_VERSION, p) == 0) {
            strcpy(version, "1.0");
        }
        if (strcmp(HTTP_V1_1_VERSION, p) == 0) {
            strcpy(version, "1.1");
        }

    }
    p = strtok(NULL,delim);
    if (p != NULL) {

        *status_code = atoi(p);

    }

}

void HTTPParser::get_http_request_info(char line_info[], int len, char *method, char *path, char *version)
{
    char delim[] = " ";//分隔符字符串
    char* p = strtok(line_info, delim);//第一次调用strtok
    if (p != NULL) {
        strcpy(method, p);
    }
    p = strtok(NULL,delim);
    if (p != NULL) {
        strcpy(path, p);
    }
    p = strtok(NULL,delim);
    if (p != NULL) {
        if (strcmp(HTTP_V1_0_VERSION, p) == 0) {
            strcpy(version, "1.0");
        }
        if (strcmp(HTTP_V1_1_VERSION, p) == 0) {
            strcpy(version, "1.1");
        }
    }

}

void HTTPParser::find_col_index(vector<char> body_line, int *col_index)
{
    int i;
    for (i = 0; i < body_line.size(); i++) {
        if (body_line[i] =  ':') {
            *col_index = i;
        }
    }
}

int HTTPParser::parse_http_v1(char payload[], enum PacketDirection direction)
{
    cout << "parse_http_v1" << endl;
    char version[4] = {'\0'};
    int status_code = 0;
    char method[16] = {'\0'};
    char path[128] = {'\0'};

    if (!is_http_v1_payload(payload)) {
        return -1;
        //return Err(Error::HttpHeaderParseFailed);
    }
    vector<vector<char>> lines;
    parse_lines(payload, lines, 20);
    if (lines.size() == 0) {
        return -1; //
    }

    vector<char> line_0 = lines[0];
    int len = line_0.size();
    char line_0_c[len] = {'\0'};
    for(int i = 0; i < line_0.size(); i++) {
        line_0_c[i] = line_0[i];
    }

    if (direction == ServerToClient) {
        // HTTP响应行：HTTP/1.1 404 Not Found.

        cout << "direction ServerToClient" << endl;
        
        get_http_resp_info(line_0_c, len, version, &status_code);
        this->httpInfo.version = version;
        this->status_code = (uint16_t) status_code;
        this->msg_type = Response;

        cout << "this->msg_type" << this->msg_type << endl;

        // this->set_status(status_code);
    } else {
        // HTTP请求行：GET /background.png HTTP/1.0
        cout << "direction ClientToServer" << endl;
        get_http_request_info(line_0_c, len, method, path, version);
        this->httpInfo.method = method;
        this->httpInfo.path = path;
        this->httpInfo.version = version;
        this->msg_type = Request;
    }

    uint64_t content_length = 0;
    for (int j = 1; j < lines.size(); j++) {
        vector<char> body_line = lines[j];
        int col_index = 0;
        find_col_index(body_line, &col_index);

        // let col_index = body_line.iter().position(|x| *x == b':');
        if (col_index == 0) {
                continue;
        }
        if ((col_index + 1) >= body_line.size()) {
                continue;
        }
        string key;
        string value;
        vector<char> key_part;
        vector<char> value_part;
        vector<char>::const_iterator key_begin = body_line.begin();
        vector<char>::const_iterator key_end = body_line.begin() + col_index;
        vector<char>::const_iterator value_begin = body_line.begin() + col_index + 1;
        vector<char>::const_iterator value_end = body_line.end();
        key_part.assign(key_begin, key_end);
        key.assign(key_part.begin(), key_part.end());
        value_part.assign(value_begin, value_end);
        value.assign(value_part.begin(), value_part.end());
        // key 转成小写
        transform(key_part.begin(), key_part.end(), key_part.begin(), ::tolower);
        // value 去掉头尾空格
        value.erase(0, value.find_first_not_of(" "));
        value.erase(value.find_last_not_of(" ") + 1);
        if (key.compare("content-length") == 0 ) {
            content_length = stoul(value, nullptr, 10);

            // content_length = Some(value.parse::<u64>().unwrap_or_default());
        } else if (key.compare("trace_id") == 0) {

                // if let Some(id) = Self::decode_id(value, key.as_str(), Self::TRACE_ID) {
                //     self.info.trace_id = id;
                // }
                // // 存在配置相同字段的情况，如“sw8”
                // if self.l7_log_dynamic_config.is_span_id(key.as_str()) {
                //     if let Some(id) = Self::decode_id(value, key.as_str(), Self::SPAN_ID) {
                //         self.info.span_id = id;
                //     }
                // }
                this->httpInfo.trace_id = value;
        } else if (key.compare("span_id") == 0 ) {
                this->httpInfo.span_id = value;
        } else if (key.compare("x_request_id") == 0) {
                this->httpInfo.x_request_id = value;
        } else if (key.compare("host") == 0 ) {
            if (direction == ClientToServer) {
                    this->httpInfo.host = value;
            }
        }

        // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
        if (direction == ServerToClient) {
            this->httpInfo.resp_content_length = content_length;
        } else {
            this->httpInfo.req_content_length = content_length;
        }
        this->proto = L7_PROTOCOL_HTTP1;
    }

        return 0;

}

void HTTPParser::reset_logs()
{

}

L7Protocol HTTPParser::get_l7_protocol()
{

    return L7_PROTOCOL_HTTP1;
}
