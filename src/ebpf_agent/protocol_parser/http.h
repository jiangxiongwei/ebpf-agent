

#ifndef __HTTP_H__
#define __HTTP_H__
#include <stdbool.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include "Enum.h"


#define MAX_LINES 20


// struct HttpInfo {

//     __32 stream_id;
//     char version[8];
//     char trace_id[64];
//     char span_id[64];
//     char method[8];
//     char path[128];
//     char host[32];
//     char client_ip[64];
//     char x_request_id[64];
//     __u64 req_content_length;
//     __u64 resp_content_length;


//     int (*merge)(struct HttpInfo self, struct HttpInfo other);
// };



struct L7LogDynamicConfig {

};



// struct HttpLog {
//     __u16 status_code;
//     enum LogMessageType msg_type;
//     enum L7Protocol proto;
//     enum L7ResponseStatus status;
//     struct HttpInfo info;
//     bool is_https;
//     struct L7LogDynamicConfig l7_log_dynamic_config;

// };


void  parse_lines_c(char payload[], int len, int *delimiters, int max_lines) {
    //delimiters 数组里存放的是换行符的位置
    int i = 0;
    int size = len;
    char *p = payload;
    int start_index = 0;
    while (i < max_lines) {
        int next_index = 0;
        int j;
        for(j = 0; j < size; j++) {
            //换行时，是连续的'\r'和'\n'
            if((j > 2) && (p[j] == '\n') && (p[j - 1] == '\r')) {
                delimiters[i] = start_index + j - 1;
                next_index = j + 1;
                break;
            }

        }
        if(next_index == 0) {//没有遇到换行符
            return;
        }
        if(next_index > size) {//刚好最后两个字符是\r\n
            return;
        }

        p =  p + next_index;
        start_index = start_index + next_index;
        size = size - (next_index);
        i++;
    }   

}

void get_http_resp_info(char line_info[], int len, char *version, int *status_code) {

    char* delim = " ";//分隔符字符串
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

void get_http_request_info(char line_info[], int len, char *method, char *path, char *version) {



}

void parse_http_v1_c(char payload[], int len, PacketDirection direction) {
    if (!is_http_v1_payload(payload)) {
        return;
    }
    //指针是只读的
    int* const delimiters = (int*)malloc(MAX_LINES * (sizeof(int)));
    memset(delimiters, 0, MAX_LINES);
    parse_lines_c(payload, len, delimiters, MAX_LINES);
    int line_0_end = delimiters[0];
    char *line_0;
    for (int i = 0; i < line_0_end; i++) {
        line_0[i] = payload[i];
    }

    //
    if (direction == ServerToClient) {
            // HTTP响应行：HTTP/1.1 404 Not Found.
            char version[5] = {0};
            int status_code = 0;
            get_http_resp_info(line_0, line_0_end, version, &status_code);

            // self.info.version = version;
            // self.status_code = status_code as u16;

            // self.msg_type = LogMessageType::Response;

            // self.set_status(status_code);
    } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            char method[16] = {0};
            char path[128] = {0};
            char version[5] = {0};
            get_http_request_info(line_0, line_0_end, method, path, version);

            // self.info.method = contexts[0].to_string();
            // self.info.path = contexts[1].to_string();
            // self.info.version = get_http_request_version(contexts[2])?.to_string();
            // self.msg_type = LogMessageType::Request;
    }
    unsigned long long content_length = 0;

    for(int j = 1; j < MAX_LINES; j++) {
        // 第j行的换行符位置
        int line_end_index = delimiters[j];
        char *line_text;
        for (int k = 0; k < line_end_index; k++) {
            line_text[k] = payload[line_0_end + 2];
        }

    }
    // content_length: Option<u64> = None;
    //     for body_line in &lines[1..] {
    //         let col_index = body_line.iter().position(|x| *x == b':');
    //         if col_index.is_none() {
    //             continue;
    //         }
    //         let col_index = col_index.unwrap();
    //         if col_index + 1 >= body_line.len() {
    //             continue;
    //         }
    //         let key = str::from_utf8(&body_line[..col_index])?.to_lowercase();
    //         let value = str::from_utf8(&body_line[col_index + 1..])?.trim();
    //         if &key == "content-length" {
    //             content_length = Some(value.parse::<u64>().unwrap_or_default());
    //         } else if self.l7_log_dynamic_config.is_trace_id(key.as_str()) {
    //             if let Some(id) = Self::decode_id(value, key.as_str(), Self::TRACE_ID) {
    //                 self.info.trace_id = id;
    //             }
    //             // 存在配置相同字段的情况，如“sw8”
    //             if self.l7_log_dynamic_config.is_span_id(key.as_str()) {
    //                 if let Some(id) = Self::decode_id(value, key.as_str(), Self::SPAN_ID) {
    //                     self.info.span_id = id;
    //                 }
    //             }
    //         } else if self.l7_log_dynamic_config.is_span_id(key.as_str()) {
    //             if let Some(id) = Self::decode_id(value, key.as_str(), Self::SPAN_ID) {
    //                 self.info.span_id = id;
    //             }
    //         } else if !self.l7_log_dynamic_config.x_request_id_origin.is_empty()
    //             && key == self.l7_log_dynamic_config.x_request_id_lower
    //         {
    //             self.info.x_request_id = value.to_owned();
    //         } else if direction == PacketDirection::ClientToServer {
    //             if &key == "host" {
    //                 self.info.host = value.to_owned();
    //             } else if !self.l7_log_dynamic_config.proxy_client_origin.is_empty()
    //                 && key == self.l7_log_dynamic_config.proxy_client_lower
    //             {
    //                 self.info.client_ip = value.to_owned();
    //             }
    //         }
    //     }

    //     // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
    //     if direction == PacketDirection::ServerToClient {
    //         self.info.resp_content_length = content_length;
    //     } else {
    //         self.info.req_content_length = content_length;
    //     }
    //     self.proto = L7Protocol::Http1;

}

const char *REQUEST_PREFIXS[9] = {
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH",
};

const char *RESPONSE_PREFIX = "HTTP/";

const char *HTTP_V1_0_VERSION = "HTTP/1.0";
const char *HTTP_V1_1_VERSION = "HTTP/1.1";


int has_prefix(unsigned char s[], unsigned char prefix[], int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (s[i] != prefix[i])
            return 0;
    }
    return 1;
}
int is_http_v1_payload(char buf[]) {

    int i;
    int failed = 0;
    for (i = 0; i < 5; i++) {
        if (buf[i] != RESPONSE_PREFIX[i]) {
            failed = 1;
            break;
        }
    }
    if (failed == 0)
        return 1;
    
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
            return 1;
        } else {
            failed = 0;
        }        
    }
    
    return 0;
}



#endif /* __HTTP_H__ */
