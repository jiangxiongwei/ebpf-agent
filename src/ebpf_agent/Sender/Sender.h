#ifndef __SENDER_H__
#define __SENDER_H__

#include "protocol_logs.h"


class Sender {

public:
    void virtual send(AppProtoLogsData log){};
    void virtual send_all(){}


};

#endif //__SENDER_H__