#ifndef __APPPROTOINFO_H__
#define __APPPROTOINFO_H__


#include <iostream>

class AppProtocolInfo {

public:
    virtual uint32_t session_id(){return 0;}
    virtual void merge(AppProtocolInfo *other){};


};


#endif //__APPPROTOINFO_H__