#include "Sender.h"


class FileSender : public Sender {

public:
    FileSender(){cout << "FileSender constructor" << endl;};
    void virtual send(AppProtoLogsData log);


};