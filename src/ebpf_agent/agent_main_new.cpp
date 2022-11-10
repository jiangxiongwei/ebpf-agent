#include "EBPFWrapper.h"


EBPFWrapper* mEBPFWrapper;
struct Config {

};

void ReloadSource()
{
    mEBPFWrapper = EBPFWrapper::GetInstance();
    if (mEBPFWrapper != nullptr) {
        mEBPFWrapper->Init();
        mEBPFWrapper->Start();
    }

}

void StartEventLoop()
{
    while (true)
    {
        /* code */
        mEBPFWrapper->ProcessPackets(1, 1);
    }
    
}

int main_new(int argc, char *argv[])
{
    bool success = true;

    


    std::vector<Config*> allObserverConfigs;
    ReloadSource();
    StartEventLoop();












}