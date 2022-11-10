
#include <string>
#include <cstdlib>

class DynamicLibLoader;


class DynamicLibLoader {
    void* mLibPtr = nullptr;

    std::string GetError();

public:
    static void CloseLib(void* libPtr);

    // Release releases the ownership of @mLibPtr to caller.
    void* Release();

    ~DynamicLibLoader();

    // LoadDynLib loads dynamic library named @libName from current working dir.
    // For linux, the so name is 'lib+@libName.so'.
    // For Windows, the dll name is '@libName.dll'.
    // @return a non-NULL ptr to indicate lib handle, otherwise nullptr is returned.
    bool LoadDynLib(const std::string& libName,
                    std::string& error,
                    const std::string dlPrefix = "", 
                    const std::string dlSuffix = "");

    // LoadMethod loads method named @methodName from opened lib.
    // If error is found, @error param will be set, otherwise empty.
    void* LoadMethod(const std::string& methodName, std::string& error);
};
