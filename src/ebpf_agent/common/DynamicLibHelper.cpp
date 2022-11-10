#include "DynamicLibHelper.h"
#include <dlfcn.h>



std::string DynamicLibLoader::GetError() {
    auto dlErr = dlerror();
    return (dlErr != NULL) ? dlErr : "";

}

void DynamicLibLoader::CloseLib(void* libPtr) {
    if (nullptr == libPtr)
        return;
    dlclose(libPtr);

}

// Release releases the ownership of @mLibPtr to caller.
void* DynamicLibLoader::Release() {
    auto ptr = mLibPtr;
    mLibPtr = nullptr;
    return ptr;
}

DynamicLibLoader::~DynamicLibLoader() {
    CloseLib(mLibPtr);
}


// @return a non-NULL ptr to indicate lib handle, otherwise nullptr is returned.
bool DynamicLibLoader::LoadDynLib(const std::string& libName,
                                  std::string& error,
                                  const std::string dlPrefix,
                                  const std::string dlSuffix) {
    error.clear();

    mLibPtr = dlopen((dlPrefix + "lib" + libName + ".so" + dlSuffix).c_str(), RTLD_LAZY);
    if (mLibPtr != NULL)
        return true;
    error = GetError();
    return false;
}

// LoadMethod loads method named @methodName from opened lib.
// If error is found, @error param will be set, otherwise empty.
void* DynamicLibLoader::LoadMethod(const std::string& methodName, std::string& error) {
    error.clear();

    dlerror(); // Clear last error.
    auto methodPtr = dlsym(mLibPtr, methodName.c_str());
    error = GetError();
    return methodPtr;

}