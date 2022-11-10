#include "RuntimeUtil.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <errno.h>
#include <cstdio>
#include <sstream>

const std::string PATH_SEPARATOR = "/";

std::string GetProcessExecutionDir(void) {
    char exePath[PATH_MAX + 1] = {0};
    readlink("/proc/self/exe", exePath, sizeof(exePath));
    std::string fullPath(exePath);
    size_t index = fullPath.rfind(PATH_SEPARATOR);
    if (index == std::string::npos) {
        return ""; 
    }   
    return fullPath.substr(0, index + 1); 

}

std::string GetBinaryName(void) {
    char exePath[PATH_MAX + 1] = {0};
    readlink("/proc/self/exe", exePath, sizeof(exePath));
    std::string fullPath(exePath);
    return fullPath;

}
