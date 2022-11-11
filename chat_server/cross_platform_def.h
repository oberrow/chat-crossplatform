#pragma once
#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#define GetError() WSAGetLastError
#define PROTOCOL IPPROTO_TCP
#define DEFAULT_PORT 443
#else
#include "boolean_type.h"
typedef int SOCKET;
typedef char* LPSTR;
typedef short* LPWSTR;
typedef const char* LPCSTR;
typedef const short* LPCWSTR;
typedef bool BOOL;
typedef unsigned long long SIZE_T;
typedef long DWORD;
#define INVALID_SOCKET (-1) 
#define WINAPI
#define ERROR_FILE_NOT_FOUND ENOENT
#define ERROR_ACCESS_DENIED EPERM
#define TRUE 1
#define FALSE 0
#define SD_BOTH SHUT_RDWR
#define ExitProcess(ret) exit(ret);
#define CTRL_C_EVENT        SIGINT
#define CTRL_CLOSE_EVENT    SIGINT
#define printf_s printf
#define closesocket close
#define stricmp strcasecmp
#define _stricmp strcasecmp
#define SecureZeroMemory(p, sz) memset(p, 0, sz)
#define strcpy_s(dest, sz, src) strncpy(dest, src, sz)
#define _recalloc(ptr, size, vSz) realloc(ptr, size); memset(ptr, 0, size * vSz);
#define GetError() errno
#define sprintf_s snprintf
#define fprintf_s fprintf
#define PROTOCOL 0
#define DEFAULT_PORT 8443
#endif