#pragma once
#include "boolean_type.h"
#include <stdio.h>
#include "vec.h"
#include "utarray.h"
#include "lib_src/argon2/argon2.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "dbInterface.h"
#include "User.h"
#include <locale.h>
#ifdef _WIN32
#include <winsock2.h>
#include <conio.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "threads.h"
#include <signal.h>
#endif