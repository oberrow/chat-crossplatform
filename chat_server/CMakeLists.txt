# CMakeList.txt : CMake project for chat_server, include source and define
# project specific logic here.
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (chat_server "chat_server.c" "boolean_type.h" "vec.h" "utarray.h" "lib_src/argon2/argon2.h" "lib_src/vec.c" "threads.h" "threads.c")
add_library(argon2 STATIC "lib_src/argon2/argon2.c" "lib_src/argon2/core.c" "lib_src/argon2/encoding.c" "lib_src/argon2/opt.c" "lib_src/argon2/ref.c" "lib_src/argon2/run.c" "lib_src/argon2/test.c" "lib_src/argon2/thread.c" "lib_src/argon2/blake2/blake2b.c")
target_sources(chat_server PUBLIC "dbInterface.c" PUBLIC "User.c")

target_link_libraries(chat_server argon2)

if(WIN32)
# We're on windows
target_include_directories(chat_server PUBLIC "C:\\Code\\other_libraries\\c-hashmap\\")
target_include_directories(chat_server PUBLIC "C:\\Code\\other_libraries\\c-vector\\")
target_include_directories(chat_server PUBLIC "C:\\Code\\other_libraries\\uthash\\src")
if($<CONFIG:DEBUG>)
target_link_libraries(chat_server "C:\\Code\\vcpkg\\packages\\openssl_x64-windows\\lib\\libssl.lib")
target_link_libraries(chat_server "C:\\Code\\vcpkg\\packages\\openssl_x64-windows\\lib\\libcrypto.lib")
else()
target_link_libraries(chat_server "C:\\Code\\vcpkg\\packages\\openssl_x64-windows\\debug\\lib\\libssl.lib")
target_link_libraries(chat_server "C:\\Code\\vcpkg\\packages\\openssl_x64-windows\\debug\\lib\\libcrypto.lib")
endif()
else()
# We're on linux
set(OPENSSL_USE_STATIC_lib_srcS TRUE)
find_package(OpenSSL REQUIRED)
find_package(db)
target_link_libraries(chat_server OpenSSL::SSL)
target_link_libraries(chat_server OpenSSL::Crypto)
target_link_libraries(chat_server db)
target_include_directories(chat_server PUBLIC ${CMAKE_SOURCE_DIR})
endif()