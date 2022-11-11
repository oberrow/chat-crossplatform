#pragma once

int start_thread(void(*func)(void* args), void* args);
void detach_thread(int handle);
void join_thread(int handle);
void exit_thread(int code);