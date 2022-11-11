#include "threads.h"

#include <pthread.h>

int start_thread(void(*func)(void* args), void* args)
{
#if _WIN32
	return _beginthread(func, 0, args);
#else
	pthread_t id = 0;
	return pthread_create(&id, NULL, func, args);
#endif
}
void detach_thread(int handle)
{
#ifdef _WIN32
	CloseHandle(handle);
#else
	pthread_detach(handle);
#endif
}
void join_thread(int handle)
{
#ifdef _WIN32
	while(WaitForSingleObject(handle, INFINITE)) {}
	CloseHandle(handle);
#else
	int ret = 0;
	int *pret = &ret;
	int **dpret = &pret;
	pthread_join(handle, dpret);
	ret = *dpret;
#endif
}
void exit_thread(int code)
{
#ifdef WIN32
	ExitThread(code);
#else
	pthread_exit(&code);
#endif
}