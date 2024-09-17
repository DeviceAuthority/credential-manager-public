#ifdef WIN32
#include <Windows.h>
#else
#include <sys/time.h>
#if _POSIX_C_SOURCE >= 199309L
#include <time.h>       // for nanosleep
#else
#include <unistd.h>     // for usleep
#endif // #if _POSIX_C_SOURCE >= 199309L
#endif // #ifndef WIN32


#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

void sleep_ms(int milliseconds)
{
#if defined(WIN32)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    usleep(milliseconds * 1000);
#endif // #if defined(WIN32)
}

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus
