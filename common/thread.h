#ifndef THREAD_H
#define THREAD_H

#if defined(WIN32)

#include <windows.h>
#include <process.h>
#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x) ReleaseMutex(x)
#define THREAD_ID GetCurrentThreadId()

#define THREAD_TYPE DWORD
//! Создание нового потока
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0,(arg));\
    (tid) = GetCurrentThreadId(); \
} while (0)
#define THREAD_CC

#else

/* _POSIX_THREADS is normally defined in unistd.h if pthreads are
available on your platform. */
#include <pthread.h>
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()

#define THREAD_TYPE pthread_t
//! Создание нового потока
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, (entry), (arg))
#define THREAD_CC *

#endif

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;
struct CRYPTO_dynlock_value
{
    MUTEX_TYPE mutex;
};

static void locking_function(int mode, int n, const char * file, int line);
static unsigned long id_function(void);
static struct CRYPTO_dynlock_value * dyn_create_function(const char *file, int line);
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                              const char *file, int line);
static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line);
int THREAD_setup(void);
int THREAD_cleanup(void);

#endif // THREAD_H
