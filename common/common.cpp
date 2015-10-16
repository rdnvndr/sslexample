#include "common.h"
#include "thread.h"

void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
    // Инициализация системы OpenSSL и регистрация алгоритмов
    if (!THREAD_setup() || !SSL_library_init()) {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }

    // Загрузка строк ошибок
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();

    // Добавляет все алгоритмы
    OpenSSL_add_all_algorithms();
}

int seed_prng(int bytes)
{
    /*
    int error;
    char *buf;
    prngctx_t ctx;
    egads_init(&ctx, NULL, NULL, &error);
    if (error)
        return 0;
    buf = (char *)malloc(bytes);
    egads_entropy(&ctx, buf, bytes, &error);
    if (!error)
        RAND_seed(buf, bytes);
    free(buf);
    egads_destroy(&ctx);
    return (!error);*/
    return 0;
}
