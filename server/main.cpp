#include "common.h"
#include "thread.h"
#include "cert.h"

#define CERTFILE "certificate.pem"
#define KEYFILE  "private.key"
#define CIPHER_LIST "AES256-SHA256"

//! Настройка сервера
SSL_CTX *setup_server_ctx(void)
{
    SSL_CTX *ctx;

    // Создание SSL контекста
    ctx = SSL_CTX_new(SSLv23_method());
    if(ctx == NULL)
        int_error("Error creating SSL context");

    // Создание сертификата и закрытого ключа
    X509 *x509=NULL;
    EVP_PKEY *pkey=NULL;
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    mkcert(&x509,&pkey,512,0,365);

    // Включение сертификата в контекст SSL
    if (SSL_CTX_use_certificate(ctx,x509)!=1) {
        SSL_CTX_free(ctx);
        int_error("Error loading certificate from file");
    }

    // Включение закрытого ключа в контекст
    if (SSL_CTX_use_PrivateKey(ctx,pkey)!=1) {
        SSL_CTX_free(ctx);
        int_error("Error loading private key from file");
    }

    // Установка доступного списка алгоритмов шифрования для SSL контекста
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1) {
        SSL_CTX_free(ctx);
        int_error("Error setting cipher list (no valid ciphers)");
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return ctx;
}

//! Работа с клиентом прошедшим процедуру "рукопожатие"
//! Выводит на экран переданную клиентом информацию
int do_server_loop(SSL *ssl)
{
    int err, nread;
    char buf[80];

    do {
        for (nread = 0; nread < sizeof(buf); nread += err) {
            err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
            if (err <= 0)
                break;
        }
        fwrite(buf, 1, nread, stdout);
    } while (err > 0);

    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

//! Работа с SSL соединением в отдельном потоке
void THREAD_CC server_thread(void *arg)
{
    SSL *ssl = (SSL *)arg;

#ifndef WIN32
    pthread_detach(pthread_self());
#endif

    // Ожидание и прохождение процедуры "рукопожатия"
    if (SSL_accept(ssl) <= 0)
        int_error("Error accepting SSL connection");
    fprintf(stderr, "SSL Connection opened\n");

    // Работа с клиентом прошедшим процедуру "рукопожатие"
    if (do_server_loop(ssl))
        // Закрытие SSL соединения
        SSL_shutdown(ssl);
    else
        // Очистка SSL объекта
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");

    SSL_free(ssl);
    ERR_remove_state(0);
#ifdef WIN32
    _endthread();
#endif

}

int main(int argc, char *argv[])
{
    BIO *acc, *client;
    SSL *ssl;
    SSL_CTX *ctx;
    THREAD_TYPE tid;

    // Инициализация OpenSSL
    init_OpenSSL();
    seed_prng();

    // Создание контекста сервера
    ctx = setup_server_ctx();

    // Создание сокета
    acc = BIO_new_accept((char *)"0.0.0.0:"PORT);
    if (!acc)
        int_error("Error creating server socket");

    // Привязка сокета к порту и начало работы (первый вызов функции)
    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");

    for (;;)
    {
        // Ожидание входящего соединения
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");

        // Удаляет соединение из ожидания и возращает вместо него новое
        client = BIO_pop(acc);

        // Создание SSL структуры для соединения
        if (!(ssl = SSL_new(ctx)))
            int_error("Error creating SSL context");

        // Соединяет SSL объект с вводом-выводом
        SSL_set_bio(ssl, client/* чтение */, client /* запись */);

        // Вызов работы с соединением в отдельном потоке
        THREAD_CREATE(tid, server_thread, ssl);
    }

    SSL_CTX_free(ctx);
    BIO_free(acc);

    // http://stackoverflow.com/questions/11759725/opensslssl-library-init-memory-leak
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    return 0;
}
