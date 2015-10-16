#include "common.h"
#include <openssl/x509.h>

//! Настройка клиента
SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;

    // Создание SSL контекста
    ctx = SSL_CTX_new(SSLv23_method());
    if(ctx == NULL)
        int_error("Error creating SSL context");

    return ctx;
}

//! Работа с сервером после прохождения процедуры "рукопожатие"
//! Передает серверу информацию введенную с клавиатуры
int do_client_loop(SSL *ssl)
{
    int err, nwritten;
    char buf[80];

    for (;;) {
        if (!fgets(buf, sizeof(buf), stdin))
            break;
        for (nwritten = 0; nwritten < sizeof(buf); nwritten += err) {
            err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
            if (err <= 0)
                return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[])
{
    BIO *conn;
    SSL *ssl;
    SSL_CTX *ctx;
    X509*    server_cert;
    char*    str;

    // Инициализация OpenSSL
    init_OpenSSL();
    seed_prng();

    // Создание контекста клиента
    ctx = setup_client_ctx();

    // Создание нового объекта соединения с именем сервера и порта
    conn = BIO_new_connect(SERVER ":" PORT);
    if (!conn)
        int_error("Error creating connection BIO");


    // Соединение с сервером
    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");
    BIO_set_close(conn, BIO_NOCLOSE);

    // Создание SSL структуры для соединения
    if (!(ssl = SSL_new(ctx)))
        int_error("Error creating an SSL context");

    // Соединяет SSL объект с вводом-выводом
    SSL_set_bio(ssl, conn, conn);

    // Инициализация рукопожатия и его прохождение
    if (SSL_connect(ssl) <= 0)
        int_error("Error connecting SSL object");

    fprintf(stderr, "SSL Connection opened\n");

    // Вывод информации о сертификате на консоль
    server_cert = SSL_get_peer_certificate (ssl);

    // Загрузка открытого ключа корневого сертификата
    BIO* in = NULL;
    in = BIO_new(BIO_s_file());
    BIO_read_filename(in,"ca.crt");
    if (in == NULL)
        int_error("Error loading of CA public key");

    X509 *cacert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (in != NULL)
        BIO_free (in);


    EVP_PKEY *publicKey = X509_get_pubkey(cacert);
    X509_free(cacert);

    if (publicKey == NULL)
        int_error("Public key not found !!!");

    if (X509_verify(server_cert, publicKey)!=1)
        int_error("Not verify certificate !!!");

    str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    if (str == NULL)
        int_error("Error getting subject name of certificate");
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    if (str == NULL)
        int_error("Error getting issuer name of certificate");
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);

    X509_free(server_cert);
    EVP_PKEY_free(publicKey);

    // Работа с сервером после прохождения процедуры "рукопожатие"
    if (do_client_loop(ssl))
        // Закрытие SSL соединения
        SSL_shutdown(ssl);
    else
        // Очистка SSL объекта
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");

    BIO_set_close(conn, BIO_CLOSE);
    SSL_free(ssl);
    BIO_free (conn);
    SSL_CTX_free(ctx);

    return 0;
}
