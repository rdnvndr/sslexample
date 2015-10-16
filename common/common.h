#ifndef COMMON_H
#define COMMON_H

#define PORT "4422"
#define SERVER "localhost"
#define CLIENT "localhost"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

//! Обработка ошибки
void handle_error(const char *file, int lineno, const char *msg);
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

//! Инициализация OpenSSL
void init_OpenSSL(void);

//! Инициализация генратора случайных чисел
/*! Предназначено для исключения генерации повторяющихся данных
 *  Здесь не реализован !!! Необходима реализация !!!
*/
int seed_prng(int bytes = 10);

#endif // COMMON_H
