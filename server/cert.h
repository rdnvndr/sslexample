#ifndef CERT_H
#define CERT_H

#include "common.h"
#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>


//! Создание самоподписного сертификата
//! @param **x509p - ссылка на сертификат
//! @param **pkeyp - закрытый ключ
//! @param bits - длина ключа
//! @param days - срок действия сертификата
//! @return 1 - удачное создание сертификата, иначе ошибка создания сертификата
int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
// Расширенное описание сертификата
int add_ext(X509 *cert, int nid, char *value);

#endif // CERT_H
