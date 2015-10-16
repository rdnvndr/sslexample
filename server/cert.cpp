#include "cert.h"
#include <openssl/x509.h>

int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
    // Сертификат
    X509 *x;
    // Закрытый ключ
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;

    if ((pkeyp == NULL) || (*pkeyp == NULL)) {
        // Создание структуры закрытого ключа
        if ((pk=EVP_PKEY_new()) == NULL)
            int_error("Erroneous creation of a structure");
    } else
        pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL)) {
        // Создание структуры сертификата
        if ((x=X509_new()) == NULL)
            int_error("Erroneous creation of a structure");
    } else
        x = *x509p;

    // Создание закрытого ключа
    rsa = RSA_generate_key(bits,RSA_F4,NULL,NULL);
    if (rsa==NULL || !EVP_PKEY_assign_RSA(pk,rsa))
         int_error("Erroneous creation of a private key");

    // Установка версии сертификата
    X509_set_version(x,2);
    // Установка серийного номера сертификата
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    // Установка даты начала действия сертификата
    X509_gmtime_adj(X509_get_notBefore(x),0);
    // Установка даты окончания действия сертификата
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);

    // Запись(установка) публичного ключа в сетификат
    X509_set_pubkey(x,pk);

    // Получение сведений о сертификате
    name = X509_get_subject_name(x);

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    // Добавление сведений о стране издателя
    X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC,  (unsigned char *)"RU", -1, -1, 0);
    // Добавление сведений об издателе
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC,  (unsigned char *)"Ascon Ltd", -1, -1, 0);

    /* Its self signed so set the issuer name to be the same as the
     * subject.
     */
    // Запись сведений об издателе
    X509_set_issuer_name(x,name);

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, (char *)"critical,CA:TRUE");
    add_ext(x, NID_key_usage, (char *)"critical,keyCertSign,cRLSign");

    add_ext(x, NID_subject_key_identifier, (char *)"hash");

    /* Some Netscape specific extensions */
    /*add_ext(x, NID_netscape_cert_type, "sslCA");

    add_ext(x, NID_netscape_comment, "example comment extension");*/


#ifdef CUSTOM_EXT
    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, "example comment alias");
    }
#endif

    // Загрузка закрытого ключа корневого сертификата
    BIO* in = NULL;
    in = BIO_new(BIO_s_file());
    BIO_read_filename(in,"ca.key");
    if (in == NULL)
        int_error("Error loading of CA private key");


    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (in != NULL)
        BIO_free (in);

    if ( pkey == NULL )
        return(0);

    // Подпись сертификата
    if (!X509_sign(x,pkey,EVP_sha1()))
        int_error("Erroneous  signature of a certificate");
    EVP_PKEY_free(pkey);

    *x509p=x;
    *pkeyp=pk;
    return(1);
}


