#include "cipher.h"

Cipher::Cipher(QObject *parent)
    : QObject{parent}
{
    initialize();
}

Cipher::~Cipher()
{
    finalize();
}

EVP_PKEY *Cipher::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    EVP_PKEY* rsaPubKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(!rsaPubKey){
        qCritical() << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL);
    }

    BIO_free(bio);
    return rsaPubKey;
}

EVP_PKEY *Cipher::getPublicKey(QString filename)
{
    QByteArray data = readFile(filename);
    return getPublicKey(data);
}

EVP_PKEY *Cipher::getPrivateKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    EVP_PKEY* rsaPrivKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if(!rsaPrivKey){
        qCritical() << "Could not load private key" << ERR_error_string(ERR_get_error(), NULL);
    }

    BIO_free(bio);
    return rsaPrivKey;
}

EVP_PKEY *Cipher::getPrivateKey(QString filename)
{
    QByteArray data = readFile(filename);
    return getPrivateKey(data);
}

QByteArray Cipher::encryptRSA(EVP_PKEY *key, QByteArray &data)
{
    QByteArray buffer;
    EVP_PKEY_CTX *ctx;
    int dataSize = data.length();
    unsigned char* out;
    const unsigned char* str = (const unsigned char*)data.constData();
    size_t outlen;
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx){
        /* Error occurred */
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0){
        /* Error */
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0){
        /* Error */
    }

    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, str, dataSize) <= 0){
        /* Error */
    }

    out = (unsigned char*)OPENSSL_malloc(outlen);

    if (!out){
        /* malloc failure */
    }

    int resultLen = EVP_PKEY_encrypt(ctx, out, &outlen, str, dataSize);
    if(resultLen <= 0) {
        /* Error */
    }

    buffer = QByteArray(reinterpret_cast<char*>(out), outlen);

    return buffer;
}

QByteArray Cipher::decryptRSA(EVP_PKEY *key, QByteArray &data)
{
    QByteArray buffer;
    EVP_PKEY_CTX *ctx;
    int dataSize = data.length();
    const unsigned char* encryptedData = (const unsigned char*)data.constData();
    size_t outlen;
    ctx = EVP_PKEY_CTX_new(key, NULL);

    if (!ctx){
        /* Error occurred */
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0){
        /* Error */
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0){
        /* Error */
    }

    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encryptedData, dataSize) <= 0){
        /* Error */
    }

    unsigned char* out = (unsigned char*)OPENSSL_malloc(outlen);

    if (!out){
        /* malloc failure */
    }
    int resultLen = EVP_PKEY_decrypt(ctx, out, &outlen, encryptedData, dataSize);
    if(resultLen <= 0){
        qCritical() << "Could not decrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }

    buffer = QByteArray::fromRawData((const char*)out, outlen);

    return buffer;
}

void Cipher::freeEVPKey(EVP_PKEY *key)
{
    EVP_PKEY_free(key);
}

void Cipher::initialize()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void Cipher::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray Cipher::readFile(QString filename)
{
    QByteArray data;
    QFile file(filename);
    if(!file.open(QFile::ReadOnly))
    {
        qCritical() << file.errorString();
        return data;
    }

    data = file.readAll();
    file.close();
    return data;
}

void Cipher::writeFile(QString filename, QByteArray &data)
{
    QFile file(filename);
    if(!file.open(QFile::WriteOnly))
    {
        qCritical() << file.errorString();
        return;
    }

    file.write(data);
    file.close();
}
