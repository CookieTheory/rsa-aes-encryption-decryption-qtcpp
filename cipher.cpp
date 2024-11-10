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
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(), NULL);
        free(out);
        return buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(out), outlen);
    free(out);

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
        free(out);
        return buffer;
    }

    buffer = QByteArray::fromRawData((const char*)out, outlen);
    //free(out);

    return buffer;
}

QByteArray Cipher::encryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt = randomBytes(SALTSIZE);
    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    const unsigned char* salt = (const unsigned char*) msalt.constData();
    const unsigned char* password = (const unsigned char*) passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, password, passphrase.length(), rounds, key, iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        qCritical() << "EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char *input = data.data();
    int len = data.size();

    int c_len = len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char*)malloc(c_len);

    if (!ciphertext){
        /* malloc failure */
    }

    if(!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL))
    {
        qCritical() << "EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), NULL);
        free(ciphertext);
        return QByteArray();
    }

    if(!EVP_EncryptUpdate(ctx, ciphertext, &c_len, (unsigned char *)input, len))
    {
        qCritical() << "EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), NULL);
        free(ciphertext);
        return QByteArray();
    }

    if(!EVP_EncryptFinal(ctx, ciphertext + c_len, &f_len))
    {
        qCritical() << "EVP_EncryptFinal() error: " << ERR_error_string(ERR_get_error(), NULL);
        free(ciphertext);
        return QByteArray();
    }

    len = c_len + f_len;
    EVP_CIPHER_CTX_cipher(ctx);

    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), len);
    free(ciphertext);
    QByteArray finished;
    finished.append("Salted__");
    finished.append(msalt);
    finished.append(encrypted);

    return finished;
}

QByteArray Cipher::decryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt;
    if(QString(data.mid(0,8)) == "Salted__")
    {
        msalt = data.mid(8,8);
        data = data.mid(16);
    }
    else
    {
        qWarning() << "Could not load salt from data!";
        msalt = randomBytes(SALTSIZE);
    }

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    const unsigned char* salt = (const unsigned char*) msalt.constData();
    const unsigned char* password = (const unsigned char*) passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, password, passphrase.length(), rounds, key, iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(de);

    if(!EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv))
    {
        qCritical() << "EVP_DecryptInit_ex() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char *input = data.data();
    int len = data.size();

    int p_len = len, f_len = 0;
    unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

    if (!plaintext){
        /* malloc failure */
    }

    if(!EVP_DecryptUpdate(de, plaintext, &p_len, (unsigned char*)input, len))
    {
        qCritical() << "EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), NULL);
        free(plaintext);
        return QByteArray();
    }

    if(!EVP_DecryptFinal_ex(de, plaintext + p_len, &f_len))
    {
        qCritical() << "EVP_DecryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), NULL);
        free(plaintext);
        return QByteArray();
    }

    len = p_len + f_len;
    EVP_CIPHER_CTX_cleanup(de);

    QByteArray decrypted = QByteArray(reinterpret_cast<char *>(plaintext), len);
    free(plaintext);

    return decrypted;

}

QByteArray Cipher::randomBytes(int size)
{
    unsigned char arr[size];
    RAND_bytes(arr, size);

    QByteArray ranBytes = QByteArray(reinterpret_cast<char*>(arr), size);
    return ranBytes;
}

EVP_PKEY *Cipher::createRSAKeyPair(int key_size)
{
    EVP_PKEY_CTX* pctx;
    EVP_PKEY* rsaKeyPair = NULL;
    if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) qWarning() << "no id rsa";
    if(!EVP_PKEY_keygen_init(pctx)) qWarning() << "no keygen init";
    //if(!EVP_PKEY_paramgen_init(pctx)) qWarning() << "no param init";

    EVP_PKEY_CTX_set_rsa_padding(pctx, PADDING);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, key_size);
    EVP_PKEY_keygen(pctx, &rsaKeyPair);

    return rsaKeyPair;
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
