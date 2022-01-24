#include "tlssrv.h"
#include <assert.h>
#include <curl/curl.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "gencreds.h"

#define MRENCLAVE_SIZE 32
#define MRSIGNER_SIZE 32
#define ISVPRODID_SIZE 16
#define BUFSIZE 32
#define EXPORTED_KEY_BUFFSIZE 20480
#define DEBUG_LEVEL 0

using namespace std;

extern "C"
{
    int setup_tls_server(const char* server_port);
};

static mbedtls_net_context client_fd;
static tlssrv_t* tlsServer = NULL;
static tlssrv_err_t tlsError;

static bool _started;
static const char* _pers = "ssl_server";
static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;

static void _clear_err(tlssrv_err_t* err)
{
    if (err)
        err->buf[0] = '\0';
}

__attribute__((format(printf, 2, 3))) static void _put_err(
    tlssrv_err_t* err,
    const char* fmt,
    ...)
{
    if (err)
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->buf, sizeof(err->buf), fmt, ap);
        va_end(ap);
    }
}

__attribute__((format(printf, 3, 4))) static void _put_mbedtls_err(
    tlssrv_err_t* err,
    int code,
    const char* fmt,
    ...)
{
    _clear_err(err);

    if (err && code)
    {
        char buf1[1024];
        mbedtls_strerror(code, buf1, sizeof(buf1));

        char buf2[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf2, sizeof(buf2), fmt, ap);
        va_end(ap);
    }
}

int tlssrv_startup(tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (_started)
    {
        _put_err(err, "already initialized");
        goto done;
    }

    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);

    // #if !defined(NDEBUG)
    //     mbedtls_debug_set_threshold(DEBUG_LEVEL);
    // #endif

    if ((r = mbedtls_ctr_drbg_seed(
             &_ctr_drbg,
             mbedtls_entropy_func,
             &_entropy,
             (const unsigned char*)_pers,
             strlen(_pers))) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_entropy_func()");
        ret = r;
        goto done;
    }

    _started = true;
    ret = 0;

done:

    if (ret != 0)
    {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
    }

    return ret;
}

int tlssrv_shutdown(tlssrv_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!_started)
    {
        _put_err(err, "not started");
        goto done;
    }

    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);

done:

    return ret;
}

static int _get_cert_and_private_key(
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tlssrv_err_t* err)
{
    int ret = -1;
    uint8_t* cert_data = NULL;
    size_t cert_size;
    uint8_t* private_key_data = NULL;
    size_t private_key_size;
    const char COMMON_NAME[] = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

    _clear_err(err);

    if (!crt || !pk)
        goto done;

    if (generate_attested_credentials(
            COMMON_NAME,
            0,
            &cert_data,
            &cert_size,
            &private_key_data,
            &private_key_size) != 0)
    {
        goto done;
    }
    /* Convert the certificate from DER to internal format */
    if (mbedtls_x509_crt_parse_der(crt, cert_data, cert_size) != 0)
    {
        goto done;
    }

    /* Convert the private key from PEM to internal format */
    if (mbedtls_pk_parse_key(pk, private_key_data, private_key_size, NULL, 0) !=
        0)
    {
        goto done;
    }

    ret = 0;

done:

    if (private_key_data)
        oe_free_key(private_key_data, private_key_size, NULL, 0);

    if (cert_data)
        oe_free_attestation_certificate(cert_data);
    return ret;
}

/* The mbedtls debug tracing function */
static void _mbedtls_dbg(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    (void)level;
    (void)ctx;

    printf("_mbedtls_dbg.server: %s:%04d: %s", file, line, str);
}

static oe_result_t _enclave_identity_verifier(
    oe_identity_t* identity,
    void* arg)
{
    tlssrv_t* srv = (tlssrv_t*)arg;

    if (!identity || !srv || !srv->verify_identity)
        return OE_VERIFY_FAILED;

    return srv->verify_identity(
        srv->verify_identity_arg,
        identity->unique_id,
        OE_UNIQUE_ID_SIZE,
        identity->signer_id,
        OE_SIGNER_ID_SIZE,
        identity->product_id,
        OE_PRODUCT_ID_SIZE,
        identity->security_version);
}

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;
    (void)depth;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    if (cert_size <= 0)
        goto done;

    oe_result_t r;
    if ((r = oe_verify_attestation_certificate(
             cert_buf, cert_size, _enclave_identity_verifier, data)) != OE_OK)
    {
        goto done;
    }

    ret = 0;
    *flags = 0;

done:
    return ret;
}

static int _configure_srv(tlssrv_t* srv, tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if ((r = _get_cert_and_private_key(&srv->crt, &srv->pk, err)) != 0)
    {
        goto done;
    }

    if ((r = mbedtls_ssl_config_defaults(
             &srv->conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_config_defaults");
        ret = r;
        goto done;
    }

    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    mbedtls_ssl_conf_dbg(&srv->conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_session_cache(
        &srv->conf, &srv->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    mbedtls_ssl_conf_authmode(&srv->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_verify(&srv->conf, _cert_verify_callback, srv);

    mbedtls_ssl_conf_ca_chain(&srv->conf, srv->crt.next, NULL);

    // Read time out in 100ms
    mbedtls_ssl_conf_read_timeout(&srv->conf, 100);

    if ((r = mbedtls_ssl_conf_own_cert(&srv->conf, &srv->crt, &srv->pk)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_conf_own_cert");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_setup(&srv->ssl, &srv->conf)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_setup");
        ret = r;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tlssrv_create(
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    tlssrv_t** srv_out,
    tlssrv_err_t* err)
{
    int ret = -1;
    int r;
    tlssrv_t* srv = NULL;
    const char* pers = "tlssrv";

    _clear_err(err);

    // #if !defined(NDEBUG)
    //     mbedtls_debug_set_threshold(DEBUG_LEVEL);
    // #endif

    if (!srv_out)
    {
        _put_err(err, "invalid srv_out parameter");
        goto done;
    }

    if (!port)
    {
        _put_err(err, "invalid port parameter");
        goto done;
    }

    if (!_started)
    {
        _put_err(err, "not started: please call tlssrv_startup");
        goto done;
    }

    /* Initialize the server structure */
    {
        if (!(srv = (tlssrv_t*)calloc(1, sizeof(tlssrv_t))))
        {
            _put_err(err, "calloc(): out of memory");
            goto done;
        }

        srv->verify_identity = verify_identity;
        srv->verify_identity_arg = verify_identity_arg;

        mbedtls_net_init(&srv->net);
        mbedtls_ssl_init(&srv->ssl);
        mbedtls_ssl_config_init(&srv->conf);
        mbedtls_ssl_cache_init(&srv->cache);
        mbedtls_x509_crt_init(&srv->crt);
        mbedtls_pk_init(&srv->pk);
    }

    if ((r = mbedtls_net_bind(&srv->net, host, port, MBEDTLS_NET_PROTO_TCP)) !=
        0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_bind");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ctr_drbg_seed(
             &_ctr_drbg,
             mbedtls_entropy_func,
             &_entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ctr_drbg_seed");
        ret = r;
        goto done;
    }

    if ((r = _configure_srv(srv, err)) != 0)
    {
        goto done;
    }

    *srv_out = srv;
    srv = NULL;

    ret = 0;

done:

    if (srv)
    {
        mbedtls_net_free(&srv->net);
        mbedtls_ssl_free(&srv->ssl);
        mbedtls_ssl_config_free(&srv->conf);
        mbedtls_x509_crt_free(&srv->crt);
        mbedtls_pk_free(&srv->pk);
        mbedtls_ssl_cache_free(&srv->cache);
        free(srv);
    }

    return ret;
}

int tlssrv_destroy(tlssrv_t* srv, tlssrv_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        goto done;
    }

    mbedtls_ssl_close_notify(&srv->ssl);

    mbedtls_ssl_free(&srv->ssl);
    mbedtls_net_free(&srv->net);
    mbedtls_ssl_config_free(&srv->conf);
    mbedtls_x509_crt_free(&srv->crt);
    mbedtls_pk_free(&srv->pk);

done:
    return ret;
}

int tlssrv_accept(tlssrv_t* srv, mbedtls_net_context* conn, tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        goto done;
    }

    if (!conn)
    {
        _put_err(err, "invalid conn parameter");
        goto done;
    }

    if ((r = mbedtls_ssl_session_reset(&srv->ssl)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_session_reset");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_net_accept(&srv->net, conn, NULL, 0, NULL)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_accept");
        ret = r;
        goto done;
    }

    mbedtls_ssl_set_bio(
        &srv->ssl, conn, mbedtls_net_send, mbedtls_net_recv, NULL);

    for (;;)
    {
        r = mbedtls_ssl_handshake(&srv->ssl);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r != 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_handshake");
            ret = r;
            goto done;
        }

        break;
    }

    if (mbedtls_ssl_get_verify_result(&srv->ssl) != 0)
    {
        _put_err(err, "verify failed");
        mbedtls_ssl_close_notify(&srv->ssl);
        goto done;
    }

    ret = 0;

done:

    return ret;
}

int tlssrv_read(
    tlssrv_t* srv,
    unsigned char* data,
    size_t size,
    tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        ret = -2;
        goto done;
    }

    if (!data)
    {
        ret = -3;
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        ret = -4;
        _put_err(err, "invalid size parameter");
        goto done;
    }

    for (;;)
    {
        memset(data, 0, size);
        r = mbedtls_ssl_read(&srv->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_read");
            ret = r;
            goto done;
        }

        /* Save number of bytes read */
        ret = r;
        break;
    }

done:

    return ret;
}

int tlssrv_write(
    tlssrv_t* srv,
    const unsigned char* data,
    size_t size,
    tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        goto done;
    }

    if (!data)
    {
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        _put_err(err, "invalid size parameter");
        goto done;
    }

    for (;;)
    {
        r = mbedtls_ssl_write(&srv->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_write");
            ret = r;
            goto done;
        }

        ret = r;
        break;
    }

done:

    return ret;
}

void tlssrv_put_err(const tlssrv_err_t* err)
{
    if (err)
        fprintf(stderr, "error: %s\n", err->buf);
}

static oe_result_t verifier(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn)
{
    const uint64_t SGXLKL_ISVSVN = 1;
    const uint8_t SGXLKL_ISVPRODID[ISVPRODID_SIZE] = {1};
    const uint64_t OE_ISVSVN = 1;
    const uint8_t OE_ISVPRODID[ISVPRODID_SIZE] = {1};
    // clang-format off

    // SGX-LKL Debug MRSIGNER
    const uint8_t SGXLKL_MRSIGNER[] =
    {
        0x33, 0x17, 0x34, 0x4b, 0xfa, 0xe6, 0x25, 0x43,
        0x4d, 0x8c, 0x63, 0xe6, 0x45, 0xd5, 0x01, 0xe9,
        0xfb, 0x85, 0xec, 0x02, 0xbc, 0x34, 0x99, 0x3b,
        0x75, 0xe6, 0x47, 0x93, 0x08, 0x75, 0x77, 0xf4
    };

    // OE SDK Debug MRSIGNER
    const uint8_t OE_MRSIGNER[] =
    {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
        0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
        0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
        0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0x0a
    };

    // clang-format on

    (void)arg;

    if (!mrenclave || !mrsigner || !isvprodid)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrenclave_size != MRENCLAVE_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrsigner_size != MRSIGNER_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (isvprodid_size != ISVPRODID_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    printf("\n");
    printf(
        "=== _verify_identity() isvprodid = %d, isvsvn=%lu\n",
        isvprodid[0],
        isvsvn);
    printf("\n");

    if (memcmp(mrsigner, SGXLKL_MRSIGNER, MRSIGNER_SIZE) == 0)
    {
        if (memcmp(isvprodid, SGXLKL_ISVPRODID, ISVPRODID_SIZE) != 0)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
        if (isvsvn != SGXLKL_ISVSVN)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
    }
    // Allow OE debug identity to be used only in debug mode of client.
    else if (memcmp(mrsigner, OE_MRSIGNER, MRSIGNER_SIZE) == 0)
    {
        if (memcmp(isvprodid, OE_ISVPRODID, ISVPRODID_SIZE) != 0)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
        if (isvsvn != OE_ISVSVN)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
    }
    else
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    return OE_OK;
}

size_t WriteCallback(char* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int send_work_to_miner(const std::string& q)
{
    std::cout << "Connecting to geth node and getting PoW from the header\n";

    CURLcode ret;
    CURL* hnd;
    struct curl_slist* slist1;
    std::string readBuffer;
    slist1 = NULL;
    slist1 = curl_slist_append(slist1, "Content-Type: application/json");

    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, "localhost:8502");
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    string to_send = "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"miner_mine\","
                     "\"params\":[\"0x" +
                     q + "\"]}";
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, to_send.c_str());
    curl_easy_setopt(
        hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)to_send.length());
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.58.0");
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &readBuffer);

    ret = curl_easy_perform(hnd);

    std::cout << "Response from PoW: " << readBuffer << "\n";

    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist1);
    slist1 = NULL;

    // Sending PoW
    unsigned char dataS[3000];
    strcpy(reinterpret_cast<char*>(dataS), readBuffer.c_str());
    tlssrv_write(tlsServer, dataS, sizeof(dataS), &tlsError);
}

int send_rlp_to_miner(const std::string& rlp)
{
    struct curl_slist* slist1 = NULL;
    CURLcode ret;
    slist1 = curl_slist_append(slist1, "Content-Type: application/json");

    string to_send_2 = "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"miner_"
                       "propagateBlock\",\"params\":[\"" +
                       rlp + "\"]}";

    CURL* hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, "localhost:8502");
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, to_send_2.c_str());
    curl_easy_setopt(
        hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)to_send_2.size() * 2);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.58.0");
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);

    ret = curl_easy_perform(hnd);

    std::cout << ret << "\n";
    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist1);
    slist1 = NULL;
}

int process_client(std::string& q, std::string& coinbase, std::string& rlp)
{
    unsigned char* t = new unsigned char[1500];
    unsigned char* coinbase_message = new unsigned char[100];
    unsigned char* rlp_message = new unsigned char[3000];
    int rc = 0;
    if ((rc = tlssrv_read(tlsServer, t, 1000, &tlsError)) < 0)
    {
        printf(" failed! couldn't read from the client %d\n\n", rc);
        mbedtls_net_free(&client_fd);
        return rc;
    }
    const unsigned char* o = reinterpret_cast<const unsigned char*>(t);
    q = std::string(reinterpret_cast<const char*>(o));

    std::cout << "Response with cout: " << q << "\n";

    /* Read from the client */
    if ((rc = tlssrv_read(tlsServer, coinbase_message, 100, &tlsError)) < 0)
    {
        printf(" failed! couldn't read from the client %d\n\n", rc);
        mbedtls_net_free(&client_fd);
        return rc;
    }
    const unsigned char* coinbase_middle =
        reinterpret_cast<const unsigned char*>(coinbase_message);
    coinbase = std::string(reinterpret_cast<const char*>(coinbase_middle));
    std::cout << "Response with cout: " << coinbase << "\n";

    printf("Received some information from the client.\n");

    // Allow time out
    mbedtls_ssl_set_bio(
        &tlsServer->ssl,
        &client_fd,
        mbedtls_net_send,
        mbedtls_net_recv,
        mbedtls_net_recv_timeout);

    rc = 0;

    /* Read from the client */
    if ((rc = tlssrv_read(tlsServer, rlp_message, 3000, &tlsError)) < 0)
    {
        printf(" failed! couldn't read from the client %d\n\n", rc);
        mbedtls_net_free(&client_fd);
        return rc;
    }
    const unsigned char* rlp_middle =
        reinterpret_cast<const unsigned char*>(rlp_message);
    rlp = std::string(reinterpret_cast<const char*>(rlp_middle));

    return rc;
}

int setup_tls_server(const char* server_port)
{
    int rc = 1;

    std::stringstream ss;
    string s{};
    oe_result_t result = OE_FAILURE;
    mbedtls_net_context listen_fd;

    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        printf(
            "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        mbedtls_net_free(&client_fd);
        return rc;
    }

    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        printf(
            "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        mbedtls_net_free(&client_fd);
        return rc;
    }

    if ((rc = tlssrv_startup(&tlsError)) != 0)
    {
        printf(" failed! tlssrv_startup returned %d\n\n", rc);
        mbedtls_net_free(&client_fd);
        return rc;
    }

    if ((rc = tlssrv_create(
             NULL, server_port, verifier, NULL, &tlsServer, &tlsError)) != 0)
    {
        printf(" failed! tlssrv_create returned %d\n\n", rc);
        mbedtls_net_free(&client_fd);
        return rc;
    }

    printf("\n Server in enclave: Waiting for a trusted connection\n");
    fflush(stdout);
    const size_t NUM_OF_CLIENTS = 1;
    std::string best_q, best_coinbase, best_rlp;
    for (size_t i = 0; i < NUM_OF_CLIENTS; ++i)
    {
        std::string q, coinbase, rlp;

        std::cout << "Processing client number: " << i << std::endl;

        /* Wait for a single connections */
        if ((rc = tlssrv_accept(tlsServer, &client_fd, &tlsError)) != 0)
        {
            printf(" failed! tlssrv_accept returned %d\n\n", rc);
            mbedtls_net_free(&client_fd);
            return rc;
        }

        process_client(q, coinbase, rlp);
        if (coinbase > best_coinbase)
        {
            best_q = q;
            best_coinbase = coinbase;
            best_rlp = rlp;
        }
    }
    std::cout << "Best coinbase: " << best_coinbase << std::endl;
    std::cout << "Best hash: " << best_q << std::endl;
    send_work_to_miner(best_q);
    send_rlp_to_miner(best_rlp);

exit:
    if (tlsServer)
    {
        mbedtls_net_free(&tlsServer->net);
        mbedtls_ssl_free(&tlsServer->ssl);
        mbedtls_ssl_config_free(&tlsServer->conf);
        mbedtls_x509_crt_free(&tlsServer->crt);
        mbedtls_pk_free(&tlsServer->pk);
        mbedtls_ssl_cache_free(&tlsServer->cache);
        free(tlsServer);
    }
    mbedtls_net_free(&client_fd);
    return rc;
}
