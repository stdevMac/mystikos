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
#include <iomanip>
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <sstream>
#include "tlssrv.h"
#include "tlssrv_t.h"

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

        snprintf(err->buf, sizeof(err->buf), "%s: %s", buf1, buf2);
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
???LINES MISSING
???LINES MISSING
???LINES MISSING
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

int setup_tls_server(const char* server_port)
{
    int rc = 1;

    char* p;
    unsigned char* t = new unsigned char[1500];
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

    /* Wait for a single connections */
    if ((rc = tlssrv_accept(tlsServer, &client_fd, &tlsError)) != 0)
    {
        printf(" failed! tlssrv_accept returned %d\n\n", rc);
    mbedtls_net_free(&client_fd);
    return rc;
    }

    printf(" Remote connection established. Ready for service.\n");

    /* Read from the client */
    if ((rc = tlssrv_read(tlsServer, t, 1000, &tlsError)) < 0)
    {
        printf(" failed! couldn't read from the client %d\n\n", rc);
    mbedtls_net_free(&client_fd);
    return rc;
    }
    printf("hashedChars: ");
    for (int i = 0; i < 100; i++)
    {
        printf("%x", t[i]);
    }
    printf("\n");
    for (int i = 0; i < 128; i++)
        {
            ss << std::hex << std::setfill('0');
            ss << std::setw(2)  << static_cast<unsigned>(t[i]);
        }
    s = ss.str();
const unsigned char* o = reinterpret_cast<const unsigned char *>(t);
   std::cout << "hi " << std::string(reinterpret_cast<const char*>(o)) << "\n"; 
//s = string(reinterpret_cast<char*>(t), rc);
    printf("Response: %s\nRC: %d\n", s, rc);

    printf("Received some information from the client.\n");

    // Allow time out
    mbedtls_ssl_set_bio(
        &tlsServer->ssl,
        &client_fd,
        mbedtls_net_send,
        mbedtls_net_recv,
        mbedtls_net_recv_timeout);

    rc = 0;
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
