// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "tee.h"
#include "tlscli.h"

#define TLS_CERT_PATH "./cert.der"
#define TLS_PKEY_PATH "./private_key.pem"
#define SERVER_PORT "17500"

static tlscli_err_t tlsError;

static tlscli_t* trustedChannel;

static int load_file(const char* path, void** buf, size_t* n)
{
    FILE* f;
    long size;

    if ((f = fopen(path, "rb")) == NULL)
        return (-1);

    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1)
    {
        fclose(f);
        return (-1);
    }
    fseek(f, 0, SEEK_SET);

    *n = (size_t)size;

    if ((*buf = calloc(1, *n)) == NULL)
    {
        fclose(f);
        return (-1);
    }

    if (fread(*buf, 1, *n, f) != *n)
    {
        fclose(f);
        free(*buf);
        *buf = NULL;
        return (-1);
    }

    fclose(f);

    return (0);
}

static int trusted_channel_init(const char* serverIP)
{
    int rc = 1;
    void* cert = NULL;
    size_t cert_size = 0;
    void* pkey = NULL;
    size_t pkey_size = 0;
    bool enclave_mode = false;

    if ((rc = tlscli_startup(&tlsError)) != 0)
    {
        printf("client Agent failed! tlscli_startup\n");
        goto done;
    }

    char* target = getenv("MYST_TARGET");
    if (target && strcmp(target, "sgx") == 0)
    {
        enclave_mode = true;
        // The existence of the manifesto file indicates we are running in
        // an enclave. Ask the kernel for help.
        int ret =
            syscall(SYS_myst_gen_creds, &cert, &cert_size, &pkey, &pkey_size);
        if (ret != 0)
        {
            fprintf(stderr, "Error: failed to generate TLS credentials\n");
            goto done;
        }
    }
    else
    {
        // Load cert/pkey from files in non-enclave mode.
        if (load_file(TLS_CERT_PATH, &cert, &cert_size))
        {
            fprintf(
                stderr, "Error: failed to load cert file %s\n", TLS_CERT_PATH);
            goto done;
        }
        if (load_file(TLS_PKEY_PATH, &pkey, &pkey_size))
        {
            fprintf(
                stderr,
                "Error: failed to load private key file %s\n",
                TLS_PKEY_PATH);
            goto done;
        }
    }

    if ((rc = tlscli_connect(
             true,
             serverIP,
             SERVER_PORT,
             cert,
             cert_size,
             pkey,
             pkey_size,
             &trustedChannel,
             &tlsError)) != 0)
    {
        printf("tlscli_connect failed!\n");
        goto done;
    }

    rc = 0;
done:

    if (cert || pkey)
    {
        if (enclave_mode)
            syscall(
                SYS_myst_free_creds, cert, cert_size, pkey, pkey_size, NULL, 0);
        else
        {
            free(cert);
            free(pkey);
        }
    }

    if (rc != 0)
    {
        tlscli_destroy(trustedChannel, &tlsError);
        tlscli_shutdown(&tlsError);
    }

    return rc;
}

int main(int argc, char** argv)
{
    int result = 0;
    char* serverIP = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s serverIP\n", argv[0]);
        return 1;
    }
    serverIP = argv[1];

    trusted_channel_init(serverIP);
    if (trustedChannel == NULL)
    {
        fprintf(stderr, "server: failed to establish channel\n");
        goto done;
    }
    // Sending block header
    unsigned char ip[] =
        "805fee1677236beca1643dd37b4c03a2fa75188d6bc65b26ae8321ceb1b0f5ff";
    tlscli_write(trustedChannel, &ip, sizeof(ip), &tlsError);
    // Sending Coinbase
    unsigned char coinbase[] = "400000000000000000";
    srand(time(NULL));
    coinbase[0] = rand() % 9 + '1';
    tlscli_write(trustedChannel, &coinbase, sizeof(coinbase), &tlsError);

    // Getting PoW for Header
    unsigned char pow_message[300];
    /* Read from the client */
    if ((rc = tlscli_read(trustedChannel, pow_message, 100, &tlsError)) < 0)
    {
        printf(" failed! couldn't read from the client %d\n\n", rc);
        tlscli_destroy(trustedChannel, &tlsError);
        tlscli_shutdown(&tlsError);
        return result;
    }
    const unsigned char* pow_middle =
        reinterpret_cast<const unsigned char*>(pow_message);
    auto pow = std::string(reinterpret_cast<const char*>(pow_middle));
    std::cout << "Pow response" << pow << "\n";

    // Sending block rlp
    unsigned char rlp[] =
        "f9028bf90215a0f0c9cd8872832cf48c27c57a7920d26640c2c1b4234ce14f18ccb2ad"
        "2e96376fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4"
        "9347941dcb8d1f0fcc8cbc8c2d76528e877f915e299fbea0c040dd006d1fc49806f17d"
        "280549d3791d90e29c84d7ba32bc5a51c351a125ffa0f4e9592aba4dc5891a3c875c8b"
        "4da47fcc73e4166218d90fd9fc4459a3d2ce60a07fe394c2d0a4e5b8f961c4c569b5fe"
        "93b1eb37e662220b64e0868f305482330fb90100000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000008606157a"
        "98888983035a51832fefd88252088455f332d596d583010103844765746885676f312e"
        "35856c696e7578a0c80a206814881ca8dd651f28c87548dce58a11f73494c76db0e8ef"
        "9b5f56fc208849d7ea07e14e613af870f86e8201ef850ba43b7400825208945da8f7f0"
        "c6a4561d2d8ae1491a0d3d8efc837957881b8528be98dba400801ca059ba32680e2f74"
        "2337bfcae2cb534928c455584b62770c812e39e5c79f6e0b3ea0252748ecd088f0272a"
        "d5a4c78e543186b60b7ffcc9b64c4121802ccd109b9428c0";
    tlscli_write(trustedChannel, &rlp, sizeof(rlp), &tlsError);

done:
    tlscli_destroy(trustedChannel, &tlsError);
    tlscli_shutdown(&tlsError);
    return result;
}
