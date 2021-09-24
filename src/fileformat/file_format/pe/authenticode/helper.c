/* Copyright (c) 2021 Avast Software

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "helper.h"

#include <openssl/bio.h>
#include <openssl/x509_vfy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Creates copy of data into the array */
int byte_array_init(ByteArray* arr, const uint8_t* data, int len)
{
    arr->data = (uint8_t*)malloc(len);
    if (!arr->data)
        return -1;

    arr->len = len;
    memcpy(arr->data, data, len);
    return 0;
}

/* Converts ASN1_TIME to MMM DD HH:MM:SS YYYY [GMT] string format */
char* parse_time(const ASN1_TIME* time)
{
    if (!time || ASN1_TIME_check(time) == 0)
        return NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
        return NULL;

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free_all(bio);
        return NULL;
    }

    int size = BIO_number_written(bio);

    char* res = (char*)malloc(size + 1);
    if (res) {
        BIO_read(bio, res, size);
        res[size] = '\0';
    }

    BIO_free_all(bio);
    return res;
}

/* Calculates digest md of data, return bytes written to digest or 0 on error
 * Maximum of EVP_MAX_MD_SIZE will be written to digest */
int calculate_digest(const EVP_MD* md, const uint8_t* data, size_t len, uint8_t* digest)
{
    unsigned int outLen = 0;

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
        goto end;

    if (!EVP_DigestInit_ex(mdCtx, md, NULL) || !EVP_DigestUpdate(mdCtx, data, len) ||
        !EVP_DigestFinal_ex(mdCtx, digest, &outLen))
        goto end;

end:
    EVP_MD_CTX_free(mdCtx);
    return (int)outLen;
}
