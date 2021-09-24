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

#ifndef AUTHENTICODE_H
#define AUTHENTICODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "certificate.h"
#include "countersignature.h"

#define MAX_NESTED_COUNT 16

/* Signature is valid */
#define AUTHENTICODE_VFY_VALID            0
/* Parsing error (from OpenSSL functions) */
#define AUTHENTICODE_VFY_CANT_PARSE       1
/* Signers certificate is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_CERT   2
/* No digest saved inside the signature */
#define AUTHENTICODE_VFY_DIGEST_MISSING   3
/* Non verification errors - allocations etc. */
#define AUTHENTICODE_VFY_INTERNAL_ERROR   4
/* SignerInfo part of PKCS7 is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_INFO   5
/* PKCS7 doesn't have type of SignedData, can't proceed */
#define AUTHENTICODE_VFY_WRONG_PKCS7_TYPE 6
/* PKCS7 doesn't have corrent content, can't proceed */
#define AUTHENTICODE_VFY_BAD_CONTENT      7
/* Contained and calculated digest don't match */
#define AUTHENTICODE_VFY_INVALID          8

typedef struct {
    ByteArray digest;
    char* digest_alg; /* name of the digest algorithm */
    char* program_name;
    CertificateArray* chain;
} Signer;

typedef struct {
    int verify_flags;
    int version;
    char* digest_alg; /* name of the digest algorithm */
    ByteArray digest;
    Signer* signer;
    CertificateArray* certs;
    CountersignatureArray* countersigs;
} Authenticode;

typedef struct {
    Authenticode** signatures;
    size_t count;
} AuthenticodeArray;

AuthenticodeArray* authenticode_new(const uint8_t* data, long len);
void authenticode_array_free(AuthenticodeArray* auth);

#ifdef __cplusplus
}
#endif

#endif
