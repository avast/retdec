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

#ifndef COUNTERSIGNATURE_H
#define COUNTERSIGNATURE_H

#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "certificate.h"
#include "helper.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Countersignature is valid */
#define COUNTERSIGNATURE_VFY_VALID                  0
/* Parsing error (from OpenSSL functions) */
#define COUNTERSIGNATURE_VFY_CANT_PARSE             1
/* Signers certificate is missing */
#define COUNTERSIGNATURE_VFY_NO_SIGNER_CERT         2
/* Unknown algorithm, can't proceed with verification */
#define COUNTERSIGNATURE_VFY_UNKNOWN_ALGORITHM      3
/* Verification failed, digest mismatch */
#define COUNTERSIGNATURE_VFY_INVALID                4
/* Failed to decrypt countersignature enc_digest for verification */
#define COUNTERSIGNATURE_VFY_CANT_DECRYPT_DIGEST    5
/* No digest saved inside the countersignature */
#define COUNTERSIGNATURE_VFY_DIGEST_MISSING         6
/* Message digest inside countersignature doesn't match signature it countersigns */
#define COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE 7
/* Non verification errors - allocations etc. */
#define COUNTERSIGNATURE_VFY_INTERNAL_ERROR         8
/* Time is missing in the timestamp signature */
#define COUNTERSIGNATURE_VFY_TIME_MISSING           9

typedef struct {
    int verify_flags;
    char* sign_time;
    char* digest_alg;
    ByteArray digest;
    CertificateArray* chain;
} Countersignature;

typedef struct {
    Countersignature** counters;
    size_t count;
} CountersignatureArray;

Countersignature* pkcs9_countersig_new(
    const uint8_t* data, long size, STACK_OF(X509) * certs, ASN1_STRING* enc_digest);
Countersignature* ms_countersig_new(const uint8_t* data, long size, ASN1_STRING* enc_digest);

int countersignature_array_insert(CountersignatureArray* arr, Countersignature* sig);
int countersignature_array_move(CountersignatureArray* src, CountersignatureArray* dst);
void countersignature_free(Countersignature* sig);
void countersignature_array_free(CountersignatureArray* arr);

#ifdef __cplusplus
}
#endif

#endif
