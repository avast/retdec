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

#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "helper.h"
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ByteArray country;
    ByteArray organization;
    ByteArray organizationalUnit;
    ByteArray nameQualifier;
    ByteArray state;
    ByteArray commonName;
    ByteArray serialNumber;
    ByteArray locality;
    ByteArray title;
    ByteArray surname;
    ByteArray givenName;
    ByteArray initials;
    ByteArray pseudonym;
    ByteArray generationQualifier;
    ByteArray emailAddress;
} Attributes;

typedef struct {
    long version;
    char* issuer;
    char* subject;
    char* serial;
    ByteArray sha1;
    ByteArray sha256;
    char* key_alg;
    char* sig_alg;
    char* not_before;
    char* not_after;
    char* key;
    Attributes issuer_attrs;
    Attributes subject_attrs;
} Certificate;

typedef struct {
    Certificate** certs;
    size_t count;
} CertificateArray;

Certificate* certificate_new(X509* x509);
void certificate_free(Certificate* cert);

CertificateArray* parse_signer_chain(X509* signer_cert, STACK_OF(X509) * certs);
int certificate_array_move(CertificateArray* dst, CertificateArray* src);
CertificateArray* certificate_array_new(int certCount);
void certificate_array_free(CertificateArray* arr);

#ifdef __cplusplus
}
#endif

#endif
