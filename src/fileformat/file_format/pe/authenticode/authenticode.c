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

#include "authenticode.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "certificate.h"
#include "countersignature.h"
#include "helper.h"
#include "structs.h"

/* Moves signatures from src to dst, returns 0 on success,
 * else 1. If error occurs, arguments are unchanged */
static int authenticode_array_move(AuthenticodeArray* dst, AuthenticodeArray* src)
{
    size_t newCount = dst->count + src->count;

    Authenticode** tmp = (Authenticode**)realloc(dst->signatures, newCount * sizeof(Authenticode*));
    if (!tmp)
        return 1;

    dst->signatures = tmp;

    for (size_t i = 0; i < src->count; ++i)
        dst->signatures[i + dst->count] = src->signatures[i];

    dst->count = newCount;

    free(src->signatures);
    src->signatures = NULL;
    src->count = 0;

    return 0;
}

static SpcIndirectDataContent* get_content(PKCS7* content)
{
    if (!content)
        return NULL;

    if (OBJ_obj2nid(content->type) != OBJ_txt2nid(NID_spc_indirect_data))
        return NULL;

    SpcIndirectDataContent* spcContent = SpcIndirectDataContent_new();
    if (!spcContent)
        return NULL;

    int len = content->d.other->value.sequence->length;
    const uint8_t* data = content->d.other->value.sequence->data;

    d2i_SpcIndirectDataContent(&spcContent, &data, len);

    return spcContent;
}

static char* parse_program_name(ASN1_TYPE* spcAttr)
{
    const uint8_t* spcData = spcAttr->value.sequence->data;
    int spcLen = spcAttr->value.sequence->length;
    SpcSpOpusInfo* spcInfo = d2i_SpcSpOpusInfo(NULL, &spcData, spcLen);
    if (!spcInfo)
        return NULL;

    char* result = NULL;

    if (spcInfo->programName) {
        uint8_t* data = NULL;
        /* Should be Windows UTF16..., try to convert it to UTF8 */
        int nameLen = ASN1_STRING_to_UTF8(&data, spcInfo->programName->value.unicode);
        if (nameLen >= 0 && nameLen < spcLen) {
            result = (char*)malloc(nameLen + 1);
            if (result) {
                memcpy(result, data, nameLen);
                result[nameLen] = 0;
            }
            OPENSSL_free(data);
        }
    }

    SpcSpOpusInfo_free(spcInfo);
    return result;
}

/* Parses X509* certs into internal representation and inserts into CertificateArray
 * Array is assumed to have enough space to hold all certificates storted in the STACK */
static void parse_certificates(const STACK_OF(X509) * certs, CertificateArray* result)
{
    int certCount = sk_X509_num(certs);
    int i = 0;
    for (; i < certCount; ++i) {
        Certificate* cert = certificate_new(sk_X509_value(certs, i));
        if (!cert)
            break;

        /* Write to the result */
        result->certs[i] = cert;
    }
    result->count = i;
}

static void parse_nested_authenticode(PKCS7_SIGNER_INFO* si, AuthenticodeArray* result)
{
    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);
    int idx = X509at_get_attr_by_NID(attrs, OBJ_txt2nid(NID_spc_nested_signature), -1);
    X509_ATTRIBUTE* attr = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    /* Limit the maximum amount of nested attributes to be safe from malformed samples */
    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i) {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == NULL)
            break;
        int len = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;
        AuthenticodeArray* auth = authenticode_new(data, len);
        if (!auth)
            continue;

        authenticode_array_move(result, auth);
        authenticode_array_free(auth);
    }
}

static void parse_pkcs9_countersig(PKCS7* p7, Authenticode* auth)
{
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);

    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);

    int idx = X509at_get_attr_by_NID(attrs, NID_pkcs9_countersignature, -1);
    X509_ATTRIBUTE* attr = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    /* Limit the maximum amount of nested attributes to be safe from malformed samples */
    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i) {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == NULL)
            break;
        int len = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;

        Countersignature* sig = pkcs9_countersig_new(data, len, p7->d.sign->cert, si->enc_digest);
        if (!sig)
            continue;

        countersignature_array_insert(auth->countersigs, sig);
    }
}

/* Extracts X509 certificates from MS countersignature and stores them into result */
static void extract_ms_counter_certs(const uint8_t* data, int len, CertificateArray* result)
{
    PKCS7* p7 = d2i_PKCS7(NULL, &data, len);
    if (!p7)
        return;

    STACK_OF(X509)* certs = p7->d.sign->cert;
    CertificateArray* certArr = certificate_array_new(sk_X509_num(certs));
    if (!certArr) {
        PKCS7_free(p7);
        return;
    }
    parse_certificates(certs, certArr);
    certificate_array_move(result, certArr);
    certificate_array_free(certArr);

    PKCS7_free(p7);
}

static void parse_ms_countersig(PKCS7* p7, Authenticode* auth)
{
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);

    STACK_OF(X509_ATTRIBUTE)* attrs = PKCS7_get_attributes(si);

    int idx = X509at_get_attr_by_NID(attrs, OBJ_txt2nid(NID_spc_ms_countersignature), -1);
    X509_ATTRIBUTE* attr = X509at_get_attr(attrs, idx);

    int attrCount = X509_ATTRIBUTE_count(attr);
    if (!attrCount)
        return;

    /* Limit the maximum amount of nested attributes to be safe from malformed samples */
    attrCount = attrCount > MAX_NESTED_COUNT ? MAX_NESTED_COUNT : attrCount;

    for (int i = 0; i < attrCount; ++i) {
        ASN1_TYPE* nested = X509_ATTRIBUTE_get0_type(attr, i);
        if (nested == NULL)
            break;
        int len = nested->value.sequence->length;
        const uint8_t* data = nested->value.sequence->data;

        Countersignature* sig = ms_countersig_new(data, len, si->enc_digest);
        if (!sig)
            return;

        /* Because MS TimeStamp countersignature has it's own SET of certificates
         * extract it back into parent signature for consistency with PKCS9 */
        countersignature_array_insert(auth->countersigs, sig);
        extract_ms_counter_certs(data, len, auth->certs);
    }
}

static bool authenticode_verify(PKCS7* p7, PKCS7_SIGNER_INFO* si, X509* signCert)
{
    const uint8_t* contentData = p7->d.sign->contents->d.other->value.sequence->data;
    long contentLen = p7->d.sign->contents->d.other->value.sequence->length;

    uint64_t version = 0;
    ASN1_INTEGER_get_uint64(&version, p7->d.sign->version);
    if (version == 1) {
        /* Move the pointer to the actual contents - skip OID and length */
        int pclass = 0, ptag = 0;
        ASN1_get_object(&contentData, &contentLen, &ptag, &pclass, contentLen);
    }

    BIO* contentBio = BIO_new_mem_buf(contentData, contentLen);
    /* Create `digest` type BIO to calculate content digest for verification */
    BIO* p7bio = PKCS7_dataInit(p7, contentBio);

    char buf[4096];
    /* We now have to 'read' from p7bio to calculate content digest */
    while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
        continue;

    /* Pass it to the PKCS7_signatureVerify, to do the hard work for us */
    bool isValid = PKCS7_signatureVerify(p7bio, p7, si, signCert) == 1;

    BIO_free_all(p7bio);

    return isValid;
}

/* Creates all the Authenticode objects so we can parse them with OpenSSL */
static void initialize_openssl()
{
    OBJ_create("1.3.6.1.4.1.311.2.1.12", "spcSpOpusInfo", "SPC_SP_OPUS_INFO_OBJID");
    OBJ_create("1.3.6.1.4.1.311.3.3.1", "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE");
    OBJ_create("1.3.6.1.4.1.311.2.4.1", "spcNestedSignature", "SPC_NESTED_SIGNATUREs");
    OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectData", "SPC_INDIRECT_DATA");
}

/* Return array of Authenticode signatures stored in the data, there can be multiple
 * of signatures as Authenticode signatures are often nested through unauth attributes */
AuthenticodeArray* authenticode_new(const uint8_t* data, long len)
{
    /* We need to initialize all the custom objects for further parsing */
    initialize_openssl();

    AuthenticodeArray* result = (AuthenticodeArray*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    result->signatures = (Authenticode**)malloc(sizeof(Authenticode*));
    if (!result->signatures) {
        free(result);
        return NULL;
    }

    Authenticode* auth = (Authenticode*)calloc(1, sizeof(*auth));
    if (!auth) {
        free(result);
        free(result->signatures);
        return NULL;
    }

    result->count = 1;
    result->signatures[0] = auth;

    /* Let openssl parse the PKCS7 structure */
    PKCS7* p7 = d2i_PKCS7(NULL, &data, len);
    if (!p7) {
        auth->verify_flags = AUTHENTICODE_VFY_CANT_PARSE;
        goto end;
    }

    /* We expect SignedData type of PKCS7 */
    if (!PKCS7_type_is_signed(p7)) {
        auth->verify_flags = AUTHENTICODE_VFY_WRONG_PKCS7_TYPE;
        goto end;
    }

    PKCS7_SIGNED* p7data = p7->d.sign;

    uint64_t version = 0;
    if (ASN1_INTEGER_get_uint64(&version, p7data->version))
        auth->version = version;

    STACK_OF(X509)* certs = p7data->cert;

    auth->certs = certificate_array_new(sk_X509_num(certs));
    if (!auth->certs) {
        auth->verify_flags = AUTHENTICODE_VFY_INTERNAL_ERROR;
        goto end;
    }
    parse_certificates(certs, auth->certs);

    /* Get Signature content that contains the message digest and it's algorithm */
    SpcIndirectDataContent* dataContent = get_content(p7data->contents);
    if (!dataContent) {
        auth->verify_flags = AUTHENTICODE_VFY_BAD_CONTENT;
        goto end;
    }

    DigestInfo* messageDigest = dataContent->messageDigest;

    int digestnid = OBJ_obj2nid(messageDigest->digestAlgorithm->algorithm);
    auth->digest_alg = strdup(OBJ_nid2ln(digestnid));

    int digestLen = messageDigest->digest->length;
    const uint8_t* digestData = messageDigest->digest->data;
    byte_array_init(&auth->digest, digestData, digestLen);

    SpcIndirectDataContent_free(dataContent);

    Signer* signer = (Signer*)calloc(1, sizeof(Signer));
    if (!signer) {
        auth->verify_flags = AUTHENTICODE_VFY_INTERNAL_ERROR;
        goto end;
    }
    auth->signer = signer;

    /* Authenticode is supposed to have only one SignerInfo value
     * that contains all information for actual signing purposes
     * and nested signatures or countersignatures */
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);
    if (!si) {
        auth->verify_flags = AUTHENTICODE_VFY_NO_SIGNER_INFO;
        goto end;
    }

    auth->countersigs = (CountersignatureArray*)calloc(1, sizeof(CountersignatureArray));
    if (!auth->countersigs) {
        auth->verify_flags = AUTHENTICODE_VFY_INTERNAL_ERROR;
        goto end;
    }
    /* Authenticode can contain SET of nested Authenticode signatures
     * and countersignatures in unauthenticated attributes */
    parse_nested_authenticode(si, result);
    parse_pkcs9_countersig(p7, auth);
    parse_ms_countersig(p7, auth);

    /* Get the signing certificate for the first SignerInfo */
    STACK_OF(X509)* signCertStack = PKCS7_get0_signers(p7, certs, 0);

    X509* signCert = sk_X509_value(signCertStack, 0);
    if (!signCert) {
        auth->verify_flags = AUTHENTICODE_VFY_NO_SIGNER_CERT;
        sk_X509_free(signCertStack);
        goto end;
    }

    sk_X509_free(signCertStack);

    signer->chain = parse_signer_chain(signCert, certs);

    /* Get the Signers digest of Authenticode content */
    ASN1_TYPE* digest = PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
    if (!digest) {
        auth->verify_flags = AUTHENTICODE_VFY_DIGEST_MISSING;
        goto end;
    }

    digestnid = OBJ_obj2nid(si->digest_alg->algorithm);
    signer->digest_alg = strdup(OBJ_nid2ln(digestnid));

    digestLen = digest->value.asn1_string->length;
    digestData = digest->value.asn1_string->data;
    byte_array_init(&signer->digest, digestData, digestLen);

    /* Authenticode stores optional programName in non-optional SpcSpOpusInfo attribute */
    ASN1_TYPE* spcInfo = PKCS7_get_signed_attribute(si, OBJ_txt2nid(NID_spc_info));
    if (spcInfo)
        signer->program_name = parse_program_name(spcInfo);

    /* If we got to this point, we got all we need to start verifying */
    bool isValid = authenticode_verify(p7, si, signCert);
    if (!isValid)
        auth->verify_flags = AUTHENTICODE_VFY_INVALID;

end:
    PKCS7_free(p7);
    return result;
}

static void signer_free(Signer* si)
{
    if (si) {
        free(si->digest.data);
        free(si->digest_alg);
        free(si->program_name);
        certificate_array_free(si->chain);
        free(si);
    }
}

static void authenticode_free(Authenticode* auth)
{
    if (auth) {
        free(auth->digest.data);
        free(auth->digest_alg);
        signer_free(auth->signer);
        certificate_array_free(auth->certs);
        countersignature_array_free(auth->countersigs);
        free(auth);
    }
}

void authenticode_array_free(AuthenticodeArray* arr)
{
    if (arr) {
        for (size_t i = 0; i < arr->count; ++i) {
            authenticode_free(arr->signatures[i]);
        }
        free(arr->signatures);
        free(arr);
    }
}
