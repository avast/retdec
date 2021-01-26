/* Author #Metthal */

#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

/* 
   These are types from "Windows Authenticode Portable Executable Signature Format"
   https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
   Some of them are changed a little bit because the documentation did not reflect the reality
*/

// static const int NID_spc_nested_signature =
// 	OBJ_create("1.3.6.1.4.1.311.2.4.1", "spcNestedSignature", "SPC_NESTED_SIGNATURE (Authenticode)");

// static const int NID_spc_ms_countersignature =
// 	OBJ_create("1.3.6.1.4.1.311.3.3.1", "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE (Authenticode)");

// static const int NID_spc_indirect_data = OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectData", "SPC_INDIRECT_DATA (Authenticode)");

/* All hash and digest encryption algorithms */
enum class Algorithms
{
	MD5 = NID_md5,
	SHA1 = NID_sha1,
	SHA224 = NID_sha224,
	SHA256 = NID_sha256,
	SHA384 = NID_sha384,
	SHA512 = NID_sha512,
	MD5_RSA = NID_md5WithRSAEncryption,
	SHA1_RSA = NID_sha1WithRSAEncryption,
	SHA224_RSA = NID_sha224WithRSAEncryption,
	SHA256_RSA = NID_sha256WithRSAEncryption,
	SHA384_RSA = NID_sha384WithRSAEncryption,
	SHA512_RSA = NID_sha512WithRSAEncryption
};

struct SpcString
{
	int type;
	union {
		ASN1_BMPSTRING* unicode;
		ASN1_IA5STRING* ascii;
	} value;
};

struct SpcSerializedObject
{
	ASN1_OCTET_STRING* classId;
	ASN1_OCTET_STRING* serializedData;
};

struct SpcLink
{
	int type;
	union {
		ASN1_IA5STRING* url;
		SpcSerializedObject* moniker;
		SpcString* file;
	} value;
};

struct SpcAttributeTypeAndOptionalValue
{
	ASN1_OBJECT* type;
	ASN1_TYPE* value;
};

struct SpcPeImageData
{
	ASN1_BIT_STRING* flags;
	SpcLink* file;
};

struct AlgorithmIdentifier
{
	ASN1_OBJECT* algorithm;
	ASN1_TYPE* parameters;
};

struct DigestInfo
{
	AlgorithmIdentifier* digestAlgorithm;
	ASN1_OCTET_STRING* digest;
};

struct SpcIndirectDataContent
{
	SpcAttributeTypeAndOptionalValue* data;
	DigestInfo* messageDigest;
};

struct SpcContentInfo
{
	ASN1_OBJECT* contentType;
	SpcIndirectDataContent* content;
};
struct SpcSpOpusInfo
{
	SpcString* programName;
	SpcLink* moreInfo;
};

struct CtlEntryAttribute
{
	ASN1_OBJECT* identifier;
	STACK_OF(ASN1_TYPE)* values;
};

struct CtlEntry
{
	ASN1_OCTET_STRING* subjectIdentifier;
	STACK_OF(X509_ATTRIBUTE)* attributes;
};

struct CtlUsage
{
	ASN1_OBJECT* identifier;
};

struct CtlInfo
{
	CtlUsage* subjectUsage;
	ASN1_OCTET_STRING* listIdentifier;
	ASN1_INTEGER* sequenceNumber;
	ASN1_TIME* lastUpdate;
	AlgorithmIdentifier* subjectAlgorithm;
	STACK_OF(CtlEntry)* entries;
	STACK_OF(X509_EXTENSION)* extensions;
};

struct CatalogNameValue
{
	ASN1_BMPSTRING* name;
	ASN1_INTEGER* unk;
	ASN1_OCTET_STRING* value;
};

DECLARE_ASN1_FUNCTIONS(SpcString)
DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)
DECLARE_ASN1_FUNCTIONS(SpcLink)
DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)
DECLARE_ASN1_FUNCTIONS(SpcPeImageData)
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)
DECLARE_ASN1_FUNCTIONS(DigestInfo)
DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)
DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)
DECLARE_ASN1_FUNCTIONS(SpcContentInfo)
DECLARE_ASN1_FUNCTIONS(CtlEntryAttribute)
DECLARE_ASN1_FUNCTIONS(CtlEntry)
DECLARE_ASN1_FUNCTIONS(CtlUsage)
DECLARE_ASN1_FUNCTIONS(CtlInfo)
DECLARE_ASN1_FUNCTIONS(CatalogNameValue)

DEFINE_STACK_OF(CtlEntry)
DEFINE_STACK_OF(CtlEntryAttribute)
DEFINE_STACK_OF(ASN1_OCTET_STRING)
