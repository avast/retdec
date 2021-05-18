/**
 * @file src/fileformat/file_format/pe/authenticode/authenticode_structs.h
 * @brief Declares custom OpenSSL objects and functions
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 * @author Marek Milkovič - metthal
 */

#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509v3.h>

/* 
   These are types from "Windows Authenticode Portable Executable Signature Format"
   https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
   Some of them are changed a little bit because the documentation did not reflect the reality
*/
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
