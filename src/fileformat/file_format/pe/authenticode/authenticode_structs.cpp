/* Author #Metthal */

#include "authenticode_structs.h"

/* 
   These are types from "Windows Authenticode Portable Executable Signature Format"
   https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
   Some of them are changed a little bit because the documentation did not reflect the reality
*/

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcPeImageData) = {
	ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
	ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

ASN1_SEQUENCE(CtlEntryAttribute) = {
	ASN1_SIMPLE(CtlEntryAttribute, identifier, ASN1_OBJECT),
	ASN1_SET_OF(CtlEntryAttribute, values, ASN1_ANY)
} ASN1_SEQUENCE_END(CtlEntryAttribute)

ASN1_SEQUENCE(CtlEntry) = {
	ASN1_SIMPLE(CtlEntry, subjectIdentifier, ASN1_OCTET_STRING),
	ASN1_SET_OF_OPT(CtlEntry, attributes, X509_ATTRIBUTE)
} ASN1_SEQUENCE_END(CtlEntry)

ASN1_SEQUENCE(CtlUsage) = {
	ASN1_SIMPLE(CtlUsage, identifier, ASN1_OBJECT)
} ASN1_SEQUENCE_END(CtlUsage)

ASN1_SEQUENCE(CtlInfo) = {
	ASN1_SIMPLE(CtlInfo, subjectUsage, CtlUsage),
	ASN1_OPT(CtlInfo, listIdentifier, ASN1_OCTET_STRING),
	ASN1_OPT(CtlInfo, sequenceNumber, ASN1_INTEGER),
	ASN1_SIMPLE(CtlInfo, lastUpdate, ASN1_TIME),
	ASN1_SIMPLE(CtlInfo, subjectAlgorithm, AlgorithmIdentifier),
	ASN1_SEQUENCE_OF(CtlInfo, entries, CtlEntry),
	ASN1_EXP_SEQUENCE_OF_OPT(CtlInfo, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(CtlInfo)

ASN1_SEQUENCE(CatalogNameValue) = {
	ASN1_SIMPLE(CatalogNameValue, name, ASN1_BMPSTRING),
	ASN1_SIMPLE(CatalogNameValue, unk, ASN1_INTEGER),
	ASN1_SIMPLE(CatalogNameValue, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CatalogNameValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)
IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)
IMPLEMENT_ASN1_FUNCTIONS(SpcLink)
IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)
IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)
IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)
IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)
IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)
IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)
IMPLEMENT_ASN1_FUNCTIONS(CtlEntryAttribute)
IMPLEMENT_ASN1_FUNCTIONS(CtlEntry)
IMPLEMENT_ASN1_FUNCTIONS(CtlUsage)
IMPLEMENT_ASN1_FUNCTIONS(CtlInfo)
IMPLEMENT_ASN1_FUNCTIONS(CatalogNameValue)
