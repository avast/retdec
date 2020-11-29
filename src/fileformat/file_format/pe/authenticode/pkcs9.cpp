/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs9.cpp
 * @brief Class that wraps openssl pkcs9 information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "pkcs9.h"
#include <openssl/x509.h>

namespace authenticode {

/* PKCS7 stores all certificates for the signer and counter signers, we need to pass the certs */
Pkcs9::Pkcs9(std::vector<unsigned char> data, STACK_OF(X509)* certificates)
{
	const unsigned char* data_ptr = data.data();
	countersignInfo = d2i_PKCS7_SIGNER_INFO(nullptr, &data_ptr, data.size());
	if (!countersignInfo)
	{
		throw std::exception();
	}
	/* get the signer certificate of this counter signatures */
	signerCert = X509_find_by_issuer_and_serial(certificates,
		countersignInfo->issuer_and_serial->issuer, countersignInfo->issuer_and_serial->serial);

	if (!signerCert)
	{
		throw std::runtime_error("Unable to find PKCS9 countersignature certificate");
	}

	for (int i = 0; i < sk_X509_ATTRIBUTE_num(countersignInfo->auth_attr); ++i)
	{
		X509_ATTRIBUTE* attribute = sk_X509_ATTRIBUTE_value(countersignInfo->auth_attr, i);
		ASN1_OBJECT* attribute_object = X509_ATTRIBUTE_get0_object(attribute);
		std::vector<unsigned char> countersignature;

		if (OBJ_obj2nid(attribute_object) == NID_pkcs9_messageDigest)
		{
			ASN1_TYPE* attr_type = X509_ATTRIBUTE_get0_type(attribute, 0);
			countersignature = std::vector<unsigned char>(attr_type->value.octet_string->data,
				attr_type->value.octet_string->data + attr_type->value.octet_string->length);
			break;
		}
	}
}

X509* Pkcs9::getX509() const {
	return signerCert;
}

}// namespace authenticode