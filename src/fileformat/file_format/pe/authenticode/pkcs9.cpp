#include "pkcs9.h"

namespace authenticode {

void Pkcs9::print() {
	X509Certificate (certificate).print ();
}

Pkcs9::Pkcs9(std::vector<unsigned char> data, STACK_OF(X509) *certificates) {
	const auto *data_ptr = data.data ();
	countersign_info = d2i_PKCS7_SIGNER_INFO (nullptr, &data_ptr, data.size ());
	if (!countersign_info) {
		throw std::exception ();
	}
	/* get the certificate of this counter signatures */
	certificate = X509_find_by_issuer_and_serial (certificates,
		countersign_info->issuer_and_serial->issuer, countersign_info->issuer_and_serial->serial);
	if (!certificate) {
		throw std::runtime_error ("Unable to find PKCS9 countersignature certificate");
	}

	for (int i = 0; i < sk_X509_ATTRIBUTE_num (countersign_info->auth_attr); ++i) {
		auto attribute = sk_X509_ATTRIBUTE_value (countersign_info->auth_attr, i);
		auto attribute_object = X509_ATTRIBUTE_get0_object (attribute);
		std::vector<unsigned char> countersignature;

		if (OBJ_obj2nid (attribute_object) == NID_pkcs9_messageDigest) {
			auto attr_type = X509_ATTRIBUTE_get0_type (attribute, 0);
			countersignature = std::vector<unsigned char> (attr_type->value.octet_string->data,
				attr_type->value.octet_string->data + attr_type->value.octet_string->length);
			break;
		}
	}
}

}