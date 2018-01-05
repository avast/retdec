/**
 * @file include/retdec/fileformat/utils/asn1.h
 * @brief Declaration of classes for ASN1 parsing and representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_ASN1_H
#define RETDEC_FILEFORMAT_UTILS_ASN1_H

#include <cstdint>
#include <memory>
#include <vector>

namespace retdec {
namespace fileformat {

const std::uint8_t Asn1TagMask_Class       = 0xC0;
const std::uint8_t Asn1TagMask_Primitive   = 0x20;
const std::uint8_t Asn1TagMask_Type        = 0x1F;

const std::uint8_t Asn1Tag_Universal       = 0x00;
const std::uint8_t Asn1Tag_Application     = 0x40;
const std::uint8_t Asn1Tag_ContextSpecific = 0x80;
const std::uint8_t Asn1Tag_Private         = 0xC0;

const std::uint8_t Asn1Tag_Constructed     = 0x20;

const std::uint8_t Asn1Tag_BitString       = 0x03;
const std::uint8_t Asn1Tag_OctetString     = 0x04;
const std::uint8_t Asn1Tag_Null            = 0x05;
const std::uint8_t Asn1Tag_Object          = 0x06;
const std::uint8_t Asn1Tag_Sequence        = 0x10;

const std::string DigestAlgorithmOID_Sha1   = "1.3.14.3.2.26";
const std::string DigestAlgorithmOID_Sha256 = "2.16.840.1.101.3.4.2.1";
const std::string DigestAlgorithmOID_Md5    = "1.2.840.113549.2.5";

enum class Asn1Type
{
	Null,
	BitString,
	OctetString,
	Sequence,
	Object,
	ContextSpecific
};

class Asn1Item
{
public:
	virtual ~Asn1Item() = default;

	static std::shared_ptr<Asn1Item> parse(const std::vector<std::uint8_t>& data);

	std::size_t getLength() const;
	const std::vector<std::uint8_t>& getData() const;

	std::size_t getContentLength() const;
	std::vector<std::uint8_t> getContentData() const;

	bool isNull() const;
	bool isBitString() const;
	bool isOctetString() const;
	bool isSequence() const;
	bool isObject() const;
	bool isContextSpecific() const;

protected:
	Asn1Item(Asn1Type type, const std::vector<std::uint8_t>& data);

	Asn1Type _type;
	std::vector<std::uint8_t> _data;

private:
	void init();

	std::vector<std::uint8_t>::const_iterator _contentBegin;
	std::size_t _contentLength;
};

class Asn1Null : public Asn1Item
{
public:
	Asn1Null(const std::vector<std::uint8_t>& data);
};

class Asn1BitString : public Asn1Item
{
public:
	Asn1BitString(const std::vector<std::uint8_t>& data);

	std::string getString() const;

private:
	void init();

	std::string _string;
};

class Asn1OctetString : public Asn1Item
{
public:
	Asn1OctetString(const std::vector<std::uint8_t>& data);

	std::string getString() const;

private:
	void init();

	std::string _string;
};

class Asn1Object : public Asn1Item
{
public:
	Asn1Object(const std::vector<std::uint8_t>& data);

	std::string getIdentifier() const;

private:
	void init();

	std::string _identifier;
};

class Asn1Sequence : public Asn1Item
{
public:
	Asn1Sequence(const std::vector<std::uint8_t>& data);

	std::size_t getNumberOfElements() const;
	std::shared_ptr<Asn1Item> getElement(std::size_t index) const;

private:
	void init();

	std::vector<std::shared_ptr<Asn1Item>> _elements;
};

class Asn1ContextSpecific : public Asn1Item
{
public:
	Asn1ContextSpecific(const std::vector<std::uint8_t>& data);

	const std::shared_ptr<Asn1Item>& getItem() const;

private:
	void init();

	std::shared_ptr<Asn1Item> _item;
};

} // namespace fileformat
} // namespace retdec

#endif
