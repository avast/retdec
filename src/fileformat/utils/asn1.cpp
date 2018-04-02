/**
 * @file src/fileformat/utils/asn1.cpp
 * @brief Implementation of classes for ASN1 parsing and representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/asn1.h"

namespace retdec {
namespace fileformat {

Asn1Item::Asn1Item(Asn1Type type, const std::vector<std::uint8_t>& data) : _type(type), _data(data)
{
	init();
}

std::shared_ptr<Asn1Item> Asn1Item::parse(const std::vector<std::uint8_t>& data)
{
	if (data.empty())
		return nullptr;

	// At least space for tag and length
	auto itr = data.begin();
	if (itr + 1 == data.end())
		return nullptr;

	auto tag = *itr;
	auto length = *(itr + 1);
	std::size_t lengthBytes = 1;

	// MSB set in the length indicates that length has greater value than 0x7F
	// Bits 0-7 store the amount of subsequent bytes the length occupies
	if (length & 0x80)
	{
		lengthBytes += 1 + (length & 0x7F);

		if (lengthBytes > data.size())
			return nullptr;
	}

	// Parse tag and create ASN1 item
	if ((tag & Asn1TagMask_Class) == Asn1Tag_ContextSpecific)
	{
		return std::make_shared<Asn1ContextSpecific>(data);
	}
	else if ((tag & Asn1TagMask_Class) == Asn1Tag_Universal)
	{
		switch (tag & Asn1TagMask_Type)
		{
			case Asn1Tag_BitString:
				return std::make_shared<Asn1BitString>(data);
			case Asn1Tag_OctetString:
				return std::make_shared<Asn1OctetString>(data);
			case Asn1Tag_Null:
				return std::make_shared<Asn1Null>(data);
			case Asn1Tag_Object:
				return std::make_shared<Asn1Object>(data);
			case Asn1Tag_Sequence:
				return std::make_shared<Asn1Sequence>(data);
			default:
				return nullptr;
		}
	}

	return nullptr;
}

bool Asn1Item::isBitString() const
{
	return _type == Asn1Type::BitString;
}

bool Asn1Item::isOctetString() const
{
	return _type == Asn1Type::OctetString;
}

bool Asn1Item::isSequence() const
{
	return _type == Asn1Type::Sequence;
}

bool Asn1Item::isObject() const
{
	return _type == Asn1Type::Object;
}

bool Asn1Item::isContextSpecific() const
{
	return _type == Asn1Type::ContextSpecific;
}

std::size_t Asn1Item::getLength() const
{
	return _data.size();
}

const std::vector<std::uint8_t>& Asn1Item::getData() const
{
	return _data;
}

std::size_t Asn1Item::getContentLength() const
{
	return _contentLength;
}

std::vector<std::uint8_t> Asn1Item::getContentData() const
{
	return std::vector<std::uint8_t>(_contentBegin, _contentBegin + _contentLength);
}

void Asn1Item::init()
{
	if (_data.size() < 2)
	{
		_contentBegin = _data.end();
		return;
	}

	_contentLength = _data[1];
	std::size_t lengthBytes = 0;

	if (_contentLength & 0x80)
	{
		lengthBytes += _contentLength & 0x7F;
		_contentLength = 0;

		// Not enough data
		if (1 + lengthBytes > _data.size())
		{
			_contentBegin = _data.end();
			return;
		}

		for (std::size_t i = 0; i < lengthBytes; ++i)
			_contentLength = (_contentLength << 8) | _data[2 + i];
	}

	_data.resize(2 + lengthBytes + _contentLength);
	_contentBegin = _data.begin() + 2 + lengthBytes;
}

Asn1Null::Asn1Null(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::Null, data)
{
}

Asn1BitString::Asn1BitString(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::BitString, data)
{
	init();
}

std::string Asn1BitString::getString() const
{
	return _string;
}

void Asn1BitString::init()
{
	retdec::utils::bytesToHexString(getContentData(), _string);
}

Asn1OctetString::Asn1OctetString(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::OctetString, data)
{
	init();
}

std::string Asn1OctetString::getString() const
{
	return _string;
}

void Asn1OctetString::init()
{
	retdec::utils::bytesToHexString(getContentData(), _string);
}

Asn1Object::Asn1Object(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::Object, data)
{
	init();
}

std::string Asn1Object::getIdentifier() const
{
	return _identifier;
}

void Asn1Object::init()
{
	auto contentData = getContentData();
	if (contentData.empty())
	{
		_identifier.clear();
		return;
	}

	_identifier.reserve(contentData.size());

	// First number from OID is stored as 40*X + Y where OID is 'X.Y'
	auto first = contentData[0];
	_identifier += retdec::utils::numToStr(first / 40) + '.';
	_identifier += retdec::utils::numToStr(first % 40);
	if (contentData.size() != 1)
		_identifier += '.';

	std::uint64_t subident = 0;
	for (auto itr = contentData.begin() + 1; itr != contentData.end(); ++itr)
	{
		subident = (subident << 7) | (*itr & 0x7F);
		// This subidentificator occupies more than 1 byte
		if (*itr & 0x80)
		{
			continue;
		}

		_identifier += retdec::utils::numToStr(subident);
		if (itr + 1 != contentData.end())
			_identifier += '.';
		subident = 0;
	}
}

Asn1Sequence::Asn1Sequence(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::Sequence, data)
{
	init();
}

std::size_t Asn1Sequence::getNumberOfElements() const
{
	return _elements.size();
}

std::shared_ptr<Asn1Item> Asn1Sequence::getElement(std::size_t index) const
{
	return index < _elements.size() ? _elements[index] : nullptr;
}

void Asn1Sequence::init()
{
	auto contentData = getContentData();
	while (!contentData.empty())
	{
		auto element = Asn1Item::parse(contentData);
		if (element == nullptr)
			return;

		assert(element->getLength() <= contentData.size() && "https://github.com/avast-tl/retdec/issues/256");
		contentData.erase(contentData.begin(), contentData.begin() + element->getLength());
		_elements.push_back(std::move(element));
	}
}

Asn1ContextSpecific::Asn1ContextSpecific(const std::vector<std::uint8_t>& data) : Asn1Item(Asn1Type::ContextSpecific, data)
{
	init();
}

const std::shared_ptr<Asn1Item>& Asn1ContextSpecific::getItem() const
{
	return _item;
}

void Asn1ContextSpecific::init()
{
	_item = Asn1Item::parse(getContentData());
}

} // namespace fileformat
} // namespace retdec
