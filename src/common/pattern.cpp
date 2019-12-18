/**
 * @file src/common/pattern.cpp
 * @brief Common pattern representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/pattern.h"
#include "retdec/common/address.h"

namespace retdec {
namespace common {

//
//=============================================================================
// Pattern::Match
//=============================================================================
//

Pattern::Match::Match()
{

}

Pattern::Match::Match(
		const retdec::common::Address& offset,
		const retdec::common::Address& address,
		std::optional<unsigned> size,
		std::optional<unsigned> entrySize,
		eType type)
	:
		_offset(offset),
		_address(address),
		_size(size),
		_entrySize(entrySize),
		_type(type)
{

}

Pattern::Match Pattern::Match::unknown(
		const retdec::common::Address& offset,
		const retdec::common::Address& address,
		std::optional<unsigned> size,
		std::optional<unsigned> entrySize)
{
	return Match(offset, address, size, entrySize, eType::UNKNOWN);
}

Pattern::Match Pattern::Match::integral(
		const retdec::common::Address& offset,
		const retdec::common::Address& address,
		std::optional<unsigned> size,
		std::optional<unsigned> entrySize)
{
	return Match(offset, address, size, entrySize, eType::INTEGRAL);
}

Pattern::Match Pattern::Match::floatingPoint(
		const retdec::common::Address& offset,
		const retdec::common::Address& address,
		std::optional<unsigned> size,
		std::optional<unsigned> entrySize)
{
	return Match(offset, address, size, entrySize, eType::FLOATING_POINT);
}

bool Pattern::Match::isOffsetDefined() const
{
	return _offset.isDefined();
}

bool Pattern::Match::isAddressDefined() const
{
	return _address.isDefined();
}

bool Pattern::Match::isSizeDefined() const
{
	return _size.has_value();
}

bool Pattern::Match::isEntrySizeDefined() const
{
	return _entrySize.has_value();
}

bool Pattern::Match::isTypeUnknown() const
{
	return _type == eType::UNKNOWN;
}

bool Pattern::Match::isTypeIntegral() const
{
	return _type == eType::INTEGRAL;
}

bool Pattern::Match::isTypeFloatingPoint() const
{
	return _type == eType::FLOATING_POINT;
}

void Pattern::Match::setOffset(const retdec::common::Address& offset)
{
	_offset = offset;
}

void Pattern::Match::setAddress(const retdec::common::Address& address)
{
	_address = address;
}

void Pattern::Match::setSize(const unsigned size)
{
	_size = size;
}

void Pattern::Match::setEntrySize(const unsigned entrySize)
{
	_entrySize = entrySize;
}

void Pattern::Match::setIsTypeUnknown()
{
	_type = eType::UNKNOWN;
}

void Pattern::Match::setIsTypeIntegral()
{
	_type = eType::INTEGRAL;
}

void Pattern::Match::setIsTypeFloatingPoint()
{
	_type = eType::FLOATING_POINT;
}

retdec::common::Address Pattern::Match::getOffset() const
{
	return _offset;
}

retdec::common::Address Pattern::Match::getAddress() const
{
	return _address;
}

std::optional<unsigned> Pattern::Match::getSize() const
{
	return _size;
}

std::optional<unsigned> Pattern::Match::getEntrySize() const
{
	return _entrySize;
}

/**
 * @return This instance is equal with the provided one if all the members
 * are equal.
 */
bool Pattern::Match::operator==(const Match& val) const
{
	return getOffset() == val.getOffset()
			&& getAddress() == val.getAddress()
			&& getSize() == val.getSize()
			&& getEntrySize() == val.getEntrySize()
			&& _type == val._type;
}

bool Pattern::Match::operator!=(const Match& val) const
{
	return !(*this == val);
}

//
//=============================================================================
// Pattern
//=============================================================================
//

Pattern::Pattern()
{

}

Pattern::Pattern(
		const std::string& name,
		const std::string& description,
		const std::string& yaraRuleName,
		eType type,
		eEndian endian)
	:
		_name(name),
		_description(description),
		_yaraRuleName(yaraRuleName),
		_type(type),
		_endian(endian)
{

}

Pattern Pattern::other(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::OTHER, eEndian::UNKNOWN);
}

Pattern Pattern::otherLittle(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::OTHER, eEndian::LITTLE);
}

Pattern Pattern::otherBig(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::OTHER, eEndian::BIG);
}

Pattern Pattern::crypto(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::CRYPTO, eEndian::UNKNOWN);
}

Pattern Pattern::cryptoLittle(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::CRYPTO, eEndian::LITTLE);
}

Pattern Pattern::cryptoBig(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::CRYPTO, eEndian::BIG);
}

Pattern Pattern::malware(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::MALWARE, eEndian::UNKNOWN);
}

Pattern Pattern::malwareLittle(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::MALWARE, eEndian::LITTLE);
}

Pattern Pattern::malwareBig(const std::string& name, const std::string& description, const std::string& yaraRuleName)
{
	return Pattern(name, description, yaraRuleName, eType::MALWARE, eEndian::BIG);
}

bool Pattern::isTypeOther() const
{
	return _type == eType::OTHER;
}

bool Pattern::isTypeCrypto() const
{
	return _type == eType::CRYPTO;
}

bool Pattern::isTypeMalware() const
{
	return _type == eType::MALWARE;
}

bool Pattern::isEndianUnknown() const
{
	return _endian == eEndian::UNKNOWN;
}

bool Pattern::isEndianLittle() const
{
	return _endian == eEndian::LITTLE;
}

bool Pattern::isEndianBig() const
{
	return _endian == eEndian::BIG;
}

void Pattern::setName(const std::string& name)
{
	_name = name;
}

void Pattern::setDescription(const std::string& description)
{
	_description = description;
}

void Pattern::setYaraRuleName(const std::string& yaraRuleName)
{
	_yaraRuleName = yaraRuleName;
}

void Pattern::setIsTypeOther()
{
	_type = eType::OTHER;
}

void Pattern::setIsTypeCrypto()
{
	_type = eType::CRYPTO;
}

void Pattern::setIsTypeMalware()
{
	_type = eType::MALWARE;
}

void Pattern::setIsEndianUnknown()
{
	_endian = eEndian::UNKNOWN;
}

void Pattern::setIsEndianLittle()
{
	_endian = eEndian::LITTLE;
}

void Pattern::setIsEndianBig()
{
	_endian = eEndian::BIG;
}

std::string Pattern::getName() const
{
	return _name;
}

std::string Pattern::getDescription() const
{
	return _description;
}

std::string Pattern::getYaraRuleName() const
{
	return _yaraRuleName;
}

/**
 * @return This instance is equal with the provided one if all the members
 * are equal.
 */
bool Pattern::operator==(const Pattern& val) const
{
	return getName() == val.getName()
			&& getDescription() == val.getDescription()
			&& getYaraRuleName() == val.getYaraRuleName()
			&& _type == val._type
			&& _endian == val._endian
			&& matches == val.matches;
}

bool Pattern::operator!=(const Pattern& val) const
{
	return !(*this == val);
}

} // namespace common
} // namespace retdec
