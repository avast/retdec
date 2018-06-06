/**
 * @file src/config/patterns.cpp
 * @brief Decompilation configuration manipulation: patterns.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/patterns.h"

namespace retdec {
namespace config {

namespace {

const std::string JSON_offset            = "offset";
const std::string JSON_address           = "address";
const std::string JSON_size              = "size";
const std::string JSON_entrySize         = "entrySize";
const std::string JSON_match_type        = "type";

const std::string JSON_val_typeUnknown   = "unknown";
const std::string JSON_val_typeIntegral  = "integral";
const std::string JSON_val_typeFP        = "floatingPoint";

const std::string JSON_name              = "name";
const std::string JSON_description       = "description";
const std::string JSON_yara_rule_name    = "yaraRule";
const std::string JSON_patternType       = "type";
const std::string JSON_patternEndian     = "endian";
const std::string JSON_matches           = "matches";

const std::string JSON_val_typeOther     = "other";
const std::string JSON_val_typeCrypto    = "crypto";
const std::string JSON_val_typeMalware   = "malware";

const std::string JSON_val_endianUnknown = "unknown";
const std::string JSON_val_endianLittle  = "little";
const std::string JSON_val_endianBig     = "big";

} // anonymous namespace

//
//=============================================================================
// Pattern::Match
//=============================================================================
//

Pattern::Match::Match()
{

}

Pattern::Match::Match(
		const retdec::utils::Address& offset,
		const retdec::utils::Address& address,
		retdec::utils::Maybe<unsigned> size,
		retdec::utils::Maybe<unsigned> entrySize,
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
		const retdec::utils::Address& offset,
		const retdec::utils::Address& address,
		retdec::utils::Maybe<unsigned> size,
		retdec::utils::Maybe<unsigned> entrySize)
{
	return Match(offset, address, size, entrySize, eType::UNKNOWN);
}

Pattern::Match Pattern::Match::integral(
		const retdec::utils::Address& offset,
		const retdec::utils::Address& address,
		retdec::utils::Maybe<unsigned> size,
		retdec::utils::Maybe<unsigned> entrySize)
{
	return Match(offset, address, size, entrySize, eType::INTEGRAL);
}

Pattern::Match Pattern::Match::floatingPoint(
		const retdec::utils::Address& offset,
		const retdec::utils::Address& address,
		retdec::utils::Maybe<unsigned> size,
		retdec::utils::Maybe<unsigned> entrySize)
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
	return _size.isDefined();
}

bool Pattern::Match::isEntrySizeDefined() const
{
	return _entrySize.isDefined();
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

void Pattern::Match::setOffset(const retdec::utils::Address& offset)
{
	_offset = offset;
}

void Pattern::Match::setAddress(const retdec::utils::Address& address)
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

retdec::utils::Address Pattern::Match::getOffset() const
{
	return _offset;
}

retdec::utils::Address Pattern::Match::getAddress() const
{
	return _address;
}

retdec::utils::Maybe<unsigned> Pattern::Match::getSize() const
{
	return _size;
}

retdec::utils::Maybe<unsigned> Pattern::Match::getEntrySize() const
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

Pattern::Match Pattern::Match::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Pattern::Match");

	Pattern::Match ret;

	ret.setOffset( safeGetAddress(val, JSON_offset) );
	ret.setAddress( safeGetAddress(val, JSON_address) );

	if (val.isMember(JSON_size))
		ret.setSize( safeGetUint(val, JSON_size) );
	if (val.isMember(JSON_entrySize))
		ret.setEntrySize( safeGetUint(val, JSON_entrySize) );

	std::string e = safeGetString(val, JSON_match_type);
	if (e == JSON_val_typeIntegral)
		ret.setIsTypeIntegral();
	else if (e == JSON_val_typeFP)
		ret.setIsTypeFloatingPoint();
	else
		ret.setIsTypeUnknown();

	return ret;
}

Json::Value Pattern::Match::getJsonValue() const
{
	Json::Value match;

	if (isOffsetDefined())    match[JSON_offset] = toJsonValue(getOffset());
	if (isAddressDefined())   match[JSON_address] = toJsonValue(getAddress());
	if (isSizeDefined())      match[JSON_size] = getSize().getValue();
	if (isEntrySizeDefined()) match[JSON_entrySize] = getEntrySize().getValue();

	if (isTypeIntegral())
		match[JSON_match_type] = JSON_val_typeIntegral;
	else if (isTypeFloatingPoint())
		match[JSON_match_type] = JSON_val_typeFP;
	else
		match[JSON_match_type] = JSON_val_typeUnknown;

	return match;
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

Pattern Pattern::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Pattern");

	Pattern ret;

	ret.setName( safeGetString(val, JSON_name) );
	ret.setDescription( safeGetString(val, JSON_description) );
	ret.setYaraRuleName( safeGetString(val, JSON_yara_rule_name) );

	std::string t = safeGetString(val, JSON_patternType);
	if (t == JSON_val_typeCrypto)
		ret.setIsTypeCrypto();
	else if (t == JSON_val_typeMalware)
		ret.setIsTypeMalware();
	else
		ret.setIsTypeOther();

	std::string e = safeGetString(val, JSON_patternEndian);
	if (e == JSON_val_endianLittle)
		ret.setIsEndianLittle();
	else if (e == JSON_val_endianBig)
		ret.setIsEndianBig();
	else
		ret.setIsEndianUnknown();

	ret.matches.readJsonValue( val[JSON_matches] );

	return ret;
}

Json::Value Pattern::getJsonValue() const
{
	Json::Value ret;

	ret[JSON_name] = getName();
	ret[JSON_description] = getDescription();
	ret[JSON_yara_rule_name] = getYaraRuleName();

	if (isTypeCrypto())
		ret[JSON_patternType] = JSON_val_typeCrypto;
	else if (isTypeMalware())
		ret[JSON_patternType] = JSON_val_typeMalware;
	else
		ret[JSON_patternType] = JSON_val_typeOther;

	if (isEndianLittle())
		ret[JSON_patternEndian] = JSON_val_endianLittle;
	else if (isEndianBig())
		ret[JSON_patternEndian] = JSON_val_endianBig;
	else
		ret[JSON_patternEndian] = JSON_val_endianUnknown;

	ret[JSON_matches] = matches.getJsonValue();

	return ret;
}

//
//=============================================================================
// PatternContainer
//=============================================================================
//

} // namespace config
} // namespace retdec
