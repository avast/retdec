/**
 * @file src/serdes/pattern.cpp
 * @brief Pattern (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/pattern.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/pattern.h"
#include "retdec/serdes/std.h"

#include "serdes/utils.h"

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

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Pattern::Match& pm)
{
	Json::Value match;

	if (pm.isOffsetDefined())
	{
		match[JSON_offset] = serdes::serialize(pm.getOffset());
	}
	if (pm.isAddressDefined())
	{
		match[JSON_address] = serdes::serialize(pm.getAddress());
	}
	if (pm.isSizeDefined())
	{
		match[JSON_size] = pm.getSize().value();
	}
	if (pm.isEntrySizeDefined())
	{
		match[JSON_entrySize] = pm.getEntrySize().value();
	}

	if (pm.isTypeIntegral())
	{
		match[JSON_match_type] = JSON_val_typeIntegral;
	}
	else if (pm.isTypeFloatingPoint())
	{
		match[JSON_match_type] = JSON_val_typeFP;
	}
	else
	{
		match[JSON_match_type] = JSON_val_typeUnknown;
	}

	return match;
}

void deserialize(const Json::Value& val, common::Pattern::Match& pm)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Address offset;
	serdes::deserialize(val[JSON_offset], offset);
	pm.setOffset(offset);

	common::Address addr;
	serdes::deserialize(val[JSON_address], addr);
	pm.setAddress(addr);

	if (val.isMember(JSON_size))
	{
		pm.setSize(safeGetUint(val, JSON_size));
	}
	if (val.isMember(JSON_entrySize))
	{
		pm.setEntrySize(safeGetUint(val, JSON_entrySize));
	}

	std::string e = safeGetString(val, JSON_match_type);
	if (e == JSON_val_typeIntegral)
	{
		pm.setIsTypeIntegral();
	}
	else if (e == JSON_val_typeFP)
	{
		pm.setIsTypeFloatingPoint();
	}
	else
	{
		pm.setIsTypeUnknown();
	}
}

Json::Value serialize(const common::Pattern& p)
{
	Json::Value ret;

	ret[JSON_name] = p.getName();
	ret[JSON_description] = p.getDescription();
	ret[JSON_yara_rule_name] = p.getYaraRuleName();

	if (p.isTypeCrypto())
	{
		ret[JSON_patternType] = JSON_val_typeCrypto;
	}
	else if (p.isTypeMalware())
	{
		ret[JSON_patternType] = JSON_val_typeMalware;
	}
	else
	{
		ret[JSON_patternType] = JSON_val_typeOther;
	}

	if (p.isEndianLittle())
	{
		ret[JSON_patternEndian] = JSON_val_endianLittle;
	}
	else if (p.isEndianBig())
	{
		ret[JSON_patternEndian] = JSON_val_endianBig;
	}
	else
	{
		ret[JSON_patternEndian] = JSON_val_endianUnknown;
	}

	ret[JSON_matches] = serialize(p.matches);

	return ret;
}

void deserialize(const Json::Value& val, common::Pattern& p)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	p.setName(safeGetString(val, JSON_name));
	p.setDescription(safeGetString(val, JSON_description));
	p.setYaraRuleName(safeGetString(val, JSON_yara_rule_name));

	std::string t = safeGetString(val, JSON_patternType);
	if (t == JSON_val_typeCrypto)
	{
		p.setIsTypeCrypto();
	}
	else if (t == JSON_val_typeMalware)
	{
		p.setIsTypeMalware();
	}
	else
	{
		p.setIsTypeOther();
	}

	std::string e = safeGetString(val, JSON_patternEndian);
	if (e == JSON_val_endianLittle)
	{
		p.setIsEndianLittle();
	}
	else if (e == JSON_val_endianBig)
	{
		p.setIsEndianBig();
	}
	else
	{
		p.setIsEndianUnknown();
	}

	deserialize(val[JSON_matches], p.matches);
}

} // namespace serdes
} // namespace retdec
