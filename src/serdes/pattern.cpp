/**
 * @file src/serdes/pattern.cpp
 * @brief Pattern (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/pattern.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/pattern.h"
#include "retdec/serdes/std.h"

#include "retdec/serdes/std.h"

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

template <typename Writer>
void serialize(Writer& writer, const common::Pattern::Match& pm)
{
	writer.StartObject();

	serialize(writer, JSON_offset, pm.getOffset(), pm.isOffsetDefined());
	serialize(writer, JSON_address, pm.getAddress(), pm.isAddressDefined());
	if (pm.isSizeDefined())
	{
		serializeUint64(writer, JSON_size, pm.getSize().value());
	}
	if (pm.isEntrySizeDefined())
	{
		serializeUint64(writer, JSON_entrySize, pm.getEntrySize().value());
	}

	if (pm.isTypeIntegral())
	{
		serializeString(writer, JSON_match_type, JSON_val_typeIntegral);
	}
	else if (pm.isTypeFloatingPoint())
	{
		serializeString(writer, JSON_match_type, JSON_val_typeFP);
	}
	else
	{
		serializeString(writer, JSON_match_type, JSON_val_typeUnknown);
	}

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Pattern::Match)

void deserialize(const rapidjson::Value& val, common::Pattern::Match& pm)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Address offset;
	deserialize(val, JSON_offset, offset);
	pm.setOffset(offset);

	common::Address addr;
	deserialize(val, JSON_address, addr);
	pm.setAddress(addr);

	if (val.HasMember(JSON_size))
	{
		pm.setSize(deserializeUint64(val, JSON_size));
	}
	if (val.HasMember(JSON_entrySize))
	{
		pm.setEntrySize(deserializeUint64(val, JSON_entrySize));
	}

	std::string e = deserializeString(val, JSON_match_type);
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

template <typename Writer>
void serialize(Writer& writer, const common::Pattern& p)
{
	writer.StartObject();

	serializeString(writer, JSON_name, p.getName());
	serializeString(writer, JSON_description, p.getDescription());
	serializeString(writer, JSON_yara_rule_name, p.getYaraRuleName());

	if (p.isTypeCrypto())
	{
		serializeString(writer, JSON_patternType, JSON_val_typeCrypto);
	}
	else if (p.isTypeMalware())
	{
		serializeString(writer, JSON_patternType, JSON_val_typeMalware);
	}
	else
	{
		serializeString(writer, JSON_patternType, JSON_val_typeOther);
	}

	if (p.isEndianLittle())
	{
		serializeString(writer, JSON_patternEndian, JSON_val_endianLittle);
	}
	else if (p.isEndianBig())
	{
		serializeString(writer, JSON_patternEndian, JSON_val_endianBig);
	}
	else
	{
		serializeString(writer, JSON_patternEndian, JSON_val_endianUnknown);
	}

	serializeContainer(writer, JSON_matches, p.matches);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Pattern)

void deserialize(const rapidjson::Value& val, common::Pattern& p)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	p.setName(deserializeString(val, JSON_name));
	p.setDescription(deserializeString(val, JSON_description));
	p.setYaraRuleName(deserializeString(val, JSON_yara_rule_name));

	std::string t = deserializeString(val, JSON_patternType);
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

	std::string e = deserializeString(val, JSON_patternEndian);
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

	deserializeContainer(val, JSON_matches, p.matches);
}

} // namespace serdes
} // namespace retdec
