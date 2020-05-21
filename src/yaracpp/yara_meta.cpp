/**
 * @file src/yaracpp/yara_meta.cpp
 * @brief Library representation of one YARA meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/yaracpp/yara_meta.h"

namespace retdec {
namespace yaracpp {

/**
 * Get name of meta
 * @return Name of meta
 */
const std::string& YaraMeta::getId() const
{
	return id;
}

/**
 * Get type of meta
 * @return Type of meta
 */
YaraMeta::Type YaraMeta::getType() const
{
	return type;
}

/**
 * Get string value of meta
 * @return String value of meta
 */
const std::string& YaraMeta::getStringValue() const
{
	assert(type == Type::String);
	return strValue;
}

/**
 * Get int value of meta
 * @return Int value of meta
 */
const std::uint64_t& YaraMeta::getIntValue() const
{
	assert(type == Type::Int);
	return intValue;
}

/**
 * Get string value of meta
 * @return String value of meta
 */
std::string& YaraMeta::getStringValue()
{
	assert(type == Type::String);
	return strValue;
}

/**
 * Get int value of meta
 * @return Int value of meta
 */
std::uint64_t& YaraMeta::getIntValue()
{
	assert(type == Type::Int);
	return intValue;
}

/**
 * Set name of meta
 * @param metaId Name of meta
 */
void YaraMeta::setId(const std::string &metaId)
{
	id = metaId;
}

/**
 * Set type of meta
 * @param metaType Type of meta
 */
void YaraMeta::setType(YaraMeta::Type metaType)
{
	type = metaType;
}

/**
 * Set string value of meta
 * @param metaValue String value of meta
 */
void YaraMeta::setStringValue(const std::string &metaValue)
{
	assert(type == Type::String);
	strValue = metaValue;
}

/**
 * Set int value of meta
 * @param metaValue Int value of meta
 */
void YaraMeta::setIntValue(std::uint64_t metaValue)
{
	assert(type == Type::Int);
	intValue = metaValue;
}

} // namespace yaracpp
} // namespace retdec
