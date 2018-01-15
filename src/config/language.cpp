/**
 * @file src/config/language.cpp
 * @brief Decompilation configuration manipulation: language.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/language.h"
#include "retdec/utils/string.h"

namespace {

const std::string JSON_name        = "name";
const std::string JSON_moduleCount = "moduleCount";
const std::string JSON_bytecode    = "bytecode";

} // anonymous namespace

namespace retdec {
namespace config {

//
//=============================================================================
// Language
//=============================================================================
//

Language::Language(const std::string& langName) :
		_name(langName)
{

}

/**
 * Reads JSON object (associative array) holding language information.
 * @param val JSON object.
 */
Language Language::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Language");

	Language ret(safeGetString(val, JSON_name));

	int c = safeGetInt(val, JSON_moduleCount, -1);
	if (c >= 0)
		ret.setModuleCount(c);
	ret.setIsBytecode( safeGetBool(val, JSON_bytecode) );

	return ret;
}

/**
 * Returns JSON object (associative array) holding language information.
 * @return JSON object.
 */
Json::Value Language::getJsonValue() const
{
	Json::Value lang;

	lang[JSON_name] = getName();
	if (isModuleCountSet()) lang[JSON_moduleCount] = getModuleCount();
	lang[JSON_bytecode] = isBytecode();

	return lang;
}

bool Language::isUnknown() const        { return _name.empty(); }
bool Language::isKnown() const          { return !isUnknown(); }
bool Language::isModuleCountSet() const { return _moduleCount >= 0; }
bool Language::isBytecode() const       { return _bytecode; }

void Language::setIsUnknown()                { _name.clear(); }
void Language::setModuleCount(unsigned c)    { _moduleCount = c; }
void Language::setIsBytecode(bool b)         { _bytecode = b; }

unsigned Language::getModuleCount() const { return _moduleCount; }

/**
 * @return Language's ID is its name.
 */
std::string Language::getId() const
{
	return getName();
}

std::string Language::getName() const
{
	return _name;
}

/**
 * Less-than comparison of this instance with the provided one.
 * Default string comparison of @c name members is used.
 * @param val Other language to compare with.
 * @return True if @c this instance is considered to be less-than @c val.
 */
bool Language::operator<(const Language& val) const
{
	return getName() < val.getName();
}

/**
 * Languages are equal if their names are equal.
 */
bool Language::operator==(const Language& val) const
{
	return getName() == val.getName();
}

//
//=============================================================================
// LanguageContainer
//=============================================================================
//

/**
 * @return Pointer to language or @c nullptr if not found.
 */
const Language* LanguageContainer::getFirstBytecode() const
{
	for (const auto& item : *this)
	{
		if (item.isBytecode())
		{
			return &item;
		}
	}

	return nullptr;
}

bool LanguageContainer::hasLanguage(const std::string& sub) const
{
	for (auto& l : _data)
	{
		if (retdec::utils::containsCaseInsensitive(l.getName(), sub))
		{
			return true;
		}
	}
	return false;
}

} // namespace config
} // namespace retdec
