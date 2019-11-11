/**
 * @file src/common/language.cpp
 * @brief Common programming language representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/language.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace common {

//
//=============================================================================
// Language
//=============================================================================
//

Language::Language()
{

}

Language::Language(const std::string& langName) :
		_name(langName)
{

}

bool Language::isUnknown() const        { return _name.empty(); }
bool Language::isKnown() const          { return !isUnknown(); }
bool Language::isModuleCountSet() const { return _moduleCount >= 0; }
bool Language::isBytecode() const       { return _bytecode; }

void Language::setName(const std::string& n) { _name = n; }
void Language::setIsUnknown()                { _name.clear(); }
void Language::setModuleCount(unsigned c)    { _moduleCount = c; }
void Language::setIsBytecode(bool b)         { _bytecode = b; }

unsigned Language::getModuleCount() const { return _moduleCount; }

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
	for (auto& l : *this)
	{
		if (retdec::utils::containsCaseInsensitive(l.getName(), sub))
		{
			return true;
		}
	}
	return false;
}

} // namespace common
} // namespace retdec
