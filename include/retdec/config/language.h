/**
 * @file include/retdec/config/language.h
 * @brief Decompilation configuration manipulation: language.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_LANGUAGE_H
#define RETDEC_CONFIG_LANGUAGE_H

#include <string>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents input binary's language.
 * Language's name is its unique ID.
 */
class Language
{
	public:
		explicit Language(const std::string& langName);
		static Language fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		/// @name Language query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isModuleCountSet() const;
		bool isBytecode() const;
		/// @}

		/// @name Language set methods.
		/// @{
		void setIsUnknown();
		void setModuleCount(unsigned c);
		void setIsBytecode(bool b);
		/// @}

		/// @name Language get methods.
		/// @{
		std::string getId() const;
		std::string getName() const;
		unsigned getModuleCount() const;
		/// @}

		bool operator<(const Language& val) const;
		bool operator==(const Language& val) const;

	private:
		/// Unique ID.
		std::string _name;
		int _moduleCount = -1;
		bool _bytecode = false;
};

/**
 * Set container with languages' names as unique ID (set key).
 * See Language class for details.
 */
class LanguageContainer : public BaseSetContainer<Language>
{
	public:
		const Language* getFirstBytecode() const;
		bool hasLanguage(const std::string& sub) const;
};

} // namespace config
} // namespace retdec

#endif
