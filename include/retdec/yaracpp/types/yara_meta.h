/**
 * @file include/yaracpp/types/yara_meta.h
 * @brief Library representation of one YARA meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

namespace yaracpp
{

/**
 * Representation of metadata
 */
class YaraMeta
{
	public:
		enum class Type
		{
			String,
			Int
		};
	private:
		std::string id;         ///< name of meta
		Type type;              ///< type of meta
		std::string strValue;   ///< string value of meta
		std::uint64_t intValue; ///< int value of meta
	public:
		/// @name Const getters
		/// @{
		const std::string& getId() const;
		YaraMeta::Type getType() const;
		const std::string& getStringValue() const;
		const std::uint64_t& getIntValue() const;
		/// @}

		/// @name Getters
		/// @{
		std::string& getStringValue();
		std::uint64_t& getIntValue();
		/// @}

		/// @name Setters
		/// @{
		void setId(const std::string &metaId);
		void setType(YaraMeta::Type metaType);
		void setStringValue(const std::string &metaValue);
		void setIntValue(std::uint64_t metaValue);
		/// @}
};

} // namespace yaracpp
