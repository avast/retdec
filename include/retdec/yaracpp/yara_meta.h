/**
 * @file include/retdec/yaracpp/yara_meta.h
 * @brief Library representation of one YARA meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_YARACPP_YARA_META_H
#define RETDEC_YARACPP_YARA_META_H

#include <cstdint>
#include <string>

namespace retdec {
namespace yaracpp {

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
	    /// name of meta
		std::string id;
		Type type;
		std::string strValue;
		std::uint64_t intValue;
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
} // namespace retdec

#endif
