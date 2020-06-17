/**
 * @file include/retdec/config/config.h
 * @brief Decompilation configuration manipulation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_CONFIG_H
#define RETDEC_CONFIG_CONFIG_H

#include "retdec/common/architecture.h"
#include "retdec/common/class.h"
#include "retdec/common/file_format.h"
#include "retdec/common/file_type.h"
#include "retdec/common/function.h"
#include "retdec/common/language.h"
#include "retdec/common/pattern.h"
#include "retdec/common/tool_info.h"
#include "retdec/common/vtable.h"
#include "retdec/common/type.h"
#include "retdec/config/config_exceptions.h"
#include "retdec/config/parameters.h"

namespace retdec {
namespace config {

/**
 * Main config class containing all configuration information.
 */
class Config
{
	public:
		/// @name Config named constructors.
		/// @{
		static Config empty();
		static Config fromFile(const std::string& path);
		static Config fromJsonString(const std::string& json);
		/// @}

		std::string generateJsonString() const;
		std::string generateJsonFile() const;
		std::string generateJsonFile(const std::string& outputFilePath) const;

		void readJsonString(const std::string& json);
		void readJsonFile(const std::string& input);

	public:
		Parameters parameters;
		common::Architecture architecture;
		common::FileType fileType;
		common::FileFormat fileFormat;
		common::ToolInfoContainer tools;
		common::LanguageContainer languages;
		common::FunctionContainer functions;
		common::GlobalVarContainer globals;
		common::ObjectSetContainer registers;
		common::TypeContainer structures;
		common::VtableContainer vtables;
		common::ClassContainer classes;
		common::PatternContainer patterns;
};

} // namespace config
} // namespace retdec

#endif
