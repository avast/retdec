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
#include "retdec/config/base.h"
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
		static Config empty(const std::string& path = "");
		static Config fromFile(const std::string& path);
		static Config fromJsonString(const std::string& json);
		/// @}

		/// @name Config query methods.
		/// @{
		bool isIda() const;
		/// @}

		/// @name Config set methods.
		/// @{
		void setInputFile(const std::string& n);
		void setUnpackedInputFile(const std::string& n);
		void setPdbInputFile(const std::string& n);
		void setFrontendVersion(const std::string& n);
		void setEntryPoint(const retdec::common::Address& a);
		void setMainAddress(const retdec::common::Address& a);
		void setSectionVMA(const retdec::common::Address& a);
		void setImageBase(const retdec::common::Address& a);
		void setIsIda(bool b);
		/// @}

		/// @name Config get methods.
		/// @{
		std::string getInputFile() const;
		std::string getUnpackedInputFile() const;
		std::string getPdbInputFile() const;
		std::string getFrontendVersion() const;
		std::string getConfigFileName() const;
		retdec::common::Address getEntryPoint() const;
		retdec::common::Address getMainAddress() const;
		retdec::common::Address getSectionVMA() const;
		retdec::common::Address getImageBase() const;
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

	private:
		std::string _inputFile;
		std::string _unpackedInputFile;
		std::string _pdbInputFile;
		std::string _frontendVersion;
		std::string _configFileName;

		retdec::common::Address _entryPoint;
		retdec::common::Address _mainAddress;
		retdec::common::Address _sectionVMA;
		retdec::common::Address _imageBase;

		bool _ida = false;
};

} // namespace config
} // namespace retdec

#endif
