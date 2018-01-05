/**
 * @file include/retdec-config/config.h
 * @brief Decompilation configuration manipulation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_CONFIG_H
#define RETDEC_CONFIG_CONFIG_H

#include "retdec-config/architecture.h"
#include "retdec-config/base.h"
#include "retdec-config/classes.h"
#include "retdec-config/file_format.h"
#include "retdec-config/file_type.h"
#include "retdec-config/functions.h"
#include "retdec-config/language.h"
#include "retdec-config/parameters.h"
#include "retdec-config/patterns.h"
#include "retdec-config/segments.h"
#include "retdec-config/tool_info.h"
#include "retdec-config/types.h"
#include "retdec-config/vtables.h"

namespace retdec_config  {

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
		void setEntryPoint(const tl_cpputils::Address& a);
		void setMainAddress(const tl_cpputils::Address& a);
		void setSectionVMA(const tl_cpputils::Address& a);
		void setImageBase(const tl_cpputils::Address& a);
		void setIsIda(bool b);
		/// @}

		/// @name Config get methods.
		/// @{
		std::string getInputFile() const;
		std::string getUnpackedInputFile() const;
		std::string getPdbInputFile() const;
		std::string getFrontendVersion() const;
		std::string getConfigFileName() const;
		tl_cpputils::Address getEntryPoint() const;
		tl_cpputils::Address getMainAddress() const;
		tl_cpputils::Address getSectionVMA() const;
		tl_cpputils::Address getImageBase() const;
		/// @}

		std::string generateJsonString() const;
		std::string generateJsonFile() const;
		std::string generateJsonFile(const std::string& outputFilePath) const;

		void readJsonString(const std::string& json);
		void readJsonFile(const std::string& input);

	public:
		Parameters parameters;
		Architecture architecture;
		FileType fileType;
		FileFormat fileFormat;
		ToolInfoContainer tools;
		LanguageContainer languages;
		FunctionContainer functions;
		GlobalVarContainer globals;
		RegisterContainer registers;
		TypeContainer structures;
		SegmentContainer segments;
		VtableContainer vtables;
		ClassContainer classes;
		PatternContainer patterns;

	private:
		std::string _inputFile;
		std::string _unpackedInputFile;
		std::string _pdbInputFile;
		std::string _frontendVersion;
		std::string _configFileName;

		tl_cpputils::Address _entryPoint;
		tl_cpputils::Address _mainAddress;
		tl_cpputils::Address _sectionVMA;
		tl_cpputils::Address _imageBase;

		bool _ida = false;
};

} // namespace retdec_config

#endif
