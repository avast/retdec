/**
 * @file include/retdec/config/parameters.h
 * @brief Decompilation configuration manipulation: decompilation parameters.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_PARAMETERS_H
#define RETDEC_CONFIG_PARAMETERS_H

#include <set>
#include <string>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents decompilation process parameters (options).
 */
class Parameters
{
	public:
		/// @name Parameters query methods.
		/// @{
		bool isSomethingSelected() const;
		bool isVerboseOutput() const;
		bool isKeepAllFunctions() const;
		bool isSelectedDecodeOnly() const;
		bool isFrontendFunction(const std::string& funcName) const;
		/// @}

		/// @name Parameters set methods.
		/// @{
		void setIsVerboseOutput(bool b);
		void setIsKeepAllFunctions(bool b);
		void setIsSelectedDecodeOnly(bool b);
		void setOutputFile(const std::string& n);
		void setFrontendOutputFile(const std::string& n);
		void setOrdinalNumbersDirectory(const std::string& n);
		/// @}

		/// @name Parameters get methods.
		/// @{
		std::string getOutputFile() const;
		std::string getFrontendOutputFile() const;
		std::string getOrdinalNumbersDirectory() const;
		/// @}

		Json::Value getJsonValue() const;
		void readJsonValue(const Json::Value& val);

	public:
		std::set<std::string> userStaticSignaturePaths;
		std::set<std::string> staticSignaturePaths;
		std::set<std::string> libraryTypeInfoPaths;
		std::set<std::string> semanticPaths;
		std::set<std::string> abiPaths;
		std::set<std::string> frontendFunctions;

		/// Functions' names which were selected by the user through
		/// selective decompilation.
		std::set<std::string> selectedFunctions;

		/// Selected functions' names from @c selectedFunctions which
		/// were not found in the binary.
		std::set<std::string> selectedNotFoundFunctions;

		/// Address ranges selected by the user through selective decompilation.
		BaseSequentialContainer<AddressRangeJson> selectedRanges;

	private:
		/// Decompilation will verbosely inform about the
		/// decompilation process.
		bool _verboseOutput = false;

		/// Keep all functions in the decompiler's output.
		/// Otherwise, only functions reachable from main are kept.
		bool _keepAllFunctions = false;

		/// Decode only parts selected through selective decompilation.
		/// Otherwise, entire binary is decoded.
		/// This speeds up decompilation, but usually produces lower-quality
		/// results.
		bool _selectedDecodeOnly = false;

		std::string _outputFile;
		std::string _frontendOutputFile;
		std::string _ordinalNumbersDirectory;
};

} // namespace config
} // namespace retdec

#endif
