/**
 * @file include/retdec/config/parameters.h
 * @brief Decompilation configuration manipulation: decompilation parameters.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_PARAMETERS_H
#define RETDEC_CONFIG_PARAMETERS_H

#include <set>
#include <string>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>

#include "retdec/common/address.h"

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
		bool isDetectStaticCode() const;
		bool isTimeout() const;
		bool isMaxMemoryLimitHalfRam() const;
		bool isBackendNoOpts() const;
		bool isBackendEmitCfg() const;
		bool isBackendEmitCg() const;
		bool isBackendKeepAllBrackets() const;
		bool isBackendKeepLibraryFuncs() const;
		bool isBackendNoTimeVaryingInfo() const;
		bool isBackendNoVarRenaming() const;
		bool isBackendNoCompoundOperators() const;
		bool isBackendNoSymbolicNames() const;
		/// @}

		/// @name Parameters set methods.
		/// @{
		void setIsVerboseOutput(bool b);
		void setIsKeepAllFunctions(bool b);
		void setIsSelectedDecodeOnly(bool b);
		void setOrdinalNumbersDirectory(const std::string& n);
		void setInputFile(const std::string& file);
		void setInputPdbFile(const std::string& file);
		void setOutputFile(const std::string& n);
		void setOutputBitcodeFile(const std::string& file);
		void setOutputAsmFile(const std::string& file);
		void setOutputLlvmirFile(const std::string& file);
		void setOutputConfigFile(const std::string& file);
		void setOutputUnpackedFile(const std::string& file);
		void setOutputFormat(const std::string& format);
		void setLogFile(const std::string& file);
		void setErrFile(const std::string& file);
		void setMaxMemoryLimit(uint64_t limit);
		void setIsMaxMemoryLimitHalfRam(bool f);
		void setTimeout(uint64_t seconds);
		void setEntryPoint(const retdec::common::Address& a);
		void setMainAddress(const retdec::common::Address& a);
		void setSectionVMA(const retdec::common::Address& a);
		void setBackendDisabledOpts(const std::string& o);
		void setBackendEnabledOpts(const std::string& o);
		void setBackendCallInfoObtainer(const std::string& val);
		void setBackendVarRenamer(const std::string& val);
		void setIsDetectStaticCode(bool b);
		void setIsBackendNoOpts(bool b);
		void setIsBackendEmitCfg(bool b);
		void setIsBackendEmitCg(bool b);
		void setIsBackendKeepAllBrackets(bool b);
		void setIsBackendKeepLibraryFuncs(bool b);
		void setIsBackendNoTimeVaryingInfo(bool b);
		void setIsBackendNoVarRenaming(bool b);
		void setIsBackendNoCompoundOperators(bool b);
		void setIsBackendNoSymbolicNames(bool b);
		/// @}

		/// @name Parameters get methods.
		/// @{
		const std::string& getOrdinalNumbersDirectory() const;
		const std::string& getInputFile() const;
		const std::string& getInputPdbFile() const;
		const std::string& getOutputFile() const;
		const std::string& getOutputBitcodeFile() const;
		const std::string& getOutputAsmFile() const;
		const std::string& getOutputLlvmirFile() const;
		const std::string& getOutputConfigFile() const;
		const std::string& getOutputUnpackedFile() const;
		const std::string& getOutputFormat() const;
		const std::string& getLogFile() const;
		const std::string& getErrFile() const;
		uint64_t getMaxMemoryLimit() const;
		uint64_t getTimeout() const;
		retdec::common::Address getEntryPoint() const;
		retdec::common::Address getMainAddress() const;
		retdec::common::Address getSectionVMA() const;
		const std::string& getBackendDisabledOpts() const;
		const std::string& getBackendEnabledOpts() const;
		const std::string& getBackendCallInfoObtainer() const;
		const std::string& getBackendVarRenamer() const;
		/// @}

		void fixRelativePaths(const std::string& configPath);

		template <typename Writer>
		void serialize(Writer& writer) const;
		void deserialize(const rapidjson::Value& val);

	public:
		std::set<std::string> userStaticSignaturePaths;
		std::set<std::string> staticSignaturePaths;
		std::set<std::string> libraryTypeInfoPaths;
		std::set<std::string> cryptoPatternPaths;
		std::set<std::string> abiPaths;

		/// Functions' names which were selected by the user through
		/// selective decompilation.
		std::set<std::string> selectedFunctions;

		/// Selected functions' names from @c selectedFunctions which
		/// were not found in the binary.
		std::set<std::string> selectedNotFoundFunctions;

		/// Address ranges selected by the user through selective decompilation.
		common::AddressRangeContainer selectedRanges;

		/// LLVM passes.
		std::vector<std::string> llvmPasses;

	private:
		/// Decompilation will verbosely inform about the
		/// decompilation process.
		bool _verboseOutput = true;

		/// Keep all functions in the decompiler's output.
		/// Otherwise, only functions reachable from main are kept.
		bool _keepAllFunctions = false;

		/// Decode only parts selected through selective decompilation.
		/// Otherwise, entire binary is decoded.
		/// This speeds up decompilation, but usually produces lower-quality
		/// results.
		bool _selectedDecodeOnly = false;

		std::string _ordinalNumbersDirectory;
		std::string _inputFile;
		std::string _inputPdbFile;
		std::string _outputFile;
		std::string _outputBitcodeFile;
		std::string _outputAsmFile;
		std::string _outputLlFile;
		std::string _outputConfigFile;
		std::string _outputUnpackedFile;
		std::string _outputFormat;
		std::string _logFile;
		std::string _errFile;
		uint64_t _maxMemoryLimit = 0;
		bool _maxMemoryLimitHalfRam = true;
		uint64_t _timeout = 0;

		bool _detectStaticCode = true;
		std::string _backendDisabledOpts;
		std::string _backendEnabledOpts;
		std::string _backendCallInfoObtainer = "optim";
		std::string _backendVarRenamer = "readable";
		bool _backendNoOpts = false;
		bool _backendEmitCfg = false;
		bool _backendEmitCg = false;
		bool _backendKeepAllBrackets = false;
		bool _backendKeepLibraryFuncs = false;
		bool _backendNoTimeVaryingInfo = false;
		bool _backendNoVarRenaming = false;
		bool _backendNoCompoundOperators = false;
		bool _backendNoSymbolicNames = false;

		retdec::common::Address _entryPoint;
		retdec::common::Address _mainAddress;
		retdec::common::Address _sectionVMA;
};

} // namespace config
} // namespace retdec

#endif
