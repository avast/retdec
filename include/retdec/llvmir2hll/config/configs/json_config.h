/**
* @file include/retdec/llvmir2hll/config/configs/json_config.h
* @brief Config in the JSON format.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_CONFIG_CONFIGS_JSON_CONFIG_H
#define RETDEC_LLVMIR2HLL_CONFIG_CONFIGS_JSON_CONFIG_H

#include "retdec/llvmir2hll/config/config.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Base class for all exceptions raised by JSONConfig.
*/
class JSONConfigError: public ConfigError {
	using ConfigError::ConfigError;
};

/**
* @brief Exception raised when the config file does not exist.
*/
class JSONConfigFileNotFoundError: public JSONConfigError {
	using JSONConfigError::JSONConfigError;
};

/**
* @brief Exception raised when there is a parsing error.
*/
class JSONConfigParsingError: public JSONConfigError {
	using JSONConfigError::JSONConfigError;
};

/**
* @brief Config in the JSON format.
*/
class JSONConfig: public Config {
public:
	virtual ~JSONConfig() override;

	/// @name Loading and Saving
	/// @{
	static UPtr<JSONConfig> fromFile(const std::string &path);
	static UPtr<JSONConfig> fromString(const std::string &str);
	static UPtr<JSONConfig> empty();

	virtual void saveTo(const std::string &path) override;
	/// @}

	/// @name Debugging
	/// @{
	virtual void dump() override;
	/// @}

	/// @name Variables
	/// @{
	virtual bool isGlobalVarStoringWideString(const std::string &var) const override;
	virtual std::string comesFromGlobalVar(const std::string &func,
		const std::string &var) const override;
	virtual std::string getRegisterForGlobalVar(const std::string &var) const override;
	virtual std::string getDetectedCryptoPatternForGlobalVar(const std::string &var) const override;
	/// @}

	/// @name Functions
	/// @{
	virtual std::string getRealNameForFunc(const std::string &func) const override;
	virtual AddressRange getAddressRangeForFunc(const std::string &func) const override;
	virtual LineRange getLineRangeForFunc(const std::string &func) const override;
	virtual bool isUserDefinedFunc(const std::string &func) const override;
	virtual bool isStaticallyLinkedFunc(const std::string &func) const override;
	virtual bool isDynamicallyLinkedFunc(const std::string &func) const override;
	virtual bool isSyscallFunc(const std::string &func) const override;
	virtual bool isInstructionIdiomFunc(const std::string &func) const override;
	virtual bool isExportedFunc(const std::string &func) const override;
	virtual void markFuncAsStaticallyLinked(const std::string &func) override;
	virtual std::string getDeclarationStringForFunc(const std::string &func) const override;
	virtual std::string getCommentForFunc(const std::string &func) const override;
	virtual StringSet getDetectedCryptoPatternsForFunc(const std::string &func) const override;
	virtual std::string getWrappedFunc(const std::string &func) const override;
	virtual std::string getDemangledNameOfFunc(const std::string &func) const override;
	virtual StringSet getFuncsFixedWithLLVMIRFixer() const override;
	/// @}

	/// @name Classes
	/// @{
	virtual StringSet getClassNames() const override;
	virtual std::string getClassForFunc(const std::string &func) const override;
	virtual std::string getTypeOfFuncInClass(const std::string &func,
		const std::string &cl) const override;
	virtual StringVector getBaseClassNames(const std::string &cl) const override;
	virtual std::string getDemangledNameOfClass(const std::string &cl) const override;
	/// @}

	/// @name Debug Info
	/// @{
	virtual bool isDebugInfoAvailable() const override;
	virtual std::string getDebugModuleNameForFunc(const std::string &func) const override;
	virtual StringSet getDebugModuleNames() const override;
	virtual std::string getDebugNameForGlobalVar(const std::string &var) const override;
	virtual std::string getDebugNameForLocalVar(const std::string &func,
		const std::string &var) const override;
	/// @}

	/// @name Meta Information
	/// @{
	virtual StringSet getPrefixesOfFuncsToBeRemoved() const override;
	virtual std::string getFrontendRelease() const override;
	virtual std::size_t getNumberOfFuncsDetectedInFrontend() const override;
	virtual std::string getDetectedCompilerOrPacker() const override;
	virtual std::string getDetectedLanguage() const override;
	virtual StringSet getSelectedButNotFoundFuncs() const override;
	/// @}

private:
	JSONConfig();

private:
	struct Impl;
	/// Private implementation.
	UPtr<Impl> impl;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
