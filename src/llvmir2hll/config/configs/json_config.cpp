/**
* @file src/llvmir2hll/config/configs/json_config.cpp
* @brief Implementation of the base class for all configs.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/llvmir2hll/config/configs/json_config.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/config/config.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using namespace std::string_literals;

using retdec::utils::addToSet;
using retdec::utils::hasItem;
using retdec::utils::trim;
using retdec::utils::unifyLineEnds;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Private implementation.
*/
struct JSONConfig::Impl {
	Impl();

	const retdec::config::Object &getConfigGlobalVariableByNameOrEmptyVariable(
		const std::string &name) const;
	const retdec::config::Object *getConfigRegisterByName(const std::string &name) const;
	retdec::config::Function *getConfigFunctionByName(const std::string &name);
	const retdec::config::Function *getConfigFunctionByName(const std::string &name) const;
	const retdec::config::Function &getConfigFunctionByNameOrEmptyFunction(
		const std::string &name) const;
	const retdec::config::Class *getConfigClassByName(const std::string &name) const;
	const retdec::config::Class &getConfigClassByNameOrEmptyClass(
		const std::string &name) const;
	std::string getNameOfRegister(const retdec::config::Object &reg) const;

	/// Path to the config file (if any).
	std::string path;

	/// Underlying config.
	retdec::config::Config config;
};

/**
* @brief Constructs the implementation.
*/
JSONConfig::Impl::Impl() = default;

retdec::config::Function *JSONConfig::Impl::getConfigFunctionByName(
		const std::string &name) {
	return config.functions.getFunctionByName(name);
}

// A const overload of getConfigFunctionByName().
const retdec::config::Function *JSONConfig::Impl::getConfigFunctionByName(
		const std::string &name) const {
	return config.functions.getFunctionByName(name);
}

const retdec::config::Object &JSONConfig::Impl::getConfigGlobalVariableByNameOrEmptyVariable(
		const std::string &name) const {
	static const retdec::config::Object emptyGlobalVariable(
		"no-name",
		retdec::config::Storage::undefined()
	);
	auto g = config.globals.getObjectByName(name);
	return g ? *g : emptyGlobalVariable;
}

const retdec::config::Object *JSONConfig::Impl::getConfigRegisterByName(
		const std::string &name) const {
	return config.registers.getObjectByName(name);
}

const retdec::config::Function &JSONConfig::Impl::getConfigFunctionByNameOrEmptyFunction(
		const std::string &name) const {
	static const retdec::config::Function emptyFunction(""s);
	auto f = getConfigFunctionByName(name);
	return f ? *f : emptyFunction;
}

const retdec::config::Class *JSONConfig::Impl::getConfigClassByName(
		const std::string &name) const {
	return config.classes.getElementById(name);
}

std::string JSONConfig::Impl::getNameOfRegister(const retdec::config::Object &reg) const {
	// Each register has a name set in its storage. However, this name may be
	// just our internal LLVM IR name. To get the real name, we have to perform
	// another check.
	auto name = reg.getStorage().getRegisterName();

	auto realReg = getConfigRegisterByName(name);
	if (!realReg) {
		return name;
	}

	auto realName = realReg->getStorage().getRegisterName();
	return !realName.empty() ? realName : name;
}

const retdec::config::Class &JSONConfig::Impl::getConfigClassByNameOrEmptyClass(
		const std::string &name) const {
	static const retdec::config::Class emptyClass(""s);
	auto c = getConfigClassByName(name);
	return c ? *c : emptyClass;
}

JSONConfig::JSONConfig(): impl(std::make_unique<Impl>()) {}

JSONConfig::~JSONConfig() = default;

/**
* @brief Parses and returns a config from the given file.
*
* @throw JSONConfigFileNotFoundError when the file does not exist.
* @throw JSONConfigParsingError when there is a parsing error.
*/
UPtr<JSONConfig> JSONConfig::fromFile(const std::string &path) {
	// We cannot use std::make_unique() because JSONConfig() is private.
	auto config = UPtr<JSONConfig>(new JSONConfig());
	config->impl->path = path;
	try {
		config->impl->config.readJsonFile(path);
	} catch (const retdec::config::FileNotFoundException &ex) {
		throw JSONConfigFileNotFoundError(ex.what());
	} catch (const retdec::config::Exception &ex) {
		throw JSONConfigParsingError(ex.what());
	}
	return config;
}

/**
* @brief Parses and returns a config from the given JSON string.
*
* @throw JSONConfigParsingError when there is a parsing error.
*/
UPtr<JSONConfig> JSONConfig::fromString(const std::string &str) {
	// We cannot use std::make_unique() because JSONConfig() is private.
	auto config = UPtr<JSONConfig>(new JSONConfig());
	try {
		config->impl->config.readJsonString(str);
	} catch (const retdec::config::Exception &ex) {
		throw JSONConfigParsingError(ex.what());
	}
	return config;
}

/**
* @brief Returns an empty config.
*/
UPtr<JSONConfig> JSONConfig::empty() {
	// We cannot use std::make_unique() because JSONConfig() is private.
	return UPtr<JSONConfig>(new JSONConfig());
}

void JSONConfig::saveTo(const std::string &path) {
	impl->config.generateJsonFile(path);
}

void JSONConfig::dump() {
	// The string returned from generateJsonString() is already ended with a
	// new line, so do not emit an additional '\n'.
	llvm::errs() << impl->config.generateJsonString();
}

bool JSONConfig::isGlobalVarStoringWideString(const std::string &var) const {
	const auto &g = impl->getConfigGlobalVariableByNameOrEmptyVariable(var);
	return g.type.isWideString();
}

std::string JSONConfig::comesFromGlobalVar(const std::string &func,
		const std::string &var) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	auto v = f.locals.getObjectByName(var);
	return v && v->getStorage().isRegister() ?
		impl->getNameOfRegister(*v) : std::string();
}

std::string JSONConfig::getRegisterForGlobalVar(const std::string &var) const {
	const auto reg = impl->getConfigRegisterByName(var);
	if (!reg) {
		return {};
	}

	std::string registerName;
	bool inRegister = reg->getStorage().isRegister(registerName);
	return inRegister ? registerName : std::string();
}

std::string JSONConfig::getDetectedCryptoPatternForGlobalVar(const std::string &var) const {
	const auto &g = impl->getConfigGlobalVariableByNameOrEmptyVariable(var);
	return g.getCryptoDescription();
}

std::string JSONConfig::getRealNameForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.getRealName();
}

AddressRange JSONConfig::getAddressRangeForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	auto startAddress = f.getStart();
	auto endAddress = f.getEnd();
	if (startAddress.isUndefined() || endAddress.isUndefined()) {
		return NO_ADDRESS_RANGE;
	}

	return AddressRange(startAddress.getValue(), endAddress.getValue());
}

LineRange JSONConfig::getLineRangeForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	auto startLine = f.getStartLine();
	auto endLine = f.getEndLine();
	if (startLine.isUndefined() || endLine.isUndefined()) {
		return NO_LINE_RANGE;
	}

	return LineRange(startLine.getValue(), endLine.getValue());
}

bool JSONConfig::isUserDefinedFunc(const std::string &func) const {
	// We cannot use getConfigFunctionByNameOrEmptyFunction() because config
	// functions are user-defined by default.
	const auto f = impl->getConfigFunctionByName(func);
	return f ? f->isUserDefined() : false;
}

bool JSONConfig::isStaticallyLinkedFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.isStaticallyLinked();
}

bool JSONConfig::isDynamicallyLinkedFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.isDynamicallyLinked();
}

bool JSONConfig::isSyscallFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.isSyscall();
}

bool JSONConfig::isInstructionIdiomFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.isIdiom();
}

bool JSONConfig::isExportedFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.isExported();
}

void JSONConfig::markFuncAsStaticallyLinked(const std::string &func) {
	auto f = impl->getConfigFunctionByName(func);
	if (f) {
		f->setIsStaticallyLinked();
	}
}

std::string JSONConfig::getDeclarationStringForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return trim(f.getDeclarationString());
}

std::string JSONConfig::getCommentForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return unifyLineEnds(trim(f.getComment()));
}

StringSet JSONConfig::getDetectedCryptoPatternsForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.usedCryptoConstants;
}

std::string JSONConfig::getWrappedFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.getWrappedFunctionName();
}

std::string JSONConfig::getDemangledNameOfFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.getDemangledName();
}

StringSet JSONConfig::getFuncsFixedWithLLVMIRFixer() const {
	StringSet fixedFuncs;
	for (const auto &addrFuncPair : impl->config.functions) {
		auto &func = addrFuncPair.second;
		if (func.isFixed()) {
			fixedFuncs.insert(func.getName());
		}
	}
	return fixedFuncs;
}

StringSet JSONConfig::getClassNames() const {
	StringSet classNames;
	for (const auto &c : impl->config.classes) {
		classNames.insert(c.getName());
	}
	return classNames;
}

std::string JSONConfig::getClassForFunc(const std::string &func) const {
	for (const auto &c : impl->config.classes) {
		if (c.hasFunction(func)) {
			return c.getName();
		}
	}
	return {};
}

std::string JSONConfig::getTypeOfFuncInClass(const std::string &func,
		const std::string &cl) const {
	const auto &c = impl->getConfigClassByNameOrEmptyClass(cl);
	if (c.hasConstructor(func)) {
		return "constructor";
	} else if (c.hasDestructor(func)) {
		return "destructor";
	} else if (c.hasMethod(func)) {
		return "member function";
	} else if (c.hasVirtualMethod(func)) {
		return "virtual member function";
	}
	return {};
}

StringVector JSONConfig::getBaseClassNames(const std::string &cl) const {
	const auto &c = impl->getConfigClassByNameOrEmptyClass(cl);
	return c.getSuperClasses();
}

std::string JSONConfig::getDemangledNameOfClass(const std::string &cl) const {
	const auto &c = impl->getConfigClassByNameOrEmptyClass(cl);
	return c.getDemangledName();
}

bool JSONConfig::isDebugInfoAvailable() const {
	// Global variables.
	for (const auto &nameVarPair : impl->config.globals) {
		const auto &v = nameVarPair.second;
		if (v.isFromDebug()) {
			return true;
		}
	}

	// Functions.
	for (const auto &addrFuncPair : impl->config.functions) {
		const auto &func = addrFuncPair.second;
		if (func.isFromDebug()) {
			return true;
		}

		// Module names and line ranges.
		if (!func.getSourceFileName().empty() || func.getEndLine() > 0) {
			return true;
		}

		// Parameters.
		for (const auto &v : func.parameters) {
			if (v.isFromDebug()) {
				return true;
			}
		}

		// Local variables.
		for (const auto &nameVarPair : func.locals) {
			const auto &v = nameVarPair.second;
			if (v.isFromDebug()) {
				return true;
			}
		}
	}

	return false;
}

std::string JSONConfig::getDebugModuleNameForFunc(const std::string &func) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	return f.getSourceFileName();
}

StringSet JSONConfig::getDebugModuleNames() const {
	StringSet moduleNames;
	for (const auto &addrFuncPair : impl->config.functions) {
		const auto &func = addrFuncPair.second;
		const auto &moduleName = func.getSourceFileName();
		if (!moduleName.empty()) {
			moduleNames.insert(moduleName);
		}
	}
	return moduleNames;
}

std::string JSONConfig::getDebugNameForGlobalVar(const std::string &var) const {
	auto v = impl->config.globals.getObjectByName(var);
	return v && v->isFromDebug() ? v->getRealName() : std::string();
}

std::string JSONConfig::getDebugNameForLocalVar(const std::string &func,
		const std::string &var) const {
	const auto &f = impl->getConfigFunctionByNameOrEmptyFunction(func);
	auto v = f.locals.getObjectByName(var);
	if (!v) {
		v = f.parameters.getObjectByName(var);
	}
	return v && v->isFromDebug() ? v->getRealName() : std::string();
}

StringSet JSONConfig::getPrefixesOfFuncsToBeRemoved() const {
	return impl->config.parameters.frontendFunctions;
}

std::string JSONConfig::getFrontendRelease() const {
	return impl->config.getFrontendVersion();
}

std::size_t JSONConfig::getNumberOfFuncsDetectedInFrontend() const {
	return impl->config.functions.size();
}

std::string JSONConfig::getDetectedCompilerOrPacker() const {
	const auto compilerOrPacker = impl->config.tools.getToolMostSignificant();
	if (!compilerOrPacker) {
		return {};
	}

	auto name = compilerOrPacker->getName();
	auto version = compilerOrPacker->getVersion();
	return version.empty() ? name : name + " (" + version + ")";
}

std::string JSONConfig::getDetectedLanguage() const {
	std::stringstream detectedLanguage;

	// There may be multiple languages.
	for (const auto &lang : impl->config.languages) {
		if (detectedLanguage.tellp() > 0) {
			detectedLanguage << ", ";
		}

		// Name.
		detectedLanguage << lang.getName();

		// Bytecode language?
		if (lang.isBytecode()) {
			detectedLanguage << " (bytecode)";
		}

		// Number of modules in which the language was detected.
		if (lang.isModuleCountSet()) {
			detectedLanguage << " "
				<< "("
				<< lang.getModuleCount()
				<< " module"
				<< (lang.getModuleCount() > 1 ? "s" : "")
				<< ")";
		}
	}

	return detectedLanguage.str();
}

StringSet JSONConfig::getSelectedButNotFoundFuncs() const {
	return impl->config.parameters.selectedNotFoundFunctions;
}

} // namespace llvmir2hll
} // namespace retdec
