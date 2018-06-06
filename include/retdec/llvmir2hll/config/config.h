/**
* @file include/retdec/llvmir2hll/config/config.h
* @brief Base class for all configs.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_CONFIG_CONFIG_H
#define RETDEC_LLVMIR2HLL_CONFIG_CONFIG_H

#include <cstddef>
#include <exception>
#include <set>
#include <string>

#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Base class for all config-related errors.
*/
class ConfigError: public std::exception {
public:
	ConfigError(const std::string &message);

	virtual const char *what() const noexcept override;

	const std::string &getMessage() const noexcept;

private:
	std::string message;
};

/**
* @brief Base class for all configs.
*/
class Config: private retdec::utils::NonCopyable {
public:
	virtual ~Config();

	/// @name Loading and Saving
	/// @{

	/**
	* @brief Saves the config to the given file.
	*/
	virtual void saveTo(const std::string &path) = 0;

	/// @}

	/// @name Debugging
	/// @{

	/**
	* @brief Dumps the contents of the config to the standard error.
	*/
	virtual void dump() = 0;

	/// @}

	/// @name Variables
	/// @{

	/**
	* @brief Stores the given global variable a wide string?
	*/
	virtual bool isGlobalVarStoringWideString(const std::string &var) const = 0;

	/**
	* @brief Returns the name of a global variable from which the given local
	*        variable comes from.
	*
	* If the given variable does not come from a global variable, the empty string
	* is returned.
	*/
	virtual std::string comesFromGlobalVar(const std::string &func,
		const std::string &var) const = 0;

	/**
	* @brief Returns the name of the register corresponding to the given global
	*        variable.
	*
	* If the given variable is not a global variable or it does not have any
	* register name attached, the empty string is returned.
	*/
	virtual std::string getRegisterForGlobalVar(const std::string &var) const = 0;

	/**
	* @brief Returns a description of the detected cryptographic pattern for
	*        the given global variable.
	*
	* If the given variable is not a global variable or it does not have any
	* cryptographic-pattern description attached, the empty string is returned.
	*/
	virtual std::string getDetectedCryptoPatternForGlobalVar(const std::string &var) const = 0;

	/// @}

	/// @name Functions
	/// @{

	/**
	* @brief Returns the real name of the given function.
	*
	* If the given function does not have a real name, the empty string is
	* returned.
	*/
	virtual std::string getRealNameForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns the address range of the given function.
	*
	* If the given function does not have an address range, @c NO_ADDRESS_RANGE
	* is returned.
	*/
	virtual AddressRange getAddressRangeForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns the line range of the given function.
	*
	* If the given function does not have a line range, @c NO_LINE_RANGE is
	* returned.
	*/
	virtual LineRange getLineRangeForFunc(const std::string &func) const = 0;

	/**
	* @brief Is the given function user-defined?
	*/
	virtual bool isUserDefinedFunc(const std::string &func) const = 0;

	/**
	* @brief Is the given function statically linked?
	*/
	virtual bool isStaticallyLinkedFunc(const std::string &func) const = 0;

	/**
	* @brief Is the given function dynamically linked?
	*/
	virtual bool isDynamicallyLinkedFunc(const std::string &func) const = 0;

	/**
	* @brief Is the given function, in fact, a system call?
	*/
	virtual bool isSyscallFunc(const std::string &func) const = 0;

	/**
	* @brief Did the given function, in fact, come from an instruction idiom?
	*/
	virtual bool isInstructionIdiomFunc(const std::string &func) const = 0;

	/**
	* @brief Is the given function exported?
	*
	* A function is @e exported if it is marked as such in the input binary
	* file (e.g. a DLL exports its functions).
	*/
	virtual bool isExportedFunc(const std::string &func) const = 0;

	/**
	* @brief Marks the given function as statically linked.
	*
	* If there is no such function, nothing is done.
	*/
	virtual void markFuncAsStaticallyLinked(const std::string &func) = 0;

	/**
	* @brief Returns a C declaration string for the given function.
	*
	* If the function does not exist or does not have any C declaration string
	* attached, the empty string is returned.
	*/
	virtual std::string getDeclarationStringForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns a comment for the given functions.
	*
	* If the given function does not have a comment or it is empty, the empty
	* string is returned.
	*
	* Line breaks inside the comment are unified to LF.
	*/
	virtual std::string getCommentForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns a set of names of detected cryptographic patterns
	*        that the given function uses.
	*
	* If the given function does not exist or does not use any cryptographic
	* patterns, the empty set is returned.
	*/
	virtual StringSet getDetectedCryptoPatternsForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns the name of a function that @a func wraps.
	*
	* A function @c A @e wraps another function @c B when the only thing @c A
	* does is that it calls @c B (with an optional prologue/epilogue).
	*
	* If @a func does not exist or it is not a wrapper, the empty string is
	* returned.
	*/
	virtual std::string getWrappedFunc(const std::string &func) const = 0;

	/**
	* @brief Returns the demangled named of the given function.
	*
	* If there is no such function or its name cannot be demangled, the empty
	* string is returned.
	*/
	virtual std::string getDemangledNameOfFunc(const std::string &func) const = 0;

	/**
	* @brief Returns a set of functions that were fixed by our LLVM-IR fixer.
	*/
	virtual StringSet getFuncsFixedWithLLVMIRFixer() const = 0;

	/// @}

	/// @name Classes
	/// @{

	/**
	* @brief Returns the set of found class names.
	*/
	virtual StringSet getClassNames() const = 0;

	/**
	* @brief Returns the name of a class to which the given function belongs.
	*
	* If @a func does not belong to any class, the empty string is returned. If
	* @a func belongs to multiple classes, the name of the first class is
	* returned.
	*/
	virtual std::string getClassForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns the type of the given function in the given class.
	*
	* The returned value is a textual representation, e.g. "constructor" or
	* "virtual member function".
	*
	* If @a func does not belong to any class, the empty string is returned.
	*/
	virtual std::string getTypeOfFuncInClass(const std::string &func,
		const std::string &cl) const = 0;

	/**
	* @brief Returns the names of base classes of the given class.
	*
	* If there is no such class, the empty vector is returned.
	*/
	virtual StringVector getBaseClassNames(const std::string &cl) const = 0;

	/**
	* @brief Returns the demangled named of the given class.
	*
	* If there is no such class or its name cannot be demangled, the empty
	* string is returned.
	*/
	virtual std::string getDemangledNameOfClass(const std::string &cl) const = 0;

	/// @}

	/// @name Debug Info
	/// @{

	/**
	* @brief Is Debug info available?
	*/
	virtual bool isDebugInfoAvailable() const = 0;

	/**
	* @brief Returns the name of a module from which the given function
	*        originates.
	*
	* When debug info is not available, the empty string is returned.
	*/
	virtual std::string getDebugModuleNameForFunc(const std::string &func) const = 0;

	/**
	* @brief Returns a set of module names from which functions originate.
	*
	* When debug info is not available, the empty set is returned.
	*/
	virtual StringSet getDebugModuleNames() const = 0;

	/**
	* @brief Returns a name from debug information of the given global
	*        variable.
	*
	* If the variable has no such name attached, the empty string is returned.
	*/
	virtual std::string getDebugNameForGlobalVar(const std::string &var) const = 0;

	/**
	* @brief Returns a name from debug information of the given local variable
	*        from the given function.
	*
	* If the variable has no such name attached, the empty string is returned.
	*/
	virtual std::string getDebugNameForLocalVar(const std::string &func,
		const std::string &var) const = 0;

	/// @}

	/// @name Meta Information
	/// @{

	/**
	* @brief Returns a set of prefixes of functions to be removed.
	*/
	virtual StringSet getPrefixesOfFuncsToBeRemoved() const = 0;

	/**
	* @brief Returns the release of the front-end.
	*
	* Returns the empty string if there is no front-end release.
	*/
	virtual std::string getFrontendRelease() const = 0;

	/**
	* @brief Returns the number of functions detected in the front-end.
	*
	* Returns @c 0 if there are no detected functions.
	*/
	virtual std::size_t getNumberOfFuncsDetectedInFrontend() const = 0;

	/**
	* @brief Returns the detected compiler or packer.
	*
	* Returns the empty string if there is no compiler or packer.
	*/
	virtual std::string getDetectedCompilerOrPacker() const = 0;

	/**
	* @brief Returns the detected language.
	*
	* Returns the empty string if there is no language.
	*/
	virtual std::string getDetectedLanguage() const = 0;

	/**
	* @brief Returns a set of functions that were selected to be decompiled but
	*        were not found.
	*/
	virtual StringSet getSelectedButNotFoundFuncs() const = 0;

	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
