/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter.h
* @brief A base class for all converters of LLVM IR to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class Module;
class Pass;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Config;
class Module;
class Semantics;

/**
* @brief A base class for all converters of LLVM IR to BIR.
*
* This class should be used as a base class for all converters of LLVM IR to
* BIR.
*
* To implement a new converter:
*  - subclass this class and implement getId() and convert()
*  - create a static create() function and register the converter at
*    LLVMIR2BIRConverterFactory (see the implementation of existing subclasses)
*
* Instances of this class have reference object semantics.
*/
class LLVMIR2BIRConverter: private retdec::utils::NonCopyable {
public:
	virtual ~LLVMIR2BIRConverter();

	/**
	* @brief Returns the ID of the converter.
	*/
	virtual std::string getId() const = 0;

	/**
	* @brief Converts the given LLVM module into a module in BIR.
	*
	* @param[in] llvmModule LLVM module to be converted.
	* @param[in] moduleName Identifier of the resulting module.
	* @param[in] semantics The used semantics.
	* @param[in] config Configuration for the module.
	* @param[in] enableDebug If @c true, debugging messages will be emitted.
	*
	* @par Preconditions
	*  - both @a llvmModule and @a semantics are non-null
	*/
	virtual ShPtr<Module> convert(llvm::Module *llvmModule,
		const std::string &moduleName, ShPtr<Semantics> semantics,
		ShPtr<Config> config, bool enableDebug = false) = 0;

	/// @name Options
	/// @{
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

protected:
	LLVMIR2BIRConverter(llvm::Pass *basePass);

protected:
	/// Pass that have instantiated the converter.
	llvm::Pass *basePass;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
