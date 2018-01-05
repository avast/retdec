/**
* @file include/retdec/llvmir2hll/ir/function_builder.h
* @brief A builder providing a simple way of creating functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FUNCTION_BUILDER_H
#define RETDEC_LLVMIR2HLL_IR_FUNCTION_BUILDER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Function;
class Statement;
class Type;
class Variable;

/**
* @brief A builder providing a simple way of creating functions.
*
* It implements a simplified version of the <a
* href="http://en.wikipedia.org/wiki/Builder_pattern">Builder design
* pattern</a> with a <a
* href="http://en.wikipedia.org/wiki/Fluent_interface">fluent interface</a>.
*
* @par Usage Example
* The following code constructs a definition of a function named @c "myFunc"
* with an empty body and the single given parameter:
* @code
* ShPtr<Function> myFunc(
*     FunctionBuilder("myFunc")
*         .definitionWithEmptyBody()
*         .withParam(param)
*         .build()
* );
* @endcode
* Since the return type has not been specified, the default one is used (see
* the description of FunctionBuilder() for more information).
*/
class FunctionBuilder: private retdec::utils::NonCopyable {
public:
	FunctionBuilder(const std::string &funcName = "");

	/// @name Specifiers
	/// @{
	FunctionBuilder &definitionWithEmptyBody();
	FunctionBuilder &definitionWithBody(ShPtr<Statement> body);
	FunctionBuilder &withRetType(ShPtr<Type> retType);
	FunctionBuilder &withParam(ShPtr<Variable> param);
	FunctionBuilder &withLocalVar(ShPtr<Variable> var);
	FunctionBuilder &withVarArg();
	/// @}

	ShPtr<Function> build();

private:
	ShPtr<Function> releaseFuncAndInvalidateBuilder();

private:
	/// A function that is being built.
	ShPtr<Function> func;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
