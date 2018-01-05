/**
* @file src/llvmir2hll/ir/function_builder.cpp
* @brief The implementation of FunctionBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/// An error message for the situation when build() has already been called.
const std::string BUILD_ALREADY_CALLED_ERROR_MSG(
	"build() has already been called for this builder");

/**
* @brief Creates a default function (see the description of FunctionBuilder()
*        for more details).
*/
ShPtr<Function> createDefaultFunction(const std::string &funcName) {
	return Function::create(VoidType::create(), funcName, VarVector());
}

} // anonymous namespace

/**
* @brief Constructs a builder providing the default function named @a funcName.
*
* If you call build() right after the builder is created, it will return a
* function declaration named @a funcName with the void return type and without
* any parameters.
*/
FunctionBuilder::FunctionBuilder(const std::string &funcName):
	func(createDefaultFunction(funcName)) {}

/**
* @brief Makes the function a definition with an empty body.
*
* @par Preconditions
*  - build() has not yet been called
*/
FunctionBuilder &FunctionBuilder::definitionWithEmptyBody() {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);

	func->setBody(EmptyStmt::create());
	return *this;
}

/**
* @brief Makes the function a definition with the given body.
*
* @par Preconditions
*  - build() has not yet been called
*  - @a body has to be non-null
*/
FunctionBuilder &FunctionBuilder::definitionWithBody(ShPtr<Statement> body) {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);
	PRECONDITION_NON_NULL(body);

	func->setBody(body);
	return *this;
}

/**
* @brief Returns the built function.
*
* This function can be called at most once. It is an error to call it once
* again after it has already been called.
*/
ShPtr<Function> FunctionBuilder::build() {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);

	return releaseFuncAndInvalidateBuilder();
}

/**
* @brief Makes the function to have the given return type.
*
* @par Preconditions
*  - build() has not yet been called
*  - @a retType has to be non-null
*/
FunctionBuilder &FunctionBuilder::withRetType(ShPtr<Type> retType) {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);
	PRECONDITION_NON_NULL(retType);

	func->setRetType(retType);
	return *this;
}

/**
* @brief Adds the given parameter to the function.
*
* @par Preconditions
*  - build() has not yet been called
*  - @a param has to be non-null
*/
FunctionBuilder &FunctionBuilder::withParam(ShPtr<Variable> param) {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);
	PRECONDITION_NON_NULL(param);

	func->addParam(param);
	return *this;
}

/**
* @brief Adds the given local variable to the function.
*
* @par Preconditions
*  - build() has not yet been called
*  - @a var has to be non-null
*/
FunctionBuilder &FunctionBuilder::withLocalVar(ShPtr<Variable> var) {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);
	PRECONDITION_NON_NULL(var);

	func->addLocalVar(var);
	return *this;
}

/**
* @brief Makes the function taking a variable number of arguments.
*
* @par Preconditions
*  - build() has not yet been called
*/
FunctionBuilder &FunctionBuilder::withVarArg() {
	PRECONDITION(func, BUILD_ALREADY_CALLED_ERROR_MSG);

	func->setVarArg();
	return *this;
}

/**
* @brief Releases the built function and invalidates the builder.
*/
ShPtr<Function> FunctionBuilder::releaseFuncAndInvalidateBuilder() {
	ShPtr<Function> funcToReturn(func);
	func.reset();
	return funcToReturn;
}

} // namespace llvmir2hll
} // namespace retdec
