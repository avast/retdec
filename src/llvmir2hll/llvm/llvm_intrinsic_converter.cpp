/**
* @file src/llvmir2hll/llvm/llvm_intrinsic_converter.cpp
* @brief Implementation of LLVMIntrinsicConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_intrinsic_converter.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using retdec::utils::endsWith;
using retdec::utils::hasItem;
using retdec::utils::startsWith;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Chooses a type-aware name for the given function.
*
* This function assumes that @a func is a floating-point function.
*/
std::string getTypeAwareNameFor(ShPtr<Function> func, const std::string &baseName) {
	const auto &funcName = func->getInitialName();
	if (endsWith(funcName, ".f32")) {
		// e.g. float fabsf(float x);
		return baseName + "f";
	} else if (endsWith(funcName, ".f64")) {
		// e.g. double fabs(double x);
		return baseName;
	} else if (endsWith(funcName, ".f80") || endsWith(funcName, ".f128")) {
		// e.g. long double fabsl(long double x);
		return baseName + "l";
	}

	// No info.
	return baseName;
}

} // anonymous namespace

/**
* @brief Constructs a new converter.
*
* See convert() for the description of all parameters and preconditions.
*/
LLVMIntrinsicConverter::LLVMIntrinsicConverter(ShPtr<Module> module):
	OrderedAllVisitor(), module(module), renamedFuncNames() {}

/**
* @brief Destructs the converter.
*/
LLVMIntrinsicConverter::~LLVMIntrinsicConverter() {}

/**
* @brief Converts LLVM intrinsic functions in @a module into standard-C-library
*        functions.
*
* @param[in,out] module Module in which LLVM intrinsic functions are converted.
*
* @par Preconditions
*  - @a module is non-null
*/
void LLVMIntrinsicConverter::convert(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<LLVMIntrinsicConverter> converter(new LLVMIntrinsicConverter(module));
	converter->performConversion();
}

/**
* @brief Performs the conversion of LLVM intrinsic functions into functions
*        from the standard C library.
*
* See the class description for more information.
*/
void LLVMIntrinsicConverter::performConversion() {
	// Go through all function declarations to find LLVM intrinsic functions.
	// When an intrinsic is found, we try to convert its name into a C function's name.
	for (auto i = module->func_declaration_begin(),
			e = module->func_declaration_end(); i != e; ++i) {
		if (isIntrinsicFunc(*i)) {
			convertIntrinsicFuncName(*i);
		}
	}

	// Go through all function definitions and if necessary, modify calls to
	// these intrinsic functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		visitStmt((*i)->getBody());
	}
}

/**
* @brief Returns @c true if the given function is an LLVM intrinsic function,
*        @c false otherwise.
*/
bool LLVMIntrinsicConverter::isIntrinsicFunc(ShPtr<Function> func) const {
	// See the class description for the format of LLVM intrinsic function
	// names.
	return startsWith(func->getInitialName(), "llvm.");
}

/**
* @brief If supported, converts the given LLVM intrinsic function's name into
*        an appropriate name of a standard-C-library function.
*
* @par Preconditions
*  - @a func is an LLVM intrinsic function
*/
void LLVMIntrinsicConverter::convertIntrinsicFuncName(ShPtr<Function> func) {
	// Check whether we support such an intrinsic. If so, rename it.
	const std::string &funcName(func->getInitialName());

	// llvm.memcpy.*
	if (startsWith(funcName, "llvm.memcpy.")) {
		renameIntrinsicFunc(func, "memcpy");
	}
	// llvm.memmove.*
	else if (startsWith(funcName, "llvm.memmove.")) {
		renameIntrinsicFunc(func, "memmove");
	}
	// llvm.memset.*
	else if (startsWith(funcName, "llvm.memset.")) {
		renameIntrinsicFunc(func, "memset");
	}
	// llvm.sqrt.*
	else if (startsWith(funcName, "llvm.sqrt.")) {
		renameFloatIntrinsicFunc(func, "sqrt");
	}
	// llvm.sin.*
	else if (startsWith(funcName, "llvm.sin.")) {
		renameFloatIntrinsicFunc(func, "sin");
	}
	// llvm.cos.*
	else if (startsWith(funcName, "llvm.cos.")) {
		renameFloatIntrinsicFunc(func, "cos");
	}
	// llvm.pow.*
	else if (startsWith(funcName, "llvm.pow.")) {
		renameFloatIntrinsicFunc(func, "pow");
	}
	// llvm.exp.*
	else if (startsWith(funcName, "llvm.exp.")) {
		renameFloatIntrinsicFunc(func, "exp");
	}
	// llvm.log.*
	else if (startsWith(funcName, "llvm.log.")) {
		renameFloatIntrinsicFunc(func, "log");
	}
	// llvm.fma.*
	else if (startsWith(funcName, "llvm.fma.")) {
		renameFloatIntrinsicFunc(func, "fma");
	}
	// llvm.fabs.*
	else if (startsWith(funcName, "llvm.fabs.")) {
		renameFloatIntrinsicFunc(func, "fabs");
	}
	// llvm.floor.*
	else if (startsWith(funcName, "llvm.floor.")) {
		renameFloatIntrinsicFunc(func, "floor");
	}
	// llvm.trap
	else if (startsWith(funcName, "llvm.trap")) {
		renameIntrinsicFunc(func, "abort");
	}
	// llvm.copysign
	else if (startsWith(funcName, "llvm.copysign")) {
		renameFloatIntrinsicFunc(func, "copysign");
	}
}

/**
* @brief Renames the given LLVM intrinsic function.
*
* If there are some metadata for the changed function, it attaches them to the
* renamed function. Also updates renamedFuncNames.
*/
void LLVMIntrinsicConverter::renameIntrinsicFunc(ShPtr<Function> func,
		const std::string &newName) {
	func->setName(newName);
	renamedFuncNames.insert(newName);
}

/**
* @brief Renames the given LLVM floating-point intrinsic function.
*
* It differs from renameIntrinsicFunc() in that it chooses a proper "overload",
* e.g. for @c llvm.fabs.32, it renames the function to @c fabsf, because @c
* fabsf is @c fabs for @c float (@c fabs is for @c double).
*/
void LLVMIntrinsicConverter::renameFloatIntrinsicFunc(ShPtr<Function> func,
		const std::string &baseName) {
	renameIntrinsicFunc(func, getTypeAwareNameFor(func, baseName));
}

/**
* @brief Removes the last @a n arguments from @a expr and the last @a n
*        parameters from the function declaration @a func.
*
* Arguments/parameters are only removed if the original number of
* arguments/parameters is @a m.
*/
void LLVMIntrinsicConverter::trimLastNArgsAndParams(ShPtr<CallExpr> expr,
		ShPtr<Function> func, unsigned m, unsigned n) {
	// Alter the called expression.
	ExprVector args(expr->getArgs());
	if (args.size() == m) {
		for (unsigned i = 0; i < n; ++i) {
			args.pop_back();
		}
		expr->setArgs(args);
	}

	// Alter the function declaration.
	VarVector params(func->getParams());
	if (params.size() == m) {
		for (unsigned i = 0; i < n; ++i) {
			params.pop_back();
		}
		func->setParams(params);
	}
}

void LLVMIntrinsicConverter::visit(ShPtr<CallExpr> expr) {
	// Check whether we have to change the call. If so, then we change it.

	// The called expression has to be a variable.
	ShPtr<Variable> funcVar(cast<Variable>(expr->getCalledExpr()));
	if (!funcVar) {
		OrderedAllVisitor::visit(expr);
		return;
	}

	// It has to be a call to a changed intrinsic.
	const std::string &funcName(funcVar->getName());
	if (!hasItem(renamedFuncNames, funcName)) {
		OrderedAllVisitor::visit(expr);
		return;
	}

	// Check whether we have to change the call. If so, then change it.

	// llvm.memcpy.*, llvm.memmove.*, and llvm.memset.*
	if (funcName == "memcpy" || funcName == "memmove" || funcName == "memset") {
		// There should be 5 arguments/parameters. We have to omit the last 2.
		trimLastNArgsAndParams(expr, module->getFuncByName(funcName), 5, 2);
	}

	// Other intrinsics don't have to be changed.

	OrderedAllVisitor::visit(expr);
	return;
}

} // namespace llvmir2hll
} // namespace retdec
