/**
* @file src/llvmir2hll/support/const_symbol_converter.cpp
* @brief Implementation of ConstSymbolConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <vector>

#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/const_symbol_converter.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/// List of symbolic constants.
using ConstSymbolList = std::vector<ShPtr<ConstSymbol>>;

/**
* @brief Tries to obtain a constant integer from the given argument.
*
* If a constant integer cannot be obtained, the null pointer is returned.
*/
ShPtr<ConstInt> getArgAsConstInt(ShPtr<Expression> arg) {
	// Ignore casts. In this way, we can convert, e.g.,
	//
	//     signal(SIGSTOP, (void (*)(int32_t))1);
	//
	// to
	//
	//     signal(SIGSTOP, SIG_IGN);
	//
	// TODO Is this valid under all circumstances?
	ShPtr<Expression> argWithoutCasts(skipCasts(arg));

	// Treat the null pointer as zero (0). In this way, we can convert, e.g.,
	//
	//     signal(SIGSTOP, NULL);
	//
	// to
	//
	//     signal(SIGSTOP, SIG_DFL);
	//
	// when SIG_DFL == 0.
	if (isa<ConstNullPointer>(argWithoutCasts)) {
		// TODO Is the bit width used below correct?
		return ConstInt::create(0, 32);
	}

	return cast<ConstInt>(argWithoutCasts);
}

} // anonymous namespace

/**
* @brief Constructs a new converter.
*
* See convert() for the description of all parameters and preconditions.
*/
ConstSymbolConverter::ConstSymbolConverter(ShPtr<Module> module):
	module(module) {}

/**
* @brief Destructs the converter.
*/
ConstSymbolConverter::~ConstSymbolConverter() {}

/**
* @brief Converts the constants in function calls in the given module into
*        expressions consisting of symbolic names.
*
* @param[in,out] module Module in which the constants are converted.
*
* The constants are taken from the used semantics in @a module.
*
* For example,
* @code
* flock(avocado, 6);
* @endcode
* may be replaced with
* @code
* flock(avocado, LOCK_EX | LOCK_NB); // 6 == 2 | 4
* @endcode
*
* If a call has assigned information from dynamic analysis in @a module, its
* arguments in this information are also converted into symbols (when
* possible).
*
* @par Preconditions
*  - @a module is non-null
*/
void ConstSymbolConverter::convert(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<ConstSymbolConverter> converter(new ConstSymbolConverter(module));
	converter->performConversion();
}

/**
* @brief Performs the conversion of constants into constant symbols.
*
* For more information, see the description of convert().
*/
void ConstSymbolConverter::performConversion() {
	// Visit the bodies of all functions in the module...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		visit(*i);
	}
}

/**
* @brief Tries to convert arguments in the given call into expressions
*        consisting of symbolic names.
*
* @param[in,out] callExpr Called expression.
* @param[in] calledFuncName Name of the function called in @a callExpr.
*
* @par Preconditions
*  - @a callExpr is non-null
*  - @a calledFuncName is not empty
*  - @a calledFuncName is the name of a function declaration, not definition
*/
void ConstSymbolConverter::convertArgsToSymbolicNames(
		ShPtr<CallExpr> callExpr, const std::string &calledFuncName) {
	PRECONDITION_NON_NULL(callExpr);
	PRECONDITION(!calledFuncName.empty(),
		"the name of the called function cannot be empty");

	// For every argument of the call...
	unsigned currArgPos = 1;
	const ExprVector &args(callExpr->getArgs());
	for (auto i = args.begin(), e = args.end(); i != e; ++i, ++currArgPos) {
		ShPtr<ConstInt> argAsConstInt(getArgAsConstInt(*i));
		if (!argAsConstInt) {
			// Skip non-constant-integer arguments.
			continue;
		}

		Maybe<IntStringMap> symbolicNamesMap(
			module->getSemantics()->getSymbolicNamesForParam(
				calledFuncName, currArgPos));
		if (!symbolicNamesMap) {
			// Skip arguments for which we don't have symbolic names.
			continue;
		}

		// Perform the conversion of the argument.
		ShPtr<Expression> newArg(convertArgToSymbolicNames(
			argAsConstInt, symbolicNamesMap.get()));
		callExpr->setArg(currArgPos - 1, newArg); // index starts at 0
	}
}

/**
* @brief Tries to convert the given argument into an expression consisting of
*        symbolic names.
*
* @param[in] arg Argument to be converted.
* @param[in] symbolicNamesMap The used mapping of integers into symbols.
*
* If the argument cannot be decomposed into an expression of symbolic names, it
* is returned unchanged. Otherwise, the new expression is returned.
*/
ShPtr<Expression> ConstSymbolConverter::convertArgToSymbolicNames(
		ShPtr<ConstInt> arg, const IntStringMap &symbolicNamesMap) {
	int argValue = arg->getValue().getSExtValue();

	// If there is a direct mapping of the argument into a symbol, we are done,
	// i.e. there is nothing to compute since we may directly use the symbol.
	auto argValueIter = symbolicNamesMap.find(argValue);
	if (argValueIter != symbolicNamesMap.end()) {
		return ConstSymbol::create(argValueIter->second, arg);
	}

	// The argument's value is compound, i.e. it cannot be represented as just
	// a single symbolic name. Therefore, we try to compute an expression
	// consisting of symbolic names that characterizes the argument.

	// Non-positive arguments cannot be represented as in a compound way.
	if (argValue <= 0) {
		return arg;
	}

	// Try to decompose the argument to the form `x | y | z | ...`.
	// TODO Should we also consider `bit and` or `bit xor`?
	ConstSymbolList symbolicNames;
	for (const auto &p : symbolicNamesMap) {
		// Check whether the value of the current symbol is included in the
		// original argument's value. If so, use the symbol.
		if (argValue & p.first) {
			symbolicNames.push_back(ConstSymbol::create(p.second,
				ConstInt::create(p.first, cast<IntType>(arg->getType())->getSize(),
					arg->isSigned())));
		}
	}

	// Check whether the bit or of the decomposed list of symbolic names gives
	// us back the original argument.
	int computedArgValue = 0;
	for (const auto &name : symbolicNames) {
		computedArgValue |= cast<ConstInt>(name->getValue())->getValue().getZExtValue();
	}
	if (argValue != computedArgValue) {
		// The decomposition is invalid.
		return arg;
	}

	// Create the resulting expression by or-ing the obtained symbols.
	ShPtr<BitOrOpExpr> newArg;
	for (ConstSymbolList::size_type i = 0, e = symbolicNames.size(); i < e; ++i) {
		if (newArg) {
			newArg = BitOrOpExpr::create(newArg, symbolicNames[i]);
		} else {
			newArg = BitOrOpExpr::create(symbolicNames[i], symbolicNames[i + 1]);
			// Since we have added two symbols, we have to increment i once
			// more.
			++i;
		}
	}
	return newArg;
}

void ConstSymbolConverter::visit(ShPtr<CallExpr> expr) {
	// Visit nested calls (if any).
	OrderedAllVisitor::visit(expr);

	ShPtr<Variable> callVar(cast<Variable>(expr->getCalledExpr()));
	if (!callVar) {
		// Indirect call -> nothing to do.
		return;
	}

	ShPtr<Function> calledFunc(module->getFuncByName(callVar->getName()));
	if (!calledFunc || !calledFunc->isDeclaration()) {
		// Not a declared function -> nothing to do.
		return;
	}

	convertArgsToSymbolicNames(expr, calledFunc->getName());
}

} // namespace llvmir2hll
} // namespace retdec
