/*
* @file include/llvmir2hll/support/const_symbol_converter.h
* @brief Converter of constants into their symbolic names.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SUPPORT_CONST_SYMBOL_CONVERTER_H
#define LLVMIR2HLL_SUPPORT_CONST_SYMBOL_CONVERTER_H

#include <string>

#include "llvmir2hll/ir/module.h"
#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class Module;

/**
* @brief Converter of constants into their symbolic names.
*
* For more information, see the description of convert().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class ConstSymbolConverter: private OrderedAllVisitor,
		private tl_cpputils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~ConstSymbolConverter() override;

	static void convert(ShPtr<Module> module);

private:
	ConstSymbolConverter(ShPtr<Module> module);

	void performConversion();
	void convertArgsToSymbolicNames(ShPtr<CallExpr> callExpr,
		const std::string &calledFuncName);
	ShPtr<Expression> convertArgToSymbolicNames(ShPtr<ConstInt> arg,
		const IntStringMap &symbolicNamesMap);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	/// @}

private:
	/// Module in which the constants are converted.
	ShPtr<Module> module;
};

} // namespace llvmir2hll

#endif
