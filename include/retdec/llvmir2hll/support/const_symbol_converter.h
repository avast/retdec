/*
* @file include/retdec/llvmir2hll/support/const_symbol_converter.h
* @brief Converter of constants into their symbolic names.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_CONST_SYMBOL_CONVERTER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_CONST_SYMBOL_CONVERTER_H

#include <string>

#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
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
		private retdec::utils::NonCopyable {
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
} // namespace retdec

#endif
