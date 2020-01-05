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
	static void convert(Module* module);

private:
	ConstSymbolConverter(Module* module);

	void performConversion();
	void convertArgsToSymbolicNames(CallExpr* callExpr,
		const std::string &calledFuncName);
	Expression* convertArgToSymbolicNames(ConstInt* arg,
		const IntStringMap &symbolicNamesMap);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(CallExpr* expr) override;
	/// @}

private:
	/// Module in which the constants are converted.
	Module* module = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
