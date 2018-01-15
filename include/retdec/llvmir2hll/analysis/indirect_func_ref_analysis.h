/**
* @file include/retdec/llvmir2hll/analysis/indirect_func_ref_analysis.h
* @brief Analysis of functions that are referenced outside of direct calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_INDIRECT_FUNC_REF_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_INDIRECT_FUNC_REF_ANALYSIS_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Analysis of functions that are referenced outside of direct calls.
*
* Given a module, this class can be used to find functions that are referenced
* outside of direct function calls. For example, consider the following code:
* @code
* void func(int argc) {
*     printf("%d\n", main);
* }
*
* int main(int argc, char **argv) {
*     func(argc);
*     return 0;
* }
* @endcode
* Here, @c main is indirectly referenced in @c func. This piece of information
* can be used to generate prototypes for such functions. In the code above, a
* prototype for @c main has to be given to prevent C syntax checker from
* complaining. Indeed, <tt>gcc -std=c99</tt> emits the following error when a
* prototype for @c main is not given prior to the definition of @c func:
* @code
* error: 'main' undeclared (first use in this function)
* @endcode
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class IndirectFuncRefAnalysis: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~IndirectFuncRefAnalysis() override;

	static FuncSet getIndirectlyReferencedFuncs(ShPtr<Module> module);
	static bool isIndirectlyReferenced(ShPtr<Module> module,
		ShPtr<Function> func);

private:
	IndirectFuncRefAnalysis(ShPtr<Module> module);

	void performAnalysis();
	void visitAllFuncs();
	bool shouldCalledExprBeVisited(ShPtr<Expression> expr);
	void visitArgs(const ExprVector &args);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<Variable> var) override;
	/// @}

private:
	/// The analyzed module.
	ShPtr<Module> module;

	/// The currently visited function.
	ShPtr<Function> currFunc;

	/// Indirectly referenced functions.
	FuncSet indirRefdFuncs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
