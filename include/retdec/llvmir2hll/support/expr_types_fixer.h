/**
* @file include/retdec/llvmir2hll/support/expr_types_fixer.h
* @brief A visitor for fixing the types in the IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_EXPR_TYPES_FIXER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_EXPR_TYPES_FIXER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Type;

/**
* @brief A visitor for fixing the types in the IR.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*
* This class uses @c ExprTypeAnalysis and do fixations of integer types based on
* statistics from the analysis. Then visits again all expressions and checks that
* signed/unsigned types are corrected. If no, then add some casts to variables.
*
* We have to fix some integer types to signed because all variables are
* unsigned before this fixation.
*
* We need to apply the fixer on the backend IR after it is generated. The @c
* fixTypes() function is called in @c Decompiler.cpp, between the creation of
* the backend IR and optimizations. This fixer have to be used on every place
* where we work with signed or unsigned types.
*
* For example, the following code
* @code
* uint32_t a = -33;
* if (a < 0) { // if icmp instruction was signed
*    ...
* }
* @endcode
* can be changed into
* @code
* int32_t a = -33;
* if (a < 0) {
*    ...
* }
* @endcode
*
* This is a concrete visitor which should not be subclassed.
*/
class ExprTypesFixer final: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~ExprTypesFixer() override;

	static void fixTypes(ShPtr<Module> module);

private:
	ExprTypesFixer();
	void setProbablyTypes(ShPtr<Module> module);
	ShPtr<Expression> exprCheckAndChange(bool isSigned, ShPtr<Expression> expr);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ExtCastExpr> expr) override;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<ModOpExpr> expr) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<LtEqOpExpr> expr) override;
	virtual void visit(ShPtr<GtEqOpExpr> expr) override;
	virtual void visit(ShPtr<LtOpExpr> expr) override;
	virtual void visit(ShPtr<GtOpExpr> expr) override;
	virtual void visit(ShPtr<BitShlOpExpr> expr) override;
	virtual void visit(ShPtr<BitShrOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
