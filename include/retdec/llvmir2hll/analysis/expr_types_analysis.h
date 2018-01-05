/**
* @file include/retdec/llvmir2hll/analysis/expr_types_analysis.h
* @brief A visitor for fixing the types in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_EXPR_TYPES_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_EXPR_TYPES_ANALYSIS_H

#include <cstddef>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Expression;

/**
* @brief A visitor for analyzing the types in BIR.
*
* This class is a visitor. It visits expressions in which is information about
* signed/unsigned types. From this information, the analysis creates
* statistics. These statistics are later used in fixing of signed/unsigned
* types.
*
* We need apply the analysis on the backend IR (BIR). The @c analyzeTypes()
* function is called in @c ExprTypesFixer.cpp.
*
* This analysis has to be used in every place where we work with signed or
* unsigned types in the fixer.
*
* For example, the following code
* @code
* uint32_t a = -33;
* if (a < 0) { // if icmp instruction was signed
*    ...
* }
* @endcode
* gets the following statistics
* @code
* var | signed | unsigned
*  a       1         0
* @endcode
*
* To create an instance, use create(). Instances of this class have reference
* object semantics.
*
* This is a concrete visitor which should not be subclassed.
*/
class ExprTypesAnalysis final: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	/// Mapping of a expression into a vector of signed/unsigned information.
	/// Possible tags about expressions.
	enum class ExprTag {
		Signed,  /// Signed type.
		Unsigned /// Unsigned Type.
	};

	using TagVector = std::vector<ExprTag>;
	using ExprTagsMap = std::map< ShPtr<Expression>, TagVector>;

public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~ExprTypesAnalysis() override;

	std::size_t getCountOfTag(ShPtr<Expression> expr, ExprTag tag);
	ExprTagsMap analyzeExprTypes(ShPtr<Module> module);

	static ShPtr<ExprTypesAnalysis> create();

private:
	/// Map of all analyzed expressions and tags for every expression.
	ExprTagsMap exprTagsMap;

private:
	ExprTypesAnalysis();

	void addTagToExpr(ShPtr<Expression> expr, ExprTag tag);

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
