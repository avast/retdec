/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer.h
* @brief Optimizes pointer arithmetic on variables or array accesses or
*        structures to array accesses.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEREF_TO_ARRAY_INDEX_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEREF_TO_ARRAY_INDEX_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes pointer arithmetic on variables to array accesses.
*
* For example,
* @code
* *(var + 4)
* @endcode
* can be optimized to
* @code
* var[4]
* @endcode
* or
* @code
* *(4 + a[2])
* @endcode
* can be optimized to
* @code
* a[2][4]
* @endcode
* or
* @code
* *(apple.e0[0] + 4)
* @endcode
* can be optimized to
* @code
* apple.e0[0][4]
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class DerefToArrayIndexOptimizer final: public Optimizer {
public:
	DerefToArrayIndexOptimizer(ShPtr<Module> module);

	virtual ~DerefToArrayIndexOptimizer() override;

	virtual std::string getId() const override { return "DerefToArrayIndex"; }

private:
	/// Structure that stores the base and index for creating a new
	/// ArrayIndexOpExpr.
	struct BaseAndIndex {
		ShPtr<Expression> base; ///< Base of ArrayIndexOpExpr
		ShPtr<Expression> index; ///< Index of ArrayIndexOpExpr
	};

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	/// @}

	Maybe<BaseAndIndex> getBaseAndIndexFromExprIfPossible(ShPtr<AddOpExpr> expr);
	void replaceDerefWithArrayIndex(ShPtr<DerefOpExpr> oldExpr, const
		BaseAndIndex &baseAndIndex);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
