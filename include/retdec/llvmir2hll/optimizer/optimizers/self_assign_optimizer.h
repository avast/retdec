/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/self_assign_optimizer.h
* @brief Removes self assignments.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SELF_ASSIGN_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SELF_ASSIGN_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Removes self assignments.
*
* This optimizer removes all self assignments. For example, it removes code
* like
* @code
* var = var
* @endcode
* or
* @code
* a[1] = a[1]
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class SelfAssignOptimizer final: public FuncOptimizer {
public:
	SelfAssignOptimizer(ShPtr<Module> module);

	virtual ~SelfAssignOptimizer() override;

	virtual std::string getId() const override { return "SelfAssign"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
