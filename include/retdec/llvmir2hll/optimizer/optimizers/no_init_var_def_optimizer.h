/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer.h
* @brief Removes variable-defining statements with no initializer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_NO_INIT_VAR_DEF_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_NO_INIT_VAR_DEF_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Removes variable-defining statements with no initializer.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class NoInitVarDefOptimizer final: public FuncOptimizer {
public:
	NoInitVarDefOptimizer(ShPtr<Module> module);

	virtual ~NoInitVarDefOptimizer() override;

	virtual std::string getId() const override { return "NoInitVarDef"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
