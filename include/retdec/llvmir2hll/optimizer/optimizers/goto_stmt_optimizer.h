/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.h
* @brief Replace goto statements when possible.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_GOTO_STMT_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_GOTO_STMT_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class GotoStmtOptimizer final: public FuncOptimizer {
public:
	GotoStmtOptimizer(ShPtr<Module> module);

	virtual std::string getId() const override { return "GotoStmt"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
