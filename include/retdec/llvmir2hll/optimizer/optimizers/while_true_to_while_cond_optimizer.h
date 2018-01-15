/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer.h
* @brief Optimizes "while true" loops into "while cond" loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_WHILE_COND_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_WHILE_COND_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes "while true" loops into "while cond" loops.
*
* For example, the following loop
* @code
* i = 0
* while True:
*     dest[i] = src[i]
*     if src[i] == 0:
*         break
*     i = i + 1
* @endcode
* can be optimized into
* @code
* i = 0
* dest[i] = src[i]
* while src[i] != 0:
*     i = i + 1
*     dest[i] = src[i]
* @endcode
*
* As another example, the following code
* @code
* a = 1
* while True:
*     puts("test")
*     a = a + 1
*     if a >= 6:
*         return 0
* @endcode
* can be optimized into
* @code
* a = 1
* puts("test")
* a = a + 1
* while a < 6:
*     puts("test")
*     a = a + 1
* return 0
* @endcode
*
* Prerequisities:
*  - This optimization requires that the optimization LoopLastContinueOptimizer
*    is run before it.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class WhileTrueToWhileCondOptimizer final: public FuncOptimizer {
public:
	WhileTrueToWhileCondOptimizer(ShPtr<Module> module);

	virtual ~WhileTrueToWhileCondOptimizer() override;

	virtual std::string getId() const override { return "WhileTrueToWhileCond"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
