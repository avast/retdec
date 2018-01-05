/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer.h
* @brief Removes useless casts from a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_REMOVE_USELESS_CASTS_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_REMOVE_USELESS_CASTS_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Removes useless casts from a module.
*
* This optimizer removes useless casts from the given module. A cast is
* considered to be @e useless if it may be removed without changing the
* behavior of the program. The only casts that are removed are those which can
* be removed no matter what is the target HLL.
*
* Currently, the following useless casts are removed:
*
* (1)
* @code
* int a;
* int b;
* ...
* a = (int)b;
* @endcode
* In this case, since both @c a and @c b are of the same type, the cast is
* useless.
*
* For removing yet more casts, use CCastOptimizer or RemoveAllCastsOptimizer.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class RemoveUselessCastsOptimizer final: public FuncOptimizer {
public:
	RemoveUselessCastsOptimizer(ShPtr<Module> module);

	virtual ~RemoveUselessCastsOptimizer() override;

	virtual std::string getId() const override { return "RemoveUselessCasts"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	/// @}

	bool tryOptimizationCase1(ShPtr<AssignStmt> stmt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
