/**
* @file include/retdec/llvmir2hll/optimizer/optimizer.h
* @brief A base class of all optimizers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class of all optimizers.
*
* Concrete optimizers should:
*  - subclass this class or a more specific subclass (e.g. FuncOptimizer)
*  - override the getId() function, which returns the ID of the optimizer
*  - override the necessary do*() functions (by default, they do nothing)
*  - override the needed functions from the OrderedAllVisitor base class
*    (remember that non-overridden functions have to brought to scope using the
*    <tt>using OrderedAllVisitor::visit;</tt> declaration; otherwise, they'll be
*    hidden by the overridden ones)
*  - add every accessed statement to the @c accessedStmts set to avoid looping
*    over the same statements. Also, when a statement is accessed, it should
*    check this set before accessing any of its "nested statements". For example,
*    an if statement should check whether its body has already been accessed or
*    not. visitStmt() takes care of that, so you can use it to visit statements
*    (blocks).
*
* To use it (or any more concrete optimizer), either instantiate it and call
* optimize() in it, or use any of the templated optimize() static functions as
* a shorthand.
*
* Instances of this class have reference object semantics.
*/
class Optimizer: public OrderedAllVisitor, private retdec::utils::NonCopyable {
public:
	Optimizer(ShPtr<Module> module);

	virtual ~Optimizer() override;

	/**
	* @brief Returns the ID of the optimizer.
	*/
	virtual std::string getId() const = 0;

	ShPtr<Module> optimize();

	/**
	* @brief Creates an instance of OptimizerType with the given arguments and
	*        optimizes the given module by it.
	*
	* @param[in] module Module to be optimized.
	* @param[in] args Arguments to be passed to the optimization.
	*
	* @tparam OptimizerType Type of the used optimizer.
	*
	* @return Optimized module.
	*/
	template<class OptimizerType, typename... Args>
	static ShPtr<Module> optimize(ShPtr<Module> module, Args &&... args) {
		auto optimizer = std::make_shared<OptimizerType>(module,
			std::forward<Args>(args)...);
		return optimizer->optimize();
	}

protected:
	virtual void doInitialization();
	virtual void doOptimization();
	virtual void doFinalization();

protected:
	/// The module that is being optimized.
	ShPtr<Module> module;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
