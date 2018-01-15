/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/deref_address_optimizer.h
* @brief Optimizes dereferences of addresses.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEREF_ADDRESS_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEREF_ADDRESS_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes dereferences of addresses.
*
* This optimizer removes all dereferences of addresses. For example,
* @code
* &c[0][0] = *&a[0] + *&b[2]
* @endcode
* can be optimized into
* @code
* c[0][0] = a[0] + b[2]
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class DerefAddressOptimizer final: public FuncOptimizer {
public:
	DerefAddressOptimizer(ShPtr<Module> module);

	virtual ~DerefAddressOptimizer() override;

	virtual std::string getId() const override { return "DerefAddress"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
