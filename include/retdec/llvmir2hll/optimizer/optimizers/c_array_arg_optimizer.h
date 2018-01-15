/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer.h
* @brief Optimizes array arguments of function calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_C_ARRAY_ARG_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_C_ARRAY_ARG_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes array arguments of function calls.
*
* This optimizer simplifies array arguments of function calls. More
* specifically, each argument of the form
* @code
* &x[0]
* @endcode
* is converted to
* @code
* x
* @endcode
* In this way, the following code
* @code
* int x[256];
* scanf("%s", &x[0]);
* return strlen(&x[0]);
* @endcode
* can be optimized to
* @code
* int x[256];
* scanf("%s", x);
* return strlen(x);
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class CArrayArgOptimizer final: public FuncOptimizer {
public:
	CArrayArgOptimizer(ShPtr<Module> module);

	virtual ~CArrayArgOptimizer() override;

	virtual std::string getId() const override { return "CArrayArg"; }

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	void visit(ShPtr<CallExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
