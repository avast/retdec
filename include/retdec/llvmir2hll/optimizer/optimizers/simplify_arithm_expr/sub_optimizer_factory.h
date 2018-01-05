/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer_factory.h
* @brief Factory that creates instances of classes derived from SubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_SUB_OPTIMIZER_FACTORY_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_SUB_OPTIMIZER_FACTORY_H

#include <string>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;
class SubOptimizer;

/**
* @brief Factory that creates instances of classes derived from SubOptimizer.
*/
using SubOptimizerFactory = Singleton<
	Factory<
		// Type of the base class.
		SubOptimizer,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<SubOptimizer> (*)(ShPtr<ArithmExprEvaluator>)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
