/**
* @file include/retdec/llvmir2hll/evaluator/arithm_expr_evaluator_factory.h
* @brief Factory that creates instances of classes derived from
*        ArithmExprEvaluator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_FACTORY_H
#define RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_FACTORY_H

#include <string>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;

/**
* @brief Factory that creates instances of classes derived from
*        ArithmExprEvaluator.
*/
using ArithmExprEvaluatorFactory = Singleton<
	Factory<
		// Type of the base class.
		ArithmExprEvaluator,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<ArithmExprEvaluator> (*)()
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
