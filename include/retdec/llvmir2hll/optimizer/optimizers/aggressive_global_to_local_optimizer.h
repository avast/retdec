/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/aggressive_global_to_local_optimizer.h
* @brief Converts all global variables without a name from debug information
*        to local variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AGGRESSIVE_GLOBAL_TO_LOCAL_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AGGRESSIVE_GLOBAL_TO_LOCAL_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Converts all global variables without a name from debug information
*        to local variables.
*
* By converting all global variables to local ones, the copy propagation
* optimization can be more effective. On the other hand, the optimized code
* might not be functionally equivalent with the original code.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class AggressiveGlobalToLocalOptimizer final: public Optimizer {
public:
	AggressiveGlobalToLocalOptimizer(ShPtr<Module> module);

	virtual ~AggressiveGlobalToLocalOptimizer() override;

	virtual std::string getId() const override { return "AggressiveGlobalToLocal"; }

private:
	virtual void doOptimization() override;

	void convertGlobalVarsToLocalVars();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
