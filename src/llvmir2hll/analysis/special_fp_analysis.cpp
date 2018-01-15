/**
* @file src/llvmir2hll/analysis/special_fp_analysis.cpp
* @brief Implementation of SpecialFPAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/APFloat.h>

#include "retdec/llvmir2hll/analysis/special_fp_analysis.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*/
SpecialFPAnalysis::SpecialFPAnalysis():
	OrderedAllVisitor(), specialFPFound(false) {}

/**
* @brief Destructs the visitor.
*/
SpecialFPAnalysis::~SpecialFPAnalysis() {}

/**
* @brief Returns @c true if @a module uses a special floating-point value, like
*        infinity, @c false otherwise.
*/
bool SpecialFPAnalysis::hasSpecialFP(ShPtr<Module> module) {
	ShPtr<SpecialFPAnalysis> visitor(new SpecialFPAnalysis());

	// Browse global variables.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		(*i)->accept(visitor.get());
	}

	// Browse functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(visitor.get());
	}

	return visitor->specialFPFound;
}

//
// Visits
//

void SpecialFPAnalysis::visit(ShPtr<ConstFloat> constant) {
	ConstFloat::Type value(constant->getValue());
	if (value.isInfinity() || value.isNaN()) {
		specialFPFound = true;
	}
}

} // namespace llvmir2hll
} // namespace retdec
