/**
* @file src/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer.cpp
* @brief Implementation of EmptyArrayToStringOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new function optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
EmptyArrayToStringOptimizer::EmptyArrayToStringOptimizer(ShPtr<Module> module):
	Optimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
EmptyArrayToStringOptimizer::~EmptyArrayToStringOptimizer() {}

void EmptyArrayToStringOptimizer::doOptimization() {
	// For each global variable in the module...
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		ShPtr<ConstArray> array(cast<ConstArray>((*i)->getInitializer()));
		if (!array || !isArrayOfStrings(array)) {
			continue;
		}

		// Convert each empty array into an empty string.
		for (auto i = array->init_begin(), e = array->init_end(); i != e; ++i) {
			if (isEmptyArray(*i)) {
				array->replace(*i, ConstString::create(""));
			}
		}
	}
}

/**
* @brief Returns @c true if @a array is an array of strings, @c false
*        otherwise.
*
* If the array is not initialized, this function returns @c false.
*/
bool EmptyArrayToStringOptimizer::isArrayOfStrings(ShPtr<ConstArray> array) {
	if (!array->isInitialized()) {
		return false;
	}

	const ConstArray::ArrayValue &internalArray();
	bool isOfStrings = false; // Is the array composed of strings?
	for (const auto &element : array->getInitializedValue()) {
		// There has to be at least one string.
		if (isa<ConstString>(element)) {
			isOfStrings = true;
			continue;
		}

		if (!isEmptyArray(element)) {
			isOfStrings = false;
			break;
		}
	}

	return isOfStrings;
}

/**
* @brief Returns @c true if @a expr is an empty array, @c false
*        otherwise.
*/
bool EmptyArrayToStringOptimizer::isEmptyArray(ShPtr<Expression> expr) {
	ShPtr<ConstArray> array(cast<ConstArray>(expr));
	if (!array) {
		return false;
	}

	return array->isEmpty();
}

} // namespace llvmir2hll
} // namespace retdec
