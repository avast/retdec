/**
* @file src/llvmir2hll/hll/compound_op_managers/no_compound_op_manager.cpp
* @brief Implementation of NoCompoundOpManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_managers/no_compound_op_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new compound operator manager that turns off all compound
*        optimizations.
*/
NoCompoundOpManager::NoCompoundOpManager(): CompoundOpManager() {}

/**
* @brief Destructor.
*/
NoCompoundOpManager::~NoCompoundOpManager() {}

std::string NoCompoundOpManager::getId() const {
	return "NoCompoundOpManager";
}

} // namespace llvmir2hll
} // namespace retdec
