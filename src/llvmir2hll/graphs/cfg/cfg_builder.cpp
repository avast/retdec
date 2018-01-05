/**
* @file src/llvmir2hll/graphs/cfg/cfg_builder.cpp
* @brief Implementation of CFGBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builder.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new builder.
*/
CFGBuilder::CFGBuilder() {}

/**
* @brief Destructs the builder.
*/
CFGBuilder::~CFGBuilder() {}

/**
* @brief Returns a CFG of the given function @a func.
*
* @par Preconditions
*  - @a func is non-null
*/
ShPtr<CFG> CFGBuilder::getCFG(ShPtr<Function> func) {
	PRECONDITION_NON_NULL(func);

	initializeNewCFG(func);
	buildCFG();
	return cfg;
}

/**
* @brief Creates a new CFG and initializes it.
*/
void CFGBuilder::initializeNewCFG(ShPtr<Function> func) {
	this->func = func;
	cfg = ShPtr<CFG>(new CFG(func));
}

} // namespace llvmir2hll
} // namespace retdec
