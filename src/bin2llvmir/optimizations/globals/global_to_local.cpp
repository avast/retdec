/**
* @file src/bin2llvmir/optimizations/globals/global_to_local.cpp
* @brief Implementation of GlobalToLocal optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/globals/global_to_local.h"

using namespace llvm;

namespace {

/// Argument for the optimization.
const char *PASS_ARG = "global-to-local";

/// Name of the optimization.
const char *PASS_NAME = "Global to local optimization";

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char GlobalToLocal::ID = 0;

RegisterPass<GlobalToLocal> GlobalToLocalRegistered(
	PASS_ARG, PASS_NAME, false, false
);

/**
* @brief Created a new global to local optimizer.
*/
GlobalToLocal::GlobalToLocal() {
	globalToLocal = true;
	deadGlobalAssign = false;
}

/**
* @brief Destructs a global to local optimizer.
*/
GlobalToLocal::~GlobalToLocal() {}

/**
* @brief Returns the argument for the optimization.
*/
const char *GlobalToLocal::getPassArg() {
	return PASS_ARG;
}

// Override.
const char *GlobalToLocal::getPassName() const {
	return PASS_NAME;
}

} // namespace bin2llvmir
} // namespace retdec
