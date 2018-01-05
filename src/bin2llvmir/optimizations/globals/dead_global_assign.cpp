/**
* @file src/bin2llvmir/optimizations/globals/dead_global_assign.cpp
* @brief Implementation of DeadGlobalAssign optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/globals/dead_global_assign.h"

using namespace llvm;

namespace {

/// Argument for the optimization.
const char *PASS_ARG = "dead-global-assign";

/// Name of the optimization.
const char *PASS_NAME = "Dead global assign optimization";

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char DeadGlobalAssign::ID = 0;

RegisterPass<DeadGlobalAssign> DeadGlobalAssignRegistered(
	PASS_ARG, PASS_NAME, false, false
);

/**
* @brief Creates a new dead global assign optimizer.
*/
DeadGlobalAssign::DeadGlobalAssign() {
	globalToLocal = false;
	deadGlobalAssign = true;
}

/**
* @brief Destructs a dead global assign optimizer.
*/
DeadGlobalAssign::~DeadGlobalAssign() {}

/**
* @brief Returns the argument for the optimization.
*/
const char *DeadGlobalAssign::getPassArg() {
	return PASS_ARG;
}

// Override.
const char *DeadGlobalAssign::getPassName() const {
	return PASS_NAME;
}

} // namespace bin2llvmir
} // namespace retdec
