/**
* @file src/llvmir2hll/support/valid_state.cpp
* @brief Implementation of ValidState.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/support/valid_state.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new valid state.
*/
ValidState::ValidState(): validState(true) {}

/**
* @brief Returns @c true if the object is in a valid state, @c false otherwise.
*/
bool ValidState::isInValidState() const {
	return validState;
}

/**
* @brief Sets the object's state to invalid.
*/
void ValidState::invalidateState() {
	validState = false;
}

/**
* @brief Sets the object's state to valid.
*/
void ValidState::validateState() {
	validState = true;
}

} // namespace llvmir2hll
} // namespace retdec
