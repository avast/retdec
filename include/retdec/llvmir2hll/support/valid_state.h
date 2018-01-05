/**
* @file include/retdec/llvmir2hll/support/valid_state.h
* @brief A mixin providing support for keeping the validity of an object.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VALID_STATE_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VALID_STATE_H

namespace retdec {
namespace llvmir2hll {

/**
* @brief A mixin providing support for keeping the validity of an object.
*
* To use this mixin, inherit from it:
* @code
* class MyClass: public ValidState {
*    // ...
* }
* @endcode
*
* Then, instances of @c MyClass will have a set of methods for obtaining and
* setting the object validity. After creation, every instance is in a valid
* state. When an instance becomes invalid (for example, you modify it somehow),
* call invalidateState() so further calls to isInValidState() return @c false.
* The precise conditions when an instance should get into an invalid state
* depends on what your class does. When an instance becomes valid, call
* validateState() so further calls to isInValidState() return @c true.
*/
class ValidState {
public:
	bool isInValidState() const;
	void invalidateState();
	void validateState();

protected:
	ValidState();

private:
	// Is in a valid state?
	bool validState;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
