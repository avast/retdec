/**
* @file include/retdec/utils/non_copyable.h
* @brief A mixin to make classes non-copyable.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_NON_COPYABLE_H
#define RETDEC_UTILS_NON_COPYABLE_H

namespace retdec {
namespace utils {

/**
* @brief A mixin to make classes non-copyable.
*
* If you want your class to be non-copyable, inherit privately from this class.
* For example,
* @code
* class CannotBeCopied: private NonCopyable {
*     // ...
* };
* @endcode
*
* This mixin can be used if you want your class to have reference object
* semantics.
*/
class NonCopyable {
public:
	// Disable copy constructor and assignment operator to prevent copying.
	// They are declared public to make diagnostics messages more precise.
	NonCopyable(const NonCopyable &) = delete;
	NonCopyable &operator=(const NonCopyable &) = delete;

protected:
	// Public constructor is not needed in a mixin, so prevent the
	// compiler from generating a public one.
	NonCopyable() = default;

	// Protected non-virtual destructor disables polymorphic destruction, which
	// is the appropriate behavior in this case.
	~NonCopyable() = default;
};

} // namespace utils
} // namespace retdec

#endif
