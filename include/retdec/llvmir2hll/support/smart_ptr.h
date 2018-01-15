/**
* @file include/retdec/llvmir2hll/support/smart_ptr.h
* @brief Declarations, aliases, macros, etc. for the use of smart pointers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_SMART_PTR_H
#define RETDEC_LLVMIR2HLL_SUPPORT_SMART_PTR_H

#include <cstddef>
#include <memory>

namespace retdec {
namespace llvmir2hll {

/// An alias for a shared pointer.
template<typename T>
using ShPtr = std::shared_ptr<T>;

/// An alias for a weak pointer.
template<typename T>
using WkPtr = std::weak_ptr<T>;

/// An alias for a unique pointer.
template<typename T>
using UPtr = std::unique_ptr<T>;

/**
* @brief Enables shared_from_this() in the inheriting class.
*
* By inheriting from this class, shared_from_this() is enabled.
*
* Usage:
* @code
* class MyClass: public SharableFromThis<MyClass> {
*     // ...
* };
* @endcode
* After that, you can call shared_from_this() inside @c MyClass.
*
* @tparam ForClass Class that inherits from this class template.
*/
template<class ForClass>
class SharableFromThis: public std::enable_shared_from_this<ForClass> {
protected:
	// Change the visibility of shared_from_this() from public to protected to
	// prevent unintentional use of it outside of the class.
	using std::enable_shared_from_this<ForClass>::shared_from_this;
};

/**
* @brief Equivalent of dynamic_cast<> for shared pointers.
*
* @param[in] ptr Pointer to be casted.
*
* @tparam To Output type.
* @tparam From Input type.
*
* The purpose of this function is to provide a more concise notation. Indeed,
* @c cast<X>(ptr) is more concise than @c std::dynamic_pointer_cast<X>(ptr).
*/
template<typename To, typename From>
ShPtr<To> cast(const ShPtr<From> &ptr) noexcept {
	return std::dynamic_pointer_cast<To>(ptr);
}

/**
* @brief Equivalent of static_cast<> for shared pointers (unchecked cast).
*
* @param[in] ptr Pointer to be casted.
*
* @tparam To Output type.
* @tparam From Input type.
*
* The purpose of this function is to provide a more concise notation. Indeed,
* @c scast<X>(ptr) is more concise than @c std::static_pointer_cast<X>(ptr).
*
* The name of this function template stems from the fact that it performs an
* <tt>u</tt>nchecked <tt>cast</tt>, hence @c ucast.
*/
template<typename To, typename From>
ShPtr<To> ucast(const ShPtr<From> &ptr) noexcept {
	return std::static_pointer_cast<To>(ptr);
}

/**
* @brief Returns @c true if @a ptr is of type @c To or can be casted from @c
*        From to @c To, @c false otherwise.
*
* @param[in] ptr Pointer to be tested.
*
* @tparam To Desired output type.
* @tparam From Input type.
*
* The purpose of this function is to provide a more concise notation. Indeed,
* @c isa<X>(ptr) is more concise than @c std::dynamic_pointer_cast<X>(ptr).
*
* Furthermore,
* @code
* if (isa<EmptyStmt>(stmt)) {
* @endcode
* is more readable than
* @code
* if (cast<EmptyStmt>(stmt)) {
* @endcode
*/
template<typename To, typename From>
bool isa(const ShPtr<From> &ptr) noexcept {
	return cast<To>(ptr) != nullptr;
}

/**
* @brief A predicate for checking the equality of two weak pointers.
*/
template<typename T>
class WkPtrEqPredicate {
public:
	WkPtrEqPredicate(const WkPtr<T> &ptr): ptr(ptr) {}

	bool operator()(const WkPtr<T> &otherPtr) const {
		return ptr.lock() == otherPtr.lock();
	}

private:
	const WkPtr<T> &ptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
