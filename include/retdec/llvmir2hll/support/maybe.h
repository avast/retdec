/**
* @file include/retdec/llvmir2hll/support/maybe.h
* @brief A simple implementation of the @c Maybe monad from Haskell.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_MAYBE_H
#define RETDEC_LLVMIR2HLL_SUPPORT_MAYBE_H

#include <memory>
#include <utility>

#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A simple implementation of the @c Maybe monad from Haskell.
*
* Informally speaking, this class may be used as the return type of functions
* which may either return the result or an "I don't know." answer.
*
* The purpose of this class is similar to the purpose of the @c
* boost::optional<> template (see
* http://www.boost.org/doc/libs/1_53_0/libs/optional/doc/html/index.html). The
* referenced article also shows the motivation for such a class.
*
* Usage example:
* @code
* Maybe<int> getWinningLotteryNumber() {
*     if (...) {
*         // I know the answer.
*         return Just(42);
*     } else {
*         // I don't know the answer.
*         return Nothing<int>();
*     }
* }
*
* int main() {
*     Maybe<int> winningNumber = getWinningLotteryNumber();
*     if (winningNumber) {
*         // We have an answer.
*         std::cout << "The winning number is " << winningNumber.get() << "\n";
*     } else {
*         // No answer.
*         std::cout << "We don't know the winning number\n";
*     }
* }
* @endcode
*
* @tparam T Type of the stored values. Has to be copy constructible.
*/
template<typename T>
class Maybe {
private:
	/// The stored value (or nothing if there is no value).
	std::unique_ptr<T> value;

public:
	/**
	* @brief Constructs an object without a value.
	*/
	Maybe() = default;

	/**
	* @brief Constructs an object with the given @a value.
	*/
	explicit Maybe(const T &value):
		value(std::make_unique<T>(value)) {}

	/**
	* @brief Copy-constructs a new object.
	*/
	Maybe(const Maybe<T> &other):
		value(other.value ? std::make_unique<T>(*other.value.get()) :
			std::unique_ptr<T>()) {}

	/**
	* @brief Move-constructs a new object.
	*/
	Maybe(Maybe<T> &&other) = default;

	/**
	* @brief Assigns @a other to the current object.
	*/
	Maybe<T> &operator=(Maybe<T> other) {
		value = std::move(other.value);
		return *this;
	}

	/**
	* @brief Returns the value stored in this object.
	*
	* @par Preconditions
	*  - there is a value in this object, i.e. this object evaluates to @c true
	*/
	const T &get() const noexcept {
		PRECONDITION(value, "calling get() on an empty Maybe<> instance");
		return *value;
	}

	/**
	* @brief Returns a pointer to the value stored in this object.
	*
	* When you have a Maybe<> object holding a value, you can use this operator
	* to simplify the notation. For example, assume that @c Point is a structure
	* containing attributes @c x and @c y, and consider the following variable:
	* @code
	* Maybe<Point> p = Just(Point(1, 2));
	* @endcode
	* Then, to access @c x and @c y, instead of
	* @code
	* p.get().x
	* p.get().y
	* @endcode
	* you can write
	* @code
	* p->x
	* p->y
	* @endcode
	*
	* @par Preconditions
	*  - there is a value in this object, i.e. this object evaluates to @c true
	*/
	const T *operator->() const noexcept {
		PRECONDITION(value, "calling operator->() on an empty Maybe<> instance");
		return value.get();
	}

	/**
	* @brief Returns @c true if this object evaluates to @c true, @c false
	*        otherwise.
	*
	* It is used in the bool context, e.g.:
	* @code
	* Maybe<int> i = func();
	* if (i) {
	*     // i has a value, so we can use it.
	* }
	* @endcode
	*/
	explicit operator bool() const noexcept {
		return value != nullptr;
	}
};

/**
* @brief A shortcut to @c Maybe(value).
*/
template<typename T>
inline Maybe<T> Just(T value) {
	return Maybe<T>(value);
}

/**
* @brief A shortcut to @c Maybe<T>().
*/
template<typename T>
inline Maybe<T> Nothing() {
	return Maybe<T>();
}

} // namespace llvmir2hll
} // namespace retdec

#endif
