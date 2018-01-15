/**
 * @file include/retdec/utils/value.h
 * @brief Values and other derived class representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_VALUE_H
#define RETDEC_UTILS_VALUE_H

#include <cassert>
#include <ostream>

namespace retdec {
namespace utils {

/**
 * Class encapsulates value of any type and adds information if the value
 * was defined or is still undefined. Any attempt to work with an undefined
 * value ends on assertion.
 *
 * Example usage #1:
 * @code{.cpp}
 * Maybe<int> val;
 * val.isDefined(); // false
 * val.isUndefined(); // true
 * val = 10;
 * val.isDefined(); // true
 * val.isUndefined(); // false
 * int x = val + 20;
 * @endcode
 *
 * Example usage #2:
 * @code{.cpp}
 * Maybe<int> val(10);
 * val.isDefined(); // true
 * val.isUndefined(); // false
 * @endcode
 */
template <class T>
class Maybe
{
	public:
		Maybe() {}
		Maybe(const T& value) : _defined(true), _value(value) {}
		Maybe(T&& value) : _defined(true), _value(std::move(value)) {}
		Maybe(const Maybe<T>&) = default;
		Maybe(Maybe<T>&&) = default;

		Maybe& operator=(Maybe<T> rhs)
		{
			std::swap(_defined, rhs._defined);
			std::swap(_value, rhs._value);
			return *this;
		}

		operator T() const { return getValue(); }
		const T& getValue() const { assert(isDefined()); return _value; }

		bool isUndefined() const { return !isDefined(); }
		bool isDefined() const   { return _defined; }
		void setUndefined()      { _defined = false; _value = T{}; }

		friend std::ostream& operator<< (std::ostream &out, const Maybe<T> &v)
		{
			if (v.isDefined())
				return out << v.getValue();
			else
				return out << "UNDEFINED";
		}

	private:
		bool _defined = false;
		T _value{};
};

/**
 * Two Maybe objects are equal if they are both undefined or both defined
 * with the same value.
 */
template <typename T>
bool operator==(const Maybe<T>& v1, const Maybe<T>& v2)
{
	if (v1.isUndefined() && v2.isUndefined())
	{
		return true;
	}
	if (v1.isDefined() && v2.isDefined())
	{
		return v1.getValue() == v2.getValue();
	}
	else
	{
		return false;
	}
}
template <typename T>
bool operator!=(const Maybe<T>& v1, const Maybe<T>& v2)
{
	return !(v1 == v2);
}

} // namespace utils
} // namespace retdec

#endif
