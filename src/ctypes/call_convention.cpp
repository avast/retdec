/**
* @file src/ctypes/call_convention.cpp
* @brief Implementation of CallConvention.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "ctypes/call_convention.h"

namespace ctypes {

/**
* @brief Constructs a new call convention.
*/
CallConvention::CallConvention(const std::string &callConvention):
	callConvention(callConvention) {}

CallConvention::operator std::string() const
{
	return callConvention;
}

bool CallConvention::operator==(const CallConvention &other) const
{
	return callConvention == other.callConvention;
}

bool CallConvention::operator!=(const CallConvention &other) const
{
	return !(*this == other);
}

} // namespace ctypes
