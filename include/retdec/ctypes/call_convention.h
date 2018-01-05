/**
* @file include/retdec/ctypes/call_convention.h
* @brief A representation of a C call convention.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_CALL_CONVENTION_H
#define RETDEC_CTYPES_CALL_CONVENTION_H

#include <string>

namespace retdec {
namespace ctypes {

/**
* @brief A representation of a C call convention.
*/
class CallConvention
{
	public:
		CallConvention() = default;
		CallConvention(const std::string &callConvention);

		operator std::string() const;
		bool operator==(const CallConvention &other) const;
		bool operator!=(const CallConvention &other) const;

	private:
		std::string callConvention;
};

} // namespace ctypes
} // namespace retdec

#endif
