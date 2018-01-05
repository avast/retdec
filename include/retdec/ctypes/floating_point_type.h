/**
* @file include/retdec/ctypes/floating_point_type.h
* @brief A representation of floating point types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_FLOATING_POINT_TYPE_H
#define RETDEC_CTYPES_FLOATING_POINT_TYPE_H

#include <memory>
#include <string>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of floating point types.
*/
class FloatingPointType: public Type
{
	public:
		static std::shared_ptr<FloatingPointType> create(
			const std::shared_ptr<Context> &context, const std::string &name, unsigned bitWidth);

		virtual bool isFloatingPoint() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instances are created by static method create().
		FloatingPointType(const std::string &name, unsigned bitWidth);
};

} // namespace ctypes
} // namespace retdec

#endif
