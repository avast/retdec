/**
* @file include/retdec/ctypes/integral_type.h
* @brief A representation of integral types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_INTEGRAL_TYPE_H
#define RETDEC_CTYPES_INTEGRAL_TYPE_H

#include <memory>
#include <string>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of integral types.
*/
class IntegralType: public Type
{
	public:
		enum class Signess {
			Signed,
			Unsigned
		};

	public:
		static std::shared_ptr<IntegralType> create(
			const std::shared_ptr<Context> &context, const std::string &name,
			unsigned bitWidth, Signess signess = Signess::Signed);

		bool isSigned() const;
		bool isUnsigned() const;

		virtual bool isIntegral() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instances are created by static method create().
		IntegralType(const std::string &name, unsigned bitWidth,
			Signess signess = Signess::Signed);

	private:
		Signess signess;
};

} // namespace ctypes
} // namespace retdec

#endif
