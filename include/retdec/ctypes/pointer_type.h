/**
* @file include/retdec/ctypes/pointer_type.h
* @brief A representation of pointer types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_POINTER_TYPE_H
#define RETDEC_CTYPES_POINTER_TYPE_H

#include <memory>
#include <string>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of pointer types.
*/
class PointerType: public Type
{
	public:
		static std::shared_ptr<PointerType> create(
			const std::shared_ptr<Context> &context,
			const std::shared_ptr<Type> &pointedType,
			unsigned bitWidth = 0
		);

		std::shared_ptr<Type> getPointedType() const;

		virtual bool isPointer() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		PointerType(const std::shared_ptr<Type> &pointedType, unsigned bitWidth = 0);

	private:
		std::shared_ptr<Type> pointedType;
};

} // namespace ctypes
} // namespace retdec

#endif
