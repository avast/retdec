/**
* @file include/retdec/ctypes/array_type.h
* @brief A representation of array types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ARRAY_TYPE_H
#define RETDEC_CTYPES_ARRAY_TYPE_H

#include <memory>
#include <vector>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of array types.
*/
class ArrayType: public Type
{
	public:
		using DimensionType = std::size_t;
		using Dimensions = std::vector<DimensionType>;

	public:
		/// Value used for unknown dimension.
		static const DimensionType UNKNOWN_DIMENSION;

	public:
		static std::shared_ptr<ArrayType> create(const std::shared_ptr<Context> &context,
			const std::shared_ptr<Type> &elementType, const Dimensions &dimensions);

		std::shared_ptr<Type> getElementType() const;
		const Dimensions &getDimensions() const;
		Dimensions::size_type getDimensionCount() const;

		virtual bool isArray() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}
	private:
		ArrayType(const std::shared_ptr<Type> &elementType, const Dimensions &dimensions);

	private:
		std::shared_ptr<Type> elementType;
		Dimensions dimensions;
};

} // namespace ctypes
} // namespace retdec

#endif
