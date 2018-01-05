/**
* @file include/ctypes/struct_type.h
* @brief A representation of struct types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef CTYPES_STRUCT_TYPE_H
#define CTYPES_STRUCT_TYPE_H

#include <memory>
#include <string>

#include "ctypes/composite_type.h"

namespace ctypes {

class Context;

/**
* @brief A representation of struct types.
*/
class StructType: public CompositeType
{
	public:
		static std::shared_ptr<StructType> create(
			const std::shared_ptr<Context> &context,
			const std::string &name, const Members &members
		);

		virtual bool isStruct() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instances are created by static method create().
		StructType(const std::string &name, const Members &members);
};

} // namespace ctypes

#endif
