/**
* @file include/ctypes/unknown_type.h
* @brief A representation of unknown type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef CTYPES_UNKNOWN_TYPE_H
#define CTYPES_UNKNOWN_TYPE_H

#include <memory>

#include "ctypes/type.h"

namespace ctypes {

/**
* @brief A representation of unknown type.
*/
class UnknownType : public Type
{
	public:
		static std::shared_ptr<UnknownType> create();

		virtual bool isUnknown() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instance is created by static method create().
		UnknownType();
};

} // namespace ctypes

#endif
