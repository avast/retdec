/**
* @file include/retdec/ctypes/void_type.h
* @brief A representation of void type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_VOID_TYPE_H
#define RETDEC_CTYPES_VOID_TYPE_H

#include <memory>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

/**
* @brief A representation of void type.
*/
class VoidType : public Type
{
	public:
		static std::shared_ptr<VoidType> create();

		virtual bool isVoid() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instance is created by static method create().
		VoidType();
};

} // namespace ctypes
} // namespace retdec

#endif
