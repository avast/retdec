/**
* @file include/retdec/ctypes/type.h
* @brief A base class of all C types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_TYPE_H
#define RETDEC_CTYPES_TYPE_H

#include <memory>
#include <string>

#include "retdec/ctypes/visitable.h"

namespace retdec {
namespace ctypes {

/**
* @brief A base class of all C types.
*/
class Type: public Visitable, public std::enable_shared_from_this<Type>
{
	public:
		virtual ~Type() = default;

		const std::string &getName() const;
		unsigned getBitWidth() const;

		virtual bool isArray() const;
		virtual bool isEnum() const;
		virtual bool isFloatingPoint() const;
		virtual bool isFunction() const;
		virtual bool isIntegral() const;
		virtual bool isPointer() const;
		virtual bool isStruct() const;
		virtual bool isTypedef() const;
		virtual bool isUnion() const;
		virtual bool isUnknown() const;
		virtual bool isVoid() const;

	protected:
		Type() = default;
		Type(const std::string &name, unsigned bitWidth);

	protected:
		std::string name;
		unsigned bitWidth;
};

} // namespace ctypes
} // namespace retdec

#endif
