/**
* @file include/retdec/ctypes/typedefed_type.h
* @brief A representation of typedefed types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_TYPEDEFED_TYPE_H
#define RETDEC_CTYPES_TYPEDEFED_TYPE_H

#include <memory>
#include <string>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of typedefed types.
*/
class TypedefedType: public Type
{
	public:
		static std::shared_ptr<TypedefedType> create(
			const std::shared_ptr<Context> &context,
			const std::string &name,
			const std::shared_ptr<Type> &aliasedType
		);

		std::shared_ptr<Type> getAliasedType() const;
		std::shared_ptr<Type> getRealType() const;

		virtual bool isTypedef() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		// Instances are created by static method create().
		TypedefedType(const std::string &name,
			const std::shared_ptr<Type> &aliasedType);

	private:
		/// Type that this typedef stands for.
		std::shared_ptr<Type> aliasedType;
};

} // namespace ctypes
} // namespace retdec

#endif
