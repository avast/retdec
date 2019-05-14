/**
* @file include/retdec/ctypes/reference_type.h
* @brief A representation of reference types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_REFERENCE_TYPE_H
#define RETDEC_CTYPES_REFERENCE_TYPE_H

#include <memory>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

/**
 * @brief A representation of L-Value and R-Value reference types.
 */
class ReferenceType: public Type
{
public:
	static std::shared_ptr<ReferenceType> create(
		const std::shared_ptr<Context> &context,
		const std::shared_ptr<Type> &referencedType,
		unsigned bitWidth = 0
	);

	std::shared_ptr<Type> getReferencedType() const;

	bool isReference() const override;

	/// @name Visitor interface.
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	explicit ReferenceType(const std::shared_ptr<Type> &referencedType, unsigned bitWidth = 0);

private:
	std::shared_ptr<Type> referencedType;
};

} // namespace ctypes
} // namespace retdec

#endif //RETDEC_CTYPES_REFERENCE_TYPE_H