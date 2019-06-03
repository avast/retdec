/**
* @file include/retdec/ctypes/named_type.h
* @brief A representation of class and instantiated template class types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_NAMED_TYPE_H
#define RETDEC_CTYPES_NAMED_TYPE_H

#include "retdec/ctypes/type.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
 * @brief A representation of custom types.
 * Named type represents class types and instatiated template class types,
 * when only name of the type is known.
 */
class NamedType: public Type {
public:
	static std::shared_ptr<NamedType> create(
		const std::shared_ptr<Context> &context,
		const std::string &name
	);

	/// @name Visitor interface.
	/// @{
	void accept(Visitor *v) override;
	/// @}

	bool isNamed() const override;

private:
	explicit NamedType(const std::string &name);
};

} // namespace ctypes
} // namespace retdec

#endif //RETDEC_CTYPES_NAMED_TYPE_H
