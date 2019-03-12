
#ifndef RETDEC_CTYPES_NAMED_TYPE_H
#define RETDEC_CTYPES_NAMED_TYPE_H

#include "retdec/ctypes/type.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
 * @brief A representation of custom types.
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
