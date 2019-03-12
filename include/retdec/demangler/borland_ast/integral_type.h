//
// Created by adam on 10.3.19.
//

#ifndef RETDEC_INTEGRAL_TYPE_H
#define RETDEC_INTEGRAL_TYPE_H

#include "retdec/demangler/borland_ast/built_in_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of integral types.
 */
class IntegralTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<IntegralTypeNode> create(
		Context &context,
		const std::string &typeName,
		bool isUnsigned,
		const Qualifiers &quals);

	bool isUnsigned();

	std::string typeName() const override;

	void printLeft(std::ostream &s) const override;

private:
	IntegralTypeNode(const std::string &typeName, bool isUnsigned, const Qualifiers &quals);

private:
	bool _isUnsigned;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_INTEGRAL_TYPE_H
