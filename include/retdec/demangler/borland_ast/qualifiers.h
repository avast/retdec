/**
* @file include/retdec/demangler/borland_ast/qualifiers.h
* @brief Representation of type qualifiers in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_QUALIFIERS_H
#define RETDEC_QUALIFIERS_H

#include <string>

namespace retdec {
namespace demangler {
namespace borland {

/*
 * @brief Representation of type qualifiers in borland AST.
 */
class Qualifiers
{
public:
	Qualifiers(bool isVolatile, bool isConst);

	bool isVolatile() const;

	bool isConst() const;

	void printSpaceL(std::ostream &s) const;

	void printSpaceR(std::ostream &s) const;

private:
	bool _isVolatile;
	bool _isConst;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_QUALIFIERS_H
