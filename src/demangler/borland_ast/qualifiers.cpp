/**
* @file src/demangler/borland_ast/qualifiers.cpp
* @brief Representation of type qualifiers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/qualifiers.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Constuctor for qualifiers.
 */
Qualifiers::Qualifiers(bool isVolatile, bool isConst) :
	_isVolatile(isVolatile), _isConst(isConst) {}

bool Qualifiers::isVolatile() const
{
	return _isVolatile;
}

bool Qualifiers::isConst() const
{
	return _isConst;
}

/**
 * Prints string representation of qualifiers.
 * Prints space on the left side.
 * @param s Output stream.
 */
void Qualifiers::printSpaceL(std::ostream &s) const
{
	if (_isVolatile) {
		s << " volatile";
	}
	if (_isConst) {
		s << " const";
	}
}

/**
 * Prints string representation of qualifiers.
 * Prints space on the right side.
 * @param s Output stream.
 */
void Qualifiers::printSpaceR(std::ostream &s) const
{
	if (_isVolatile) {
		s << "volatile ";
	}
	if (_isConst) {
		s << "const ";
	}
}

}    // borland
}    // demangler
}    // retdec
