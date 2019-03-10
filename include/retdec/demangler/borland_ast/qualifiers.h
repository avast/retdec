#ifndef RETDEC_QUALIFIERS_H
#define RETDEC_QUALIFIERS_H

#include <string>

namespace retdec {
namespace demangler {
namespace borland {

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
