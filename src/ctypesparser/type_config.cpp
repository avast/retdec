/**
* @file src/ctypesparser/type_config.cpp
* @brief Configuration of type widths and type signedness, that are implementation specific.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypesparser/type_config.h"

namespace retdec {
namespace ctypesparser {

/**
 * @brief Defines type widths and singnedness for types that are implementation specific.
 */
TypeConfig::TypeConfig()
{
	_typeWidths = {
		{"void", 0},
		{"bool", 1},
		{"char", 8},
		{"signed char", 8},
		{"unsigned char", 8},
		{"wchar_t", 32},
		{"short", 16},
		{"unsigned short", 16},
		{"int", 32},
		{"unsigned int", 32},
		{"long", 32},
		{"unsigned long", 64},
		{"long long", 64},
		{"unsigned long long", 64},
		{"float", 32},
		{"double", 64},
		{"long double", 80},
		{"ptr_t", 32},
		{"unsigned __int3264", 32} // this has the same size as arch size
	};

	_typeSignedness = {
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
		{"char", ctypes::IntegralType::Signess::Unsigned},
	};

	_defaultBitWidth = 0;
}

TypeConfig::TypeWidths TypeConfig::typeWidths()
{
	return _typeWidths;
}

TypeConfig::TypeSignedness TypeConfig::typeSignedness()
{
	return _typeSignedness;
}

unsigned TypeConfig::defaultBitWidth() {
	return _defaultBitWidth;
}

}
}