/**
* @file include/retdec/ctypesparser/type_config.h
* @brief Defines type widths and singnedness for types that are implementation specific.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_DEFAULT_TYPE_CONFIG_H
#define RETDEC_DEFAULT_TYPE_CONFIG_H

#include <map>

#include "retdec/ctypes/integral_type.h"

namespace retdec {
namespace ctypesparser {

/**
 * @brief Defines type widths and singnedness for types that are implementation specific.
 * TODO add configuration based on decompiled architecture and compiler.
 */
class TypeConfig {
public:
	/// Set container for C-types' bit width.
	using TypeWidths = std::map<std::string, unsigned>;
	/// Set container for C-types' signedness.
	using TypeSignedness = std::map<std::string, ctypes::IntegralType::Signess>;

public:
	TypeConfig();

	TypeWidths typeWidths();

	TypeSignedness typeSignedness();

	unsigned defaultBitWidth();

private:
	TypeWidths _typeWidths;
	TypeSignedness _typeSignedness;
	unsigned _defaultBitWidth;
};

}
}

#endif //RETDEC_DEFAULT_TYPE_CONFIG_H
