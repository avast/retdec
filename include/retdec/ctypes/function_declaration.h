/**
* @file include/retdec/ctypes/function_declaration.h
* @brief A representation of a C function declaration.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_FUNCTION_DECLARATION_H
#define RETDEC_CTYPES_FUNCTION_DECLARATION_H

#include <string>

namespace retdec {
namespace ctypes {

/**
* @brief A representation of a function declaration.
*/
class FunctionDeclaration
{
	public:
		FunctionDeclaration() = default;
		explicit FunctionDeclaration(const std::string &declaration);

		operator std::string() const;

	private:
		std::string declaration;
};

} // namespace ctypes
} // namespace retdec

#endif
