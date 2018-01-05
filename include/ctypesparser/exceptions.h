/**
* @file include/ctypesparser/exceptions.h
* @brief Exceptions for C-types parser.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef CTYPESPARSER_EXCEPTIONS_H
#define CTYPESPARSER_EXCEPTIONS_H

#include "ctypes/exceptions.h"

namespace ctypesparser {

/**
* @brief A class for ctypesparser-related errors.
*/
class CTypesParseError: public ctypes::CTypesError
{
	public:
		using ctypes::CTypesError::CTypesError;
};

} // namespace ctypesparser

#endif
