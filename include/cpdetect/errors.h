/**
 * @file include/cpdetec/errors.h
 * @brief Header file for error functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_ERRORS_H
#define CPDETECT_ERRORS_H

#include "cpdetect/cptypes.h"

namespace cpdetect {

std::string getErrorMessage(ReturnCode errorCode,
		fileformat::Format format = fileformat::Format::UNKNOWN);

bool isFatalError(ReturnCode errorCode);

} // namespace cpdetect

#endif
