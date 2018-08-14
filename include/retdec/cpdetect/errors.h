/**
 * @file include/retdec/cpdetect/errors.h
 * @brief Header file for error functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_ERRORS_H
#define RETDEC_CPDETECT_ERRORS_H

#include "retdec/cpdetect/cptypes.h"

namespace retdec {
namespace cpdetect {

std::string getErrorMessage(
		ReturnCode errorCode,
		retdec::fileformat::Format format = retdec::fileformat::Format::UNKNOWN);

bool isFatalError(ReturnCode errorCode);

} // namespace cpdetect
} // namespace retdec

#endif
