/**
 * @file include/retdec/cpdetect/signatures/avg/signature_checker.h
 * @brief Utils for checking signatures format.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_SIGNATURES_AVG_SIGNATURE_CHECKER_H
#define RETDEC_CPDETECT_SIGNATURES_AVG_SIGNATURE_CHECKER_H

#include <string>

namespace retdec {
namespace cpdetect {

bool isSlashed(const std::string &pattern);
bool isValidSignaturePattern(const std::string &pattern);
bool isValidUnslashedPattern(const std::string &pattern);

} // namespace cpdetect
} // namespace retdec

#endif
