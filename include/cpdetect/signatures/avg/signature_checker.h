/**
 * @file include/cpdetec/signatures/avg/signature_checker.h
 * @brief Utils for checking signatures format.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_SIGNATURES_AVG_SIGNATURE_CHECKER_H
#define CPDETECT_SIGNATURES_AVG_SIGNATURE_CHECKER_H

#include <string>

namespace cpdetect {

bool isSlashed(const std::string &pattern);
bool isValidSignaturePattern(const std::string &pattern);
bool isValidUnslashedPattern(const std::string &pattern);

} // namespace cpdetect

#endif
