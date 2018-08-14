/**
 * @file include/retdec/cpdetect/utils/version_solver.h
 * @brief Function for detection of version stored in string.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_UTILS_VERSION_SOLVER_H
#define RETDEC_CPDETECT_UTILS_VERSION_SOLVER_H

#include <string>

namespace retdec {
namespace cpdetect {

bool getVersion(const std::string &input, std::string &result);
bool compareVersions(const std::string &aVer, const std::string &bVer, int &result);

} // namespace cpdetect
} // namespace retdec

#endif
