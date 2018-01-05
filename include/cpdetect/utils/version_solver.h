/**
 * @file include/cpdetec/utils/version_solver.h
 * @brief Function for detection of version stored in string.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_UTILS_VERSION_SOLVER_H
#define CPDETECT_UTILS_VERSION_SOLVER_H

#include <string>

namespace cpdetect {

bool getVersion(const std::string &input, std::string &result);
bool compareVersions(const std::string &aVer, const std::string &bVer, int &result);

} // namespace cpdetect

#endif
