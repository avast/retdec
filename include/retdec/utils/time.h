/**
* @file include/retdec/utils/time.h
* @brief Time-related functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_TIME_H
#define RETDEC_UTILS_TIME_H

#include <ctime>
#include <string>

namespace retdec {
namespace utils {

std::tm *getCurrentTimestamp();
std::string getCurrentDate();
std::string getCurrentTime();
std::string getCurrentYear();
std::string timestampToDate(std::tm *tm);
std::string timestampToDate(std::time_t timestamp);

double getElapsedTime();

} // namespace utils
} // namespace retdec

#endif
