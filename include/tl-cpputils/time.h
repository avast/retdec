/**
* @file include/tl-cpputils/time.h
* @brief Time-related functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef TL_CPPUTILS_TIME_H
#define TL_CPPUTILS_TIME_H

#include <ctime>
#include <string>

namespace tl_cpputils {

std::tm *getCurrentTimestamp();
std::string getCurrentDate();
std::string getCurrentTime();
std::string getCurrentYear();
std::string timestampToDate(std::tm *tm);
std::string timestampToDate(std::time_t timestamp);

double getElapsedTime();

} // namespace tl_cpputils

#endif
