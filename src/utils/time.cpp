/**
* @file src/utils/time.cpp
* @brief Implementation of the time-related functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

#include "retdec/utils/os.h"
#include "retdec/utils/time.h"

namespace retdec {
namespace utils {

namespace {

/**
* @brief Returns date in the form @c YYYY-MM-DD.
* @param cTime Time to conversion.
*/
std::string getDate(const std::tm *cTime) {
	if (!cTime) {
		return "";
	}
	std::ostringstream date;
	date << (cTime->tm_year + 1900) << "-"
		// std::tm::tm_mon is the number of months since January (0-11), so
		// to get the actual month (1-12), we have to add 1.
		<< std::setw(2) << std::setfill('0') << (cTime->tm_mon + 1) << "-"
		<< std::setw(2) << std::setfill('0') << cTime->tm_mday;
	return date.str();
}

/**
* @brief Returns time in the form @c HH:MM:SS.
* @param cTime Time to conversion.
*/
std::string getTime(const std::tm *cTime) {
	if (!cTime) {
		return "";
	}
	std::ostringstream time;
	time << std::setw(2) << std::setfill('0') << cTime->tm_hour << ':'
		<< std::setw(2) << std::setfill('0') << cTime->tm_min << ':'
		<< std::setw(2) << std::setfill('0') << cTime->tm_sec;
	return time.str();
}

} // anonymous namespace

/**
* @brief Returns the current timestamp.
*/
std::tm *getCurrentTimestamp() {
	auto now = std::time(nullptr);
	return std::localtime(&now);
}

/**
* @brief Returns the current date in the form @c YYYY-MM-DD.
*/
std::string getCurrentDate() {
	return getDate(getCurrentTimestamp());
}

/**
* @brief Returns the current time in the form @c HH:MM:SS.
*/
std::string getCurrentTime() {
	return getTime(getCurrentTimestamp());
}

/**
* @brief Returns the current year in the form @c YYYY.
*/
std::string getCurrentYear() {
	auto now = getCurrentTimestamp();
	return std::to_string(now->tm_year + 1900);
}

/**
* @brief Returns date in human readable form.
* @param tm Timestamp for conversion.
*/
std::string timestampToDate(std::tm *tm) {
	if (!tm) {
		return "";
	}
	const auto conDate = getDate(tm);
	const auto conTime = getTime(tm);
	if (conDate.empty() && conTime.empty()) {
		return "";
	} else if (conDate.empty()) {
		return conTime;
	} else if (conTime.empty()) {
		return conDate;
	}

	return conDate + " " + conTime;
}

/**
* @brief Returns date in human readable form.
* @param timestamp Timestamp for conversion.
*/
std::string timestampToDate(std::time_t timestamp) {
	return timestampToDate(std::localtime(&timestamp));
}

/**
* @brief Returns how much time has elapsed since the program was started
*        (in seconds).
*/
double getElapsedTime() {
	// Disable the -Wold-style-cast warning on Windows because CLOCKS_PER_SEC
	// on Windows contains a C cast. This warning is only for GCC (MSVC does
	// not support it).
	#if defined(OS_WINDOWS) && defined(__GNUC__)
		#pragma GCC diagnostic ignored "-Wold-style-cast"
	#endif

	return static_cast<double>(std::clock()) / CLOCKS_PER_SEC;
}

} // namespace utils
} // namespace retdec
