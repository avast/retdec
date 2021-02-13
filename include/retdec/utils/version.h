/**
 * @file include/retdec/utils/version.h
 * @brief RetDec version header.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_VERSION_H
#define RETDEC_UTILS_VERSION_H

#include <string>

namespace retdec {
namespace utils {
namespace version {

/**
 * \return The full current Git commit hash.
 */
std::string getCommitHash();

/**
 * \return First \a length character of the current Git commit hash.
 */
std::string getShortCommitHash(unsigned length = 8);

/**
 * \return Build date.
 */
std::string getBuildDate();

/**
 * \return The Git version tag.
 *         E.g. "v4.0" if the current commit is associated with an exact tag,
 *         or e.g. "v4.0-294-g21baf36d" if the commit is on top of an tag.
 */
std::string getVersionTag();

/**
 * \return Full version string containing all the necessary parts.
 *         Can be used in implementation of \c --version application option etc.
 * \note   This can return multiline string, use \c getVersionStringShort() if you
 *         want only one line.
 */
std::string getVersionStringLong();

/**
 * \return Shorter one-line version of \c getVersionStringLong().
 */
std::string getVersionStringShort();

} // namespace version
} // namespace utils
} // namespace retdec

#endif // RETDEC_UTILS_VERSION_H
