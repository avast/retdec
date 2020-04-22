/**
 * @file src/fileinfo/file_information/file_information_types/pattern/pattern_match.h
 * @brief Information about pattern match.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PATTERN_PATTERN_MATCH_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PATTERN_PATTERN_MATCH_H

#include <limits>

namespace retdec {
namespace fileinfo {

/**
 * Class for information about detected pattern match
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 */
class PatternMatch
{
	private:
		unsigned long long offset = std::numeric_limits<unsigned long long>::max();    ///< offset of match in file
		unsigned long long address = std::numeric_limits<unsigned long long>::max();   ///< address of match in memory
		unsigned long long dataSize = std::numeric_limits<unsigned long long>::max();  ///< total size of match in bytes
		unsigned long long entrySize = std::numeric_limits<unsigned long long>::max(); ///< byte size of one entry in match
		bool integer = false;                 ///< @c true if each entry in match is integer number
		bool floatingPoint = false;           ///< @c true if each entry in match is floating point number
	public:
		/// @name Query methods
		/// @{
		bool isInteger() const;
		bool isFloatingPoint() const;
		/// @}

		/// @name Getters
		/// @{
		bool getOffset(unsigned long long &pRes) const;
		bool getAddress(unsigned long long &pRes) const;
		bool getDataSize(unsigned long long &pRes) const;
		bool getEntrySize(unsigned long long &pRes) const;
		/// @}

		/// @name Setters
		/// @{
		void setOffset(unsigned long long pOffset);
		void setAddress(unsigned long long pAddress);
		void setDataSize(unsigned long long pDataSize);
		void setEntrySize(unsigned long long pEntrySize);
		void setInteger();
		void setFloatingPoint();
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
