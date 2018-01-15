/**
 * @file src/fileformat/utils/conversions.cpp
 * @brief Simple string conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/fileformat/utils/conversions.h"

namespace retdec {
namespace fileformat {

/**
 * Formatter for conversions between string and number
 */
std::ios_base& hexWithPrefix(std::ios_base &str)
{
	str.setf(std::ios_base::hex, std::ios::basefield);
	str.setf(std::ios_base::showbase);
	return str;
}

/**
 * Divide @a str into individual strings separated by a null character ('\0')
 * @param str Input string
 * @param words Into this parameter the separated strings are saved
 *
 * At start of this function, everything from vector @a words is deleted.
 *
 * Into @a words is stored each word (chunk of text), which contain at least one character
 * with different value than '\0' (words containing only null character are eliminated).
 * Null character at end of each stored word is erased.
 */
void separateStrings(std::string &str, std::vector<std::string> &words)
{
	str += '\0';
	words.clear();
	std::string tmp;
	const auto strLen = str.length();

	for(std::size_t i = 0, lastPos = 0; i < strLen; ++i)
	{
		if(str[i] == '\0')
		{
			tmp = str.substr(lastPos, i + 1 - lastPos);
			lastPos = i;
			if(tmp != std::string(tmp.length(), '\0'))
			{
				if(tmp[0] == '\0')
				{
					tmp.erase(0, 1);
				}
				if(tmp[tmp.length() - 1] == '\0')
				{
					tmp.erase(tmp.length() - 1, 1);
				}
				words.push_back(tmp);
			}
		}
	}

	str.erase(strLen - 1, 1);
}

} // namespace fileformat
} // namespace retdec
