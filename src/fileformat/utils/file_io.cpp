/**
 * @file src/fileformat/utils/file_io.cpp
 * @brief Functions for file I/O.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/file_io.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Read bytes from file stream and convert them to hexadecimal string representation
 * @param fileStream Representation of input file
 * @param hexa Read bytes in hexadecimal string representation
 * @param start Start offset of read
 * @param desiredSize Number of bytes for read. If this parameter is set to zero,
 *    function will read all bytes from @a start until end of file.
 * @return @c true if operation went OK, otherwise @c false
 *
 * If function returns @c false, @a hexa is set to empty string
 */
bool readHexString(std::istream &fileStream, std::string &hexa, std::size_t start, std::size_t desiredSize)
{
	std::vector<unsigned char> bytes;
	if(!readFile(fileStream, bytes, start, desiredSize))
	{
		return false;
	}

	bytesToHexString(bytes, hexa);
	return true;
}

/**
 * Read bytes from file stream as plain text
 * @param fileStream Representation of input file
 * @param plain Into this parameter the resulting string is stored
 * @param start Start offset of read
 * @param desiredSize Number of bytes for read. If this parameter is set to zero,
 *    function will read all bytes from @a start until end of file.
 * @return @c true if operation went OK, otherwise @c false
 *
 * If function returns @c false, @a plain is set to empty string
 */
bool readPlainString(std::istream &fileStream, std::string &plain, std::size_t start, std::size_t desiredSize)
{
	std::vector<unsigned char> bytes;
	if(!readFile(fileStream, bytes, start, desiredSize))
	{
		return false;
	}

	bytesToString(bytes, plain);
	return true;
}

} // namespace fileformat
} // namespace retdec
