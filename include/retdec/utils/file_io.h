/**
 * @file include/retdec/utils/file_io.h
 * @brief Functions for file I/O.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_FILE_IO_H
#define RETDEC_UTILS_FILE_IO_H

#include <fstream>
#include <vector>

namespace retdec {
namespace utils {

namespace {

/**
 * 1 MiB
 */
const std::size_t FILE_BURST_READ_LENGTH = 0x100000;

template <typename N> bool readBytes(std::istream& fileStream, std::vector<N>& result, std::size_t desiredSize)
{
	// We can read directly from the file without any conversions.
	if (sizeof(N) == 1)
	{
		// Prepare buffer where to store result
		std::size_t previousSize = result.size();
		result.resize(result.size() + desiredSize);
		char* buffer = reinterpret_cast<char*>(result.data()) + previousSize;

		// Read and check for error bits
		// If badbit is set, then something bad happened and data are not valid.
		// If EOF bit is not set and fail bit is set, then there was some other problem with reading data.
		// If EOF bit and failbit are set, then it just means the file was truncated, but we should not report
		//   it as error. Instead, we just shrink the result buffer to the number of bytes we have read.
		fileStream.read(buffer, desiredSize);
		if (fileStream.bad() || (!fileStream.eof() && fileStream.fail()))
			return false;

		// We may have read less bytes than requested, so check it
		//   and resize output buffer to match the number of bytes
		//   that were actually read.
		std::size_t charsRead = fileStream.gcount();
		if (result.size() != previousSize + charsRead)
			result.resize(previousSize + charsRead);
	}
	else
	{
		std::vector<std::uint8_t> temp;
		if (!readBytes<std::uint8_t>(fileStream, temp, desiredSize))
			return false;

		result.reserve(result.size() + temp.size());

		for (const auto& val : temp)
			result.push_back(val & 0xFF);
	}

	return true;
}

template <typename N> bool writeBytes(std::ostream& fileStream, const std::vector<N>& data, std::size_t desiredSize)
{
	// We can write directly to the file without any conversions.
	if (sizeof(N) == 1)
	{
		fileStream.write(reinterpret_cast<const char*>(data.data()), desiredSize);
		return fileStream.good();
	}
	else
	{
		// Copy lowest bytes from this templated values.
		std::vector<std::uint8_t> bytesData;
		for (std::size_t i = 0; i < desiredSize; ++i)
			bytesData.push_back(data[i] & 0xFF);

		return writeBytes<std::uint8_t>(fileStream, bytesData, desiredSize);
	}
}

} // anonymous namespace

/**
 * Read bytes from file stream
 *
 * @param fileStream Representation of input file
 * @param result Into this parameter the resulting bytes are stored
 * @param start Start offset of read
 * @param desiredSize Number of bytes for read. If this parameter is set to zero,
 *    function will read all bytes from @a start until end of file.
 *
 * @return @c true if operation went OK, otherwise @c false
 *
 * If function returns @c false, @a bytes is set to empty vector
 */
template <typename N> bool readFile(std::istream& fileStream, std::vector<N>& result, std::size_t start = 0, std::size_t desiredSize = 0)
{
	// Seek to the given offset and check if nothing bad happened
	fileStream.seekg(start, std::ios::beg);
	if (!fileStream.good())
		return false;

	const bool untilEof = !desiredSize;
	if (untilEof)
		desiredSize = FILE_BURST_READ_LENGTH;

	result.clear();
	std::size_t alreadyRead = 0;
	while ((alreadyRead < desiredSize || untilEof) && !fileStream.eof())
	{
		if (!readBytes(fileStream, result, desiredSize))
		{
			result.clear();
			return false;
		}

		alreadyRead += result.size();
	}

	return true;
}

/**
 * Read bytes from file
 *
 * @param fileName Name of the file
 * @param result Into this parameter the resulting bytes are stored
 * @param start Start offset of read
 * @param desiredSize Number of bytes for read. If this parameter is set to zero,
 *    function will read all bytes from @a start until end of file.
 *
 * @return @c true if operation went OK, otherwise @c false
 *
 * If function returns @c false, @a bytes is set to empty vector
 */
template <typename N> bool readFile(const std::string& fileName, std::vector<N>& result, std::size_t start = 0, std::size_t desiredSize = 0)
{
	result.clear();

	std::ifstream file(fileName, std::ios::in | std::ios::binary);
	if (!file.is_open())
		return false;

	return readFile(file, result, start, desiredSize);
}

/**
 * Write bytes to file
 *
 * @param fileStream Representation of output file
 * @param data Data to write into the file
 * @param start Start offset of write
 * @param desiredSize Number of bytes to write. If this parameter is set to zero,
 *    function will write all bytes from @c data.
 *
 * @return @c true if operation went OK, otherwise @c false
 */
template <typename N> bool writeFile(std::ostream& fileStream, const std::vector<N>& data, std::size_t start = 0, std::size_t desiredSize = 0)
{
	fileStream.seekp(start, std::ios::beg);
	if (!fileStream.good())
		return false;

	// If no size specified, write the whole data.
	if (!desiredSize)
		desiredSize = data.size();

	return writeBytes(fileStream, data, desiredSize);
}

/**
 * Write bytes to file
 *
 * @param fileName Name of the file
 * @param data Data to write into the file
 * @param start Start offset of write
 * @param desiredSize Number of bytes to write. If this parameter is set to zero,
 *    function will write all bytes from @c data.
 *
 * @return @c true if operation went OK, otherwise @c false
 */
template <typename N> bool writeFile(const std::string& fileName, const std::vector<N>& data, std::size_t start = 0, std::size_t desiredSize = 0)
{
	std::ofstream file(fileName, std::ios::out | std::ios::trunc | std::ios::binary);
	if (!file.is_open())
		return false;

	bool ret = writeFile(file, data, start, desiredSize);
	file.close();
	return ret;
}

} // namespace utils
} // namespace retdec

#endif
