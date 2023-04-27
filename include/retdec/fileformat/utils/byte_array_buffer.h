/**
 * @file include/retdec/fileformat/utils/byte_array_buffer.h
 * @brief Array of bytes to std::istream abstraction.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_BYTE_ARRAY_BUFFER_H
#define RETDEC_FILEFORMAT_UTILS_BYTE_ARRAY_BUFFER_H

#include <cstdint>
#include <streambuf>

namespace retdec {
namespace fileformat {

/**
 * Example 2 from:
 * "A beginner's guide to writing a custom stream buffer (std::streambuf)"
 * Links:
 * http://www.voidcn.com/article/p-vjnlygmc-gy.html
 * https://stackoverflow.com/a/31597630
 */
class byte_array_buffer : public std::streambuf
{
	public:
		byte_array_buffer(const std::uint8_t* begin, const std::uint8_t* end);
		byte_array_buffer(const std::uint8_t* data, const std::size_t size);

	private:
		int_type underflow();
		int_type uflow();
		int_type pbackfail(int_type ch);
		std::streamsize showmanyc();

		std::streampos seekoff(
				std::streamoff off,
				std::ios_base::seekdir way,
				std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);
		std::streampos seekpos(std::streampos sp,
				std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);

		// copy ctor and assignment not implemented;
		// copying not allowed
		byte_array_buffer(const byte_array_buffer &);
		byte_array_buffer &operator= (const byte_array_buffer &);

	private:
		const std::uint8_t* const begin_ = nullptr;
		const std::uint8_t* const end_ = nullptr;
		const std::uint8_t* current_ = nullptr;
};

} // namespace fileformat
} // namespace retdec

#endif
