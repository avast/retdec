/**
 * @file src/fileformat/utils/byte_array_buffer.cpp
 * @brief Array of bytes to std::istream abstraction.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <functional>
#include <cassert>
#include <cstring>

#include "retdec/fileformat/utils/byte_array_buffer.h"

namespace retdec {
namespace fileformat {

byte_array_buffer::byte_array_buffer(
		const std::uint8_t*begin,
		const std::uint8_t*end)
		:
		begin_(begin),
		end_(end),
		current_(begin_)
{
	assert(std::less_equal<const std::uint8_t *>()(begin_, end_));
}

byte_array_buffer::byte_array_buffer(const std::uint8_t* data, const std::size_t size) :
	byte_array_buffer(data, data+size)
{

}

byte_array_buffer::int_type byte_array_buffer::underflow()
{
	if (current_ == end_)
	{
		return traits_type::eof();
	}

	return traits_type::to_int_type(*current_);
}

byte_array_buffer::int_type byte_array_buffer::uflow()
{
	if (current_ == end_)
	{
		return traits_type::eof();
	}

	return traits_type::to_int_type(*current_++);
}

byte_array_buffer::int_type byte_array_buffer::pbackfail(int_type ch)
{
	if (current_ == begin_ || (ch != traits_type::eof() && ch != current_[-1]))
	{
		return traits_type::eof();
	}

	return traits_type::to_int_type(*--current_);
}

std::streamsize byte_array_buffer::showmanyc()
{
	assert(std::less_equal<const std::uint8_t *>()(current_, end_));
	return end_ - current_;
}

std::streampos byte_array_buffer::seekoff(
		std::streamoff off,
		std::ios_base::seekdir way,
		std::ios_base::openmode which)
{
	if (way == std::ios_base::beg)
	{
		current_ = begin_ + off;
	}
	else if (way == std::ios_base::cur)
	{
		current_ += off;
	}
	else if (way == std::ios_base::end)
	{
		current_ = end_;
	}

	if (current_ < begin_ || current_ > end_)
	{
		return -1;
	}

	return current_ - begin_;
}

std::streampos byte_array_buffer::seekpos(
		std::streampos sp,
		std::ios_base::openmode which)
{
	current_ = begin_ + sp;

	if (current_ < begin_ || current_ > end_)
	{
		return -1;
	}

	return current_ - begin_;
}

} // namespace fileformat
} // namespace retdec
