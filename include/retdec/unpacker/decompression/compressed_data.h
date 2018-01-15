/**
 * @file include/retdec/unpacker/decompression/compressed_data.h
 * @brief Declaration of class for abstract compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_COMPRESSED_DATA_H
#define RETDEC_UNPACKER_DECOMPRESSION_COMPRESSED_DATA_H

#include <cstdint>
#include <vector>

#include "retdec/unpacker/dynamic_buffer.h"

namespace retdec {
namespace unpacker {

/**
 * @brief Abstract class for compressed data.
 *
 * The abstract class representing the compressed data.
 */
class CompressedData
{
public:
	CompressedData() = delete;
	CompressedData(const DynamicBuffer& buffer) : _buffer(buffer) {} ///< Constructor.
	CompressedData(const CompressedData& data) : _buffer(data._buffer) {} ///< Copy constructor.
	virtual ~CompressedData() {} ///< Destructor.

	/**
	 * Returns the buffer containing compressed data.
	 *
	 * @return The buffer with compressed data.
	 */
	const DynamicBuffer& getBuffer() const { return _buffer; }

	/**
	 * Changes the compressed data buffer to another buffer.
	 *
	 * @param buffer New buffer to set.
	 */
	void setBuffer(const DynamicBuffer& buffer) { _buffer = buffer; }

	/**
	 * Pure virtual method for decompressing the data.
	 *
	 * @param outputBuffer The buffer in which the data is decompressed.
	 *
	 * @return True if the decompression ended up successfully, otherwise false.
	 */
	virtual bool decompress(DynamicBuffer& outputBuffer) = 0;

protected:
	DynamicBuffer _buffer; ///< Buffer containg the compressed data.

private:
	CompressedData& operator =(const CompressedData&);
};

} // namespace unpacker
} // namespace retdec

#endif
