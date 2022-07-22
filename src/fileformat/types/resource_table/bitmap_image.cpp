/**
 * @file src/fileformat/types/resource_table/bitmap_image.cpp
 * @brief Class for one bitmap image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <vector>

#include "retdec/fileformat/types/resource_table/bitmap_image.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/scope_exit.h"
#include "retdec/utils/system.h"
#include <stb/stb_image.h>

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Get image width
 * @return Image with
 */
std::size_t BitmapImage::getWidth() const
{
	if (getHeight() == 0)
	{
		return 0;
	}

	return image[0].size();
}

/**
 * Get image height
 * @return Image height
 */
std::size_t BitmapImage::getHeight() const
{
	return image.size();
}

/**
 * Get image
 * @return Image
 */
const std::vector<std::vector<struct BitmapPixel>> &BitmapImage::getImage() const
{
	return image;
}

bool BitmapImage::parsePngFormat(const ResourceIcon &icon)
{
	int x, y, n;
	auto byte_span = icon.getBytes();
	unsigned char* data = stbi_load_from_memory(byte_span.bytes_begin(), byte_span.size(), &x, &y, &n, 4);
	if (!data) return false;

	SCOPE_EXIT {
		stbi_image_free(data);
	};

	// Flip it height wise, as existing DIB format has height flipped compared to PNG
	for (int i = y - 1; i >= 0; --i)
	{
		std::vector<BitmapPixel> row;
		for (int j = 0; j < x; j++)
		{
			int offset = (i * x + j) * 4;
			row.emplace_back(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
		}
		this->image.push_back(row);
	}

	return true;
}

/**
 * Parse image in DIB format and converts it to unified BMP
 * @param icon Icon to parse
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDibFormat(const ResourceIcon &icon)
{
	struct BitmapInformationHeader bih;

	if (!parseDibHeader(icon, bih))
	{
		return false;
	}

	image.clear();

	switch (bih.bitCount)
	{
		case 1:
			return parseDib1Data(icon, bih);

		case 4:
			return parseDib4Data(icon, bih);

		case 8:
			return parseDib8Data(icon, bih);

		case 24:
			return parseDib24Data(icon, bih);

		case 32:
			return parseDib32Data(icon, bih);

		default:
			return false;
	}
}

/**
 * Parse a DIB header
 * @param icon Icon to parse the header from
 * @param res DIB header structure to store the result to
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDibHeader(const ResourceIcon &icon, struct BitmapInformationHeader &res) const
{
	std::vector<std::uint8_t> bytes;

	bytes.reserve(res.headerSize());

	if (!icon.getBytes(bytes, 0, res.headerSize()) || bytes.size() != res.headerSize())
	{
		return false;
	}

	std::size_t offset = 0;
	res.size = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.size);
	res.width = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.width);
	res.height = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.height);
	res.planes = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(res.planes);
	res.bitCount = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(res.bitCount);
	res.compression = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.compression);
	res.bitmapSize = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.bitmapSize);
	res.horizontalRes = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.horizontalRes);
	res.verticalRes = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.verticalRes);
	res.colorsUsed = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.colorsUsed);
	res.colorImportant = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.colorImportant);

	if (!isLittleEndian())
	{
		res.size = byteSwap32(res.size);
		res.width = byteSwap32(res.width);
		res.height = byteSwap32(res.height);
		res.planes = byteSwap16(res.planes);
		res.bitCount = byteSwap16(res.bitCount);
		res.compression = byteSwap32(res.compression);
		res.bitmapSize = byteSwap32(res.bitmapSize);
		res.horizontalRes = byteSwap32(res.horizontalRes);
		res.verticalRes = byteSwap32(res.verticalRes);
		res.colorsUsed = byteSwap32(res.colorsUsed);
		res.colorImportant = byteSwap32(res.colorImportant);
	}

	if (res.size != res.headerSize() || res.planes != 1 || res.compression != 0 ||
		res.width * 2 != res.height || res.width > 512 || res.height > 1024 ||
		res.bitCount > 32)
	{
		return false;
	}

	return true;
}

/**
 * Parse a 1 bpp DIB data
 * @param icon Icon to parse the data from
 * @param hdr DIB header structure
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDib1Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr)
{
	std::uint32_t paletteSize = hdr.colorsUsed;

	if (paletteSize == 0)
	{
		paletteSize = 2;
	}

	if (paletteSize != 2)
	{
		return false;
	}

	std::vector<struct BitmapPixel> palette;
	palette.reserve(paletteSize);

	if (!parseDibPalette(icon, palette, paletteSize))
	{
		return false;
	}

	std::vector<std::uint8_t> bytes;
	std::uint32_t nColumns = hdr.width;
	std::uint32_t nRows = hdr.height / 2;
	std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	std::size_t nBytes = nBytesInRow * nRows;
	std::uint8_t padding = nBytesInRow - ((nColumns * hdr.bitCount + 7) / 8);

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize() + paletteSize * 4, nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	std::size_t offset = 0;

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns / 8; j++)
		{
			for (std::size_t i = 0; i < 8; i++)
			{
				if (bytes.size() <= offset)
				{
					return false;
				}

				auto bit = (bytes[offset] & (0x01 << (7 - i)));
				auto index = (bit == 0) ? 0 : 1;
				row.push_back(palette[index]);
			}

			offset++;
		}

		std::size_t rest = nColumns % 8;

		if (rest != 0)
		{
			for (std::size_t i = 0; i < rest; i++)
			{
				if (bytes.size() <= offset)
				{
					return false;
				}

				auto index = !!(bytes[offset] & (0x01 << (7 - i)));
				row.push_back(palette[index]);
			}

			offset++;
		}

		offset += padding;
		image.push_back(std::move(row));
	}

	return true;
}

/**
 * Parse a 4 bpp DIB data
 * @param icon Icon to parse the data from
 * @param hdr DIB header structure
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDib4Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr)
{
	std::uint32_t paletteSize = hdr.colorsUsed;

	if (paletteSize == 0)
	{
		paletteSize = 16;
	}

	if (paletteSize != 16)
	{
		return false;
	}

	std::vector<struct BitmapPixel> palette;
	palette.reserve(paletteSize);

	if (!parseDibPalette(icon, palette, paletteSize))
	{
		return false;
	}

	std::vector<std::uint8_t> bytes;
	std::uint32_t nColumns = hdr.width;
	std::uint32_t nRows = hdr.height / 2;
	std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	std::size_t nBytes = nBytesInRow * nRows;
	std::uint8_t padding = nBytesInRow - ((nColumns * hdr.bitCount + 7) / 8);

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize() + paletteSize * 4, nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	std::size_t offset = 0;

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns / 2; j++)
		{
			if (bytes.size() <= offset)
			{
				return false;
			}

			row.push_back(palette[bytes[offset] >> 4]);
			row.push_back(palette[bytes[offset] & 0x0F]);
			offset++;
		}

		if (nColumns % 2)
		{
			if (bytes.size() <= offset)
			{
				return false;
			}

			row.push_back(palette[bytes[offset] >> 4]);
			offset++;
		}

		offset += padding;
		image.push_back(std::move(row));
	}

	return true;
}

/**
 * Parse a 8 bpp DIB data
 * @param icon Icon to parse the data from
 * @param hdr DIB header structure
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDib8Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr)
{
	std::uint32_t paletteSize = hdr.colorsUsed;

	if (paletteSize == 0)
	{
		paletteSize = 256;
	}

	if (paletteSize != 256)
	{
		return false;
	}

	std::vector<struct BitmapPixel> palette;
	palette.reserve(paletteSize);

	if (!parseDibPalette(icon, palette, paletteSize))
	{
		return false;
	}

	std::vector<std::uint8_t> bytes;
	std::uint32_t nColumns = hdr.width;
	std::uint32_t nRows = hdr.height / 2;
	std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	std::size_t nBytes = nBytesInRow * nRows;
	std::uint8_t bytesPP = hdr.bitCount / 8;
	std::uint8_t padding = nBytesInRow - (nColumns * bytesPP);

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize() + paletteSize * 4, nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	std::size_t offset = 0;

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns; j++)
		{
			if (bytes.size() <= offset)
			{
				return false;
			}

			row.push_back(palette[bytes[offset]]);
			offset += bytesPP;
		}

		offset += padding;
		image.push_back(std::move(row));
	}

	return true;
}

/**
 * Parse a 24 bpp DIB data
 * @param icon Icon to parse the data from
 * @param hdr DIB header structure
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDib24Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr)
{
	if (hdr.colorsUsed != 0)
	{
		return false;
	}

	std::vector<std::uint8_t> bytes;
	std::uint32_t nColumns = hdr.width;
	std::uint32_t nRows = hdr.height / 2;
	std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	std::size_t nBytes = nBytesInRow * nRows;
	std::uint8_t bytesPP = hdr.bitCount / 8;
	std::uint8_t padding = nBytesInRow - (nColumns * bytesPP);

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize(), nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	std::size_t offset = 0;

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns; j++)
		{
			if (bytes.size() <= (offset+2))
			{
				return false;
			}

			row.emplace_back(bytes[offset + 2], bytes[offset + 1], bytes[offset], 0xFF);
			offset += bytesPP;
		}

		offset += padding;
		image.push_back(std::move(row));
	}

	return true;
}

/**
 * Parse a 32 bpp DIB data
 * @param icon Icon to parse the data from
 * @param hdr DIB header structure
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDib32Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr)
{
	if (hdr.colorsUsed != 0)
	{
		return false;
	}

	std::vector<std::uint8_t> bytes;
	std::uint32_t nColumns = hdr.width;
	std::uint32_t nRows = hdr.height / 2;
	std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	std::size_t nBytes = nBytesInRow * nRows;
	std::uint8_t bytesPP = hdr.bitCount / 8;

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize(), nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	std::size_t offset = 0;

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns; j++)
		{
			if (bytes.size() <= (offset+3))
			{
				return false;
			}

			row.emplace_back(bytes[offset + 2], bytes[offset + 1], bytes[offset], bytes[offset + 3]);
			offset += bytesPP;
		}

		image.push_back(std::move(row));
	}

	return true;
}

/**
 * Parse a DIB palette
 * @param icon Icon to parse the palette from
 * @param palette Palette structure to store the result to
 * @param nColors The expected number of colors in palette
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDibPalette(const ResourceIcon &icon, std::vector<struct BitmapPixel> &palette,
								std::uint32_t nColors)
{
	std::size_t nBytes = nColors * 4;
	std::vector<uint8_t> bytes;
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, BitmapInformationHeader().headerSize(), nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	for (std::uint32_t i = 0; i < nBytes; i += 4)
	{
		if (bytes.size() <= (i+3))
		{
			return false;
		}

		palette.emplace_back(bytes[i + 2], bytes[i + 1], bytes[i], bytes[i + 3]);
	}

	return true;
}

/**
 * Invert Y axis
 */
void BitmapImage::invertAxisY()
{
	auto height = getHeight();

	for (std::size_t i = 0; i < height / 2; i++)
	{
		image[i].swap(image[height - i - 1]);
	}
}

/**
 * Set image alpha channel to 0xFF
 */
void BitmapImage::setAlphaFull()
{
	for (auto &row : image)
	{
		for (auto &pixel : row)
		{
			pixel.a = 0xFF;
		}
	}
}

/**
 * Reduces an image to 8x8
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::reduce8x8()
{
	auto width = getWidth();
	auto height = getHeight();

	if (width < 8 || height < 8)
	{
		return false;
	}

	std::size_t boxWidth = width / 8;
	std::size_t extraPixels = width % 8;
	std::size_t normalPixels = 8 - extraPixels;
	std::size_t period = 8 / normalPixels;

	/* reduce X axis */
	for (std::size_t row = 0; row < height; row++)
	{
		std::size_t offset = 0;
		std::size_t nExtraLeft = extraPixels;

		for (std::size_t column = 0; column < 8; column++)
		{
			if (column % period == 0 && nExtraLeft > 0)
			{
				if (!averageRowPixels(row, offset, boxWidth + 1, image[row][column]))
				{
					return false;
				}

				offset += boxWidth + 1;
				nExtraLeft--;
			}

			else
			{
				if (!averageRowPixels(row, offset, boxWidth, image[row][column]))
				{
					return false;
				}

				offset += boxWidth;
			}
		}
	}

	std::size_t boxHeight = height / 8;
	extraPixels = height % 8;
	normalPixels = 8 - extraPixels;
	period = 8 / normalPixels;

	/* reduce Y axis */
	for (std::size_t column = 0; column < 8; column++)
	{
		std::size_t offset = 0;
		std::size_t nExtraLeft = extraPixels;

		for (std::size_t row = 0; row < 8; row++)
		{
			if (row % period == 0 && nExtraLeft > 0)
			{
				if (!averageColumnPixels(column, offset, boxHeight + 1, image[row][column]))
				{
					return false;
				}

				offset += boxHeight + 1;
				nExtraLeft--;
			}

			else
			{
				if (!averageColumnPixels(column, offset, boxHeight, image[row][column]))
				{
					return false;
				}

				offset += boxHeight;
			}
		}
	}

	/* crop to 8x8 */
	image.resize(8);
	for (auto &row : image)
	{
		row.resize(8);
	}

	return true;
}

/**
 * Average pixels in a row
 * @param row A row to average pixels from (indexed from 0)
 * @param offset Column offset (indexed from 0)
 * @param nPixels Number of pixels
 * @param res Pixel to store the result to
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::averageRowPixels(std::size_t row, std::size_t offset, std::size_t nPixels, struct BitmapPixel &res)
{
	if (row >= getHeight() || nPixels == 0)
	{
		return false;
	}

	if (offset + nPixels > getWidth())
	{
		nPixels = getWidth() - offset;
	}

	std::size_t r = 0, g = 0, b = 0;

	for (std::size_t i = 0; i < nPixels; i++)
	{
		const auto &pixel = image[row][offset + i];
		r += pixel.r;
		g += pixel.g;
		b += pixel.b;
	}

	r /= nPixels;
	g /= nPixels;
	b /= nPixels;

	res = {static_cast<uint8_t>(r), static_cast<uint8_t>(g), static_cast<uint8_t>(b), 0xFF};
	return true;
}

/**
 * Average pixels in a column
 * @param column A column to average pixels from (indexed from 0)
 * @param offset Row offset (indexed from 0)
 * @param nPixels Number of pixels
 * @param res Pixel to store the result to
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::averageColumnPixels(std::size_t column, std::size_t offset, std::size_t nPixels,
										struct BitmapPixel &res)
{
	if (column >= getWidth() || nPixels == 0)
	{
		return false;
	}

	if (offset + nPixels > getHeight())
	{
		nPixels = getHeight() - offset;
	}

	std::size_t r = 0, g = 0, b = 0;

	for (std::size_t i = 0; i < nPixels; i++)
	{
		const auto &pixel = image[offset + i][column];
		r += pixel.r;
		g += pixel.g;
		b += pixel.b;
	}

	r /= nPixels;
	g /= nPixels;
	b /= nPixels;

	res = {static_cast<uint8_t>(r), static_cast<uint8_t>(g), static_cast<uint8_t>(b), 0xFF};
	return true;
}

/**
 * Converts image to greyscale
 */
void BitmapImage::greyScale()
{
	for (auto &row : image)
	{
		for (auto &pixel : row)
		{
			double i = pixel.r * 0.299 + pixel.g * 0.587 + pixel.b * 0.114;
			auto intensity = static_cast<uint8_t>(i + 0.5);
			pixel = {intensity, intensity, intensity, pixel.a};
		}
	}
}

} // namespace fileformat
} // namespace retdec
