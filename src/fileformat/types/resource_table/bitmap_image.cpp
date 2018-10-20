/**
 * @file src/fileformat/types/resource_table/bitmap_image.cpp
 * @brief Class for one bitmap image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <vector>
#include <iostream>			// TODO delme

#include "retdec/fileformat/types/resource_table/bitmap_image.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/system.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
BitmapImage::BitmapImage()
{

}

/**
 * Destructor
 */
BitmapImage::~BitmapImage()
{

}



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
 * Parse image in DIB format and converts it to unified BMP
 * @param icon Icon to parse
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDibFormat(const ResourceIcon &icon, BitmapInformationHeader &res)
{
	// TODO delete parameter res
	struct BitmapInformationHeader bih;

	if (!parseDibHeader(icon, bih))
	{
		return false;
	}

	dumpDibHeader(bih);	// TODO delme

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

	// std::uint32_t nColumns = bih.width;
	// std::uint32_t nRows = bih.height / 2;
	// std::size_t nBytesInRow = ((bih.bitCount * nColumns + 31) / 32) * 4;
	// std::size_t nBytes = nBytesInRow * nRows;

	// image.reserve(nRows);
	// bytes.clear();
	// bytes.reserve(nBytes);

	// if (!icon.getBytes(bytes, bih.headerSize(), nBytes) || bytes.size() != nBytes)
	// {
	// 	return false;
	// }



	

	// TODO delme
	// if (bih.bitCount == 32)
	// {
	// 	std::size_t offset = 0;

	// 	for (std::size_t i = 0; i < nRows; i++)
	// 	{
	// 		std::vector<struct BitmapPixel> row;
	// 		row.reserve(nColumns);

	// 		for (std::size_t j = 0; j < nBytesInRow / 4; j++)
	// 		{
	// 			row.emplace_back(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
	// 			offset += 4;
	// 		}

	// 		image.push_back(std::move(row));
	// 	}
	// }

	// dumpImageHex(); // TODO delme



/////// TODO delete me
	// res.size = bih.size;
	// res.width = bih.width;
	// res.height = bih.height;
	// res.planes = bih.planes;
	// res.bitCount = bih.bitCount;
	// res.compression = bih.compression;
	// res.bitmapSize = bih.bitmapSize;
	// res.horizontalRes = bih.horizontalRes;
	// res.verticalRes = bih.verticalRes;
	// res.colorsUsed = bih.colorsUsed;
	// res.colorImportant = bih.colorImportant;


	// return true;
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
	res.width = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(res.width);
	res.height = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(res.height);
	res.planes = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(res.planes);
	res.bitCount = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(res.bitCount);
	res.compression = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.compression);
	res.bitmapSize = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(res.bitmapSize);
	res.horizontalRes = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(res.horizontalRes);
	res.verticalRes = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(res.verticalRes);
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
		res.width * 2 != res.height || res.width > 512 || res.bitCount > 32)
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
	// TODO
	(void)icon;
	(void)hdr;
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

	// std::vector<std::uint8_t> bytes;
	// std::uint32_t nColumns = hdr.width;
	// std::uint32_t nRows = hdr.height / 2;
	// std::size_t nBytesInRow = ((hdr.bitCount * nColumns + 31) / 32) * 4;         // 4 Byte alignment
	// std::size_t nBytes = nBytesInRow * nRows;
	// std::uint8_t padding = nBytesInRow - (nColumns * hdr.bitCount / 8);
	// std::uint8_t bytesPP = hdr.bitCount / 8;

	// image.reserve(nRows);
	// bytes.reserve(nBytes);

	// if (!icon.getBytes(bytes, hdr.headerSize() + paletteSize, nBytes) || bytes.size() != nBytes)
	// {
	// 	return false;
	// }

	// for (std::size_t i = 0; i < nRows; i++)
	// {
	// 	std::vector<struct BitmapPixel> row;
	// 	row.reserve(nColumns);

	// 	for (std::size_t j = 0; j < nColumns; j++)
	// 	{
	// 		row.push_back(palette[bytes[offset]]);
	// 		offset += bytesPP;
	// 	}

	// 	offset += padding;
	// 	image.push_back(std::move(row));
	// }

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
	std::uint8_t padding = nBytesInRow - (nColumns * hdr.bitCount / 8);
	std::uint8_t bytesPP = hdr.bitCount / 8;

	image.reserve(nRows);
	bytes.reserve(nBytes);

	if (!icon.getBytes(bytes, hdr.headerSize() + paletteSize, nBytes) || bytes.size() != nBytes)
	{
		return false;
	}

	for (std::size_t i = 0; i < nRows; i++)
	{
		std::vector<struct BitmapPixel> row;
		row.reserve(nColumns);

		for (std::size_t j = 0; j < nColumns; j++)
		{
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
	std::uint8_t padding = nBytesInRow - (nColumns * hdr.bitCount / 8);
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
			row.emplace_back(bytes[offset], bytes[offset + 1], bytes[offset + 2], 0xFF);
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
			row.emplace_back(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
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
		palette.emplace_back(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
	}
}

void BitmapImage::dumpImageHex() const	// TODO delme
{
	std::cout << "IMAGE\n";
	std::cout << "W: " << getWidth() << "\n";
	std::cout << "H: " << getHeight() << "\n";
	for (std::size_t i = 0; i < getHeight(); i++)
	{
		for (std::size_t j = 0; j < getWidth(); j++)
		{
			std::cout << "[" << std::hex << static_cast<unsigned>(image[i][j].r) << ","
						<< static_cast<unsigned>(image[i][j].g) << ","
						<< static_cast<unsigned>(image[i][j].b) << ","
						<< static_cast<unsigned>(image[i][j].a) << "]";
		}

		std::cout << "\n\n";
	}
}

void BitmapImage::dumpDibHeader(const struct BitmapInformationHeader &hdr) const
{
	std::cout << "BITMAP INFORMATION HEADER\n" <<
	"bisize:         " << hdr.size << "\n" <<
	"width:          " << hdr.width << "\n" <<
	"height:         " << hdr.height << "\n" <<
	"planes:         " << hdr.planes << "\n" <<
	"bitCount:       " << hdr.bitCount << "\n" <<
	"compression:    " << hdr.compression << "\n" <<
	"bitmapSize:     " << hdr.bitmapSize << "\n" <<
	"horizontalRes:  " << hdr.horizontalRes << "\n" <<
	"verticalRes:    " << hdr.verticalRes << "\n" <<
	"colorsUsed:     " << hdr.colorsUsed << "\n" <<
	"colorImportant: " << hdr.colorImportant << "\n" << "\n";
}

} // namespace fileformat
} // namespace retdec
