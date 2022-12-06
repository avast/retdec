/**
 * @file include/retdec/fileformat/types/resource_table/bitmap_image.h
 * @brief Class for one bitmap image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_BITMAP_IMAGE_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_BITMAP_IMAGE_H

#include <iostream>
#include "retdec/fileformat/types/resource_table/resource_icon.h"

namespace retdec {
namespace fileformat {

/**
 * Structure to represent BMP Information header
 */
struct BitmapInformationHeader
{
	std::uint32_t size;                      ///< size of header (must be 40)
	std::uint32_t width;                     ///< width
	std::uint32_t height;                    ///< height
	std::uint16_t planes;                    ///< color planes (must be 1)
	std::uint16_t bitCount;                  ///< bpp color depth
	std::uint32_t compression;               ///< compression
	std::uint32_t bitmapSize;                ///< size of bitmap
	std::uint32_t horizontalRes;             ///< horizontal resolution (hint for BMP reader)
	std::uint32_t verticalRes;               ///< vertical resolution (hint for BMP reader)
	std::uint32_t colorsUsed;                ///< number of colors in the image
	std::uint32_t colorImportant;            ///< minimal number of important colors (generaly ignored)

	std::size_t headerSize() const
	{
		return
			sizeof(size) + sizeof(width) + sizeof(height) + sizeof(planes) + sizeof(bitCount) +
			sizeof(compression) + sizeof(bitmapSize) + sizeof(horizontalRes) +
			sizeof(verticalRes) + sizeof(colorsUsed) + sizeof(colorImportant);
	}
};

struct BitmapPixel
{
	std::uint8_t r;
	std::uint8_t g;
	std::uint8_t b;
	std::uint8_t a;

	BitmapPixel(std::uint8_t r, std::uint8_t g, std::uint8_t b, std::uint8_t a) : r(r), g(g), b(b), a(a)
	{

	}

	BitmapPixel()
	{

	}
};

/**
 * One bitmap image
 */
class BitmapImage
{
	private:
		std::vector<std::vector<struct BitmapPixel>> image;    ///< bitmap image map row x column

	public:
		/// @name Getters
		/// @{
		std::size_t getWidth() const;
		std::size_t getHeight() const;
		std::size_t getSize() const;
		const std::vector<std::vector<struct BitmapPixel>> &getImage() const;
		/// @}

		/// @name Other methods
		/// @{
		bool parsePngFormat(const ResourceIcon &icon);
		bool parseDibFormat(const ResourceIcon &icon);
		bool parseDibHeader(const ResourceIcon &icon, struct BitmapInformationHeader &res) const;
		bool parseDib1Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr);
		bool parseDib4Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr);
		bool parseDib8Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr);
		bool parseDib24Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr);
		bool parseDib32Data(const ResourceIcon &icon, const struct BitmapInformationHeader &hdr);
		bool parseDibPalette(const ResourceIcon &icon, std::vector<struct BitmapPixel> &palette,
								std::uint32_t nColors);

		void invertAxisY();
		void setAlphaFull();
		bool reduce8x8();
		bool averageRowPixels(std::size_t row, std::size_t offset, std::size_t nPixels, struct BitmapPixel &res);
		bool averageColumnPixels(std::size_t column, std::size_t offset, std::size_t nPixels,
								struct BitmapPixel &res);
		void greyScale();
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
