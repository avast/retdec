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
	std::int32_t width;                      ///< width (signed)
	std::int32_t height;                     ///< height (signed)
	std::uint16_t planes;                    ///< color planes (must be 1)
	std::uint16_t bitCount;                  ///< bpp color depth
	std::uint32_t compression;               ///< compression
	std::uint32_t bitmapSize;                ///< size of bitmap
	std::int32_t horizontalRes;              ///< horizontal resolution (signed, hint for BMP reader)
	std::int32_t verticalRes;                ///< vertical resolution (signed, hint for BMP reader)
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

/**
 * One bitmap image
 */
class BitmapImage
{
	private:
		std::size_t width;                ///< image width
		std::size_t height;               ///< image height

	public:
		BitmapImage();
		~BitmapImage();

		/// @name Getters
		/// @{
		std::size_t getWidth() const;
		std::size_t getHeight() const;
		std::size_t getSize() const;
		/// @}

		/// @name Setters
		/// @{
		// TODO
		/// @}

		/// @name Other methods
		/// @{
		bool parseDibFormat(const ResourceIcon &icon, BitmapInformationHeader &res);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
	