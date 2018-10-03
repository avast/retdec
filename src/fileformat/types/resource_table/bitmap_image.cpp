/**
 * @file src/fileformat/types/resource_table/bitmap_image.cpp
 * @brief Class for one bitmap image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <vector>

#include "retdec/fileformat/types/resource_table/bitmap_image.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/system.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
BitmapImage::BitmapImage() : width(0), height(0)
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
	return width;
}

/**
 * Get image height
 * @return Image height
 */
std::size_t BitmapImage::getHeight() const
{
	return height;
}

/**
 * Parse image in DIB format and converts it to unified BMP
 * @param icon Icon to parse
 * @return @c `true` on success, otherwise `false`
 */
bool BitmapImage::parseDibFormat(const ResourceIcon &icon, BitmapInformationHeader &res)
{
	// TODO delete parameter
	std::vector<std::uint8_t> bytes;
	struct BitmapInformationHeader bih;

	bytes.reserve(bih.headerSize());

	if (!icon.getBytes(bytes, 0, bih.headerSize()) || bytes.size() != bih.headerSize())
	{
		return false;
	}

	std::size_t offset = 0;
	bih.size = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(bih.size);
	bih.width = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(bih.width);
	bih.height = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(bih.height);
	bih.planes = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(bih.planes);
	bih.bitCount = *reinterpret_cast<uint16_t *>(&bytes.data()[offset]); offset += sizeof(bih.bitCount);
	bih.compression = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(bih.compression);
	bih.bitmapSize = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(bih.bitmapSize);
	bih.horizontalRes = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(bih.horizontalRes);
	bih.verticalRes = *reinterpret_cast<int32_t *>(&bytes.data()[offset]); offset += sizeof(bih.verticalRes);
	bih.colorsUsed = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(bih.colorsUsed);
	bih.colorImportant = *reinterpret_cast<uint32_t *>(&bytes.data()[offset]); offset += sizeof(bih.colorImportant);

	if (!isLittleEndian())
	{
		bih.size = byteSwap32(bih.size);
		bih.width = byteSwap32(bih.width);
		bih.height = byteSwap32(bih.height);
		bih.planes = byteSwap16(bih.planes);
		bih.bitCount = byteSwap16(bih.bitCount);
		bih.compression = byteSwap32(bih.compression);
		bih.bitmapSize = byteSwap32(bih.bitmapSize);
		bih.horizontalRes = byteSwap32(bih.horizontalRes);
		bih.verticalRes = byteSwap32(bih.verticalRes);
		bih.colorsUsed = byteSwap32(bih.colorsUsed);
		bih.colorImportant = byteSwap32(bih.colorImportant);
	}

	// TODO uncomment
	// if (bih.size != bih.headerSize() || bih.planes != 1)
	// {
	// 	return false;
	// }






/////////////////////////////////////////////////////////
	// std::vector<uint8_t> dataBytes;

	// if (!icon.getBytes(dataBytes, bih.headerSize(), 0))
	// {
	// 	return false;
	// }

	// std::cout << "[KUBO]\n" <<
	// "size:           " << bih.size << "\n" <<
	// "width:          " << bih.width << "\n" <<
	// "height:         " << bih.height << "\n" <<
	// "planes:         " << bih.planes << "\n" <<
	// "bitCount:       " << bih.bitCount << "\n" <<
	// "compression:    " << bih.compression << "\n" <<
	// "bitmapSize:     " << bih.bitmapSize << "\n" <<
	// "horizontalRes:  " << bih.horizontalRes << "\n" <<
	// "verticalRes:    " << bih.verticalRes << "\n" <<
	// "colorsUsed:     " << bih.colorsUsed << "\n" <<
	// "colorImportant: " << bih.colorImportant << "\n" << "\n" <<

	// "iconWidth:      " << icon.getWidth() << "\n" <<
	// "iconHeight:     " << icon.getHeight() << "\n" <<
	// "bytesRead:      " << dataBytes.size() << "\n";

	// std::string hexBytes;
	// if (!icon.getHexBytes(hexBytes))
	// {
	// 	return false;
	// }

	// for (std::size_t i = 0; i < bih.headerSize() * 2; i++)
	// {
	// 	if (!(i % 64))
	// 	{
	// 		std::cout << "\n";
	// 	}

	// 	std::cout << hexBytes[i];

	// 	if (i % 2)
	// 	{
	// 		std::cout << " ";
	// 	}
	// }

	// std::cout << "\n";

	// for (std::size_t i = bih.headerSize() * 2; i < hexBytes.size(); i++)
	// {
	// 	if (!((i - bih.headerSize() * 2) % 64))
	// 	{
	// 		std::cout << "\n";
	// 	}

	// 	std::cout << hexBytes[i];

	// 	if (i % 2)
	// 	{
	// 		std::cout << " ";
	// 	}
	// }

	// hexBytes.erase(0, 2 * bih.headerSize());

	// hexBytes.erase(0, 2 * 4 * bih.width * bih.height);

	// std::cout << 4 * bih.width * bih.width << "\n";
	// std::cout << hexBytes << "\n";

	// for (std::size_t i = 0; i < bih.height; i++)
	// {
	// 	for (std::size_t j = 0; j < bih.width; j++)
	// 	{
	// 		std::cout << hexBytes[bih.height * i + j] << hexBytes[bih.height * i + j + 1] << ' ';
	// 	}
	// 	std::cout << "\n";
	// }


/////// TODO delete me
	res.size = bih.size;
	res.width = bih.width;
	res.height = bih.height;
	res.planes = bih.planes;
	res.bitCount = bih.bitCount;
	res.compression = bih.compression;
	res.bitmapSize = bih.bitmapSize;
	res.horizontalRes = bih.horizontalRes;
	res.verticalRes = bih.verticalRes;
	res.colorsUsed = bih.colorsUsed;
	res.colorImportant = bih.colorImportant;


	return true;
}

} // namespace fileformat
} // namespace retdec
