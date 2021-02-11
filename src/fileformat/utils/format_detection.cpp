/**
 * @file src/fileformat/utils/format_detection.cpp
 * @brief File format detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <map>
#include <memory>
#include <system_error>

#include <llvm/Object/COFF.h>
#include <llvm/Support/Host.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/byte_array_buffer.h"
#include "retdec/fileformat/utils/format_detection.h"
#include "retdec/pelib/PeFile.h"
#include "retdec/pelib/ImageLoader.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::object;
using namespace PeLib;

namespace retdec {
namespace fileformat {

namespace
{

const std::size_t COFF_FILE_HEADER_BYTE_SIZE = 20;

const std::map<std::pair<std::size_t, std::string>, Format> magicFormatMap =
{
	// PE
	{{0, "MZ"}, Format::PE},
	{{0, "ZM"}, Format::PE},

	// COFF - only Little endian variants.
	// See PELIB_IMAGE_FILE_MACHINE.
	{{0, "\x4c""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_I386
	{{0, "\x4d""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_I486
	{{0, "\x4e""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_PENTIUM
	{{0, "\x84""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ALPHA
	{{0, "\xa2""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3
	{{0, "\xa3""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3DSP
	{{0, "\xa4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3E
	{{0, "\xa6""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH4
	{{0, "\xa8""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH5

	{{0, "\xc0""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARM
	{{0, "\xc2""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_THUMB
	{{0, "\xc4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARMNT
	{{0, "\xd3""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_AM33
	{{0, "\xf0""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_POWERPC

	{{0, std::string("\x00\x02", 2)}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_POWERPCFP
	{{0, "\xc4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_IA64
	{{0, "\x68""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MOTOROLA68000
	{{0, "\x90""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_PARISC
	{{0, "\x84""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ALPHA64

	// https://opensource.apple.com/source/file/file-23/file/magic/Magdir/mips.auto.html
	{{0, "\x60""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R3000_BIG, MIPSEB-LE ECOFF executable
	{{0, "\x62""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE, MIPSEL ECOFF executable
	{{0, "\x63""\x01"}, Format::COFF}, // MIPSEB-LE MIPS-II ECOFF executable
	{{0, "\x66""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R4000, MIPSEL MIPS-II ECOFF executable
	{{0, "\x40""\x01"}, Format::COFF}, // MIPSEB-LE MIPS-III ECOFF executable
	{{0, "\x42""\x01"}, Format::COFF}, // MIPSEL MIPS-III ECOFF executable
	{{0, "\x66""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPS16
	{{0, "\x68""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R10000
	{{0, "\x69""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2
	{{0, "\x66""\x03"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPSFPU
	{{0, "\x66""\x04"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPSFPU16
	{{0, "\x20""\x05"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_TRICORE
	{{0, "\xbc""\x0e"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_EBC
	{{0, "\x64""\x86"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_AMD64
	{{0, "\x41""\x90"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_M32R
	{{0, "\x64""\xaa"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARM64
	{{0, "\xee""\xc0"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MSIL
	// COFF - big endian magic
	// Big endian COFFs should start with 0000ffff but this long magic should
	// be enough.
	// See LLVM's COFF.h BigObjMagic
	{{0xc, "\xc7\xa1\xba\xd1\xee\xba\xa9\x4b\xaf\x20\xfa\xf6\x6a\xa4\xdc\xb8"}, Format::COFF},

	// ELF
	{{0, "\x7F""ELF"}, Format::ELF},
	// Intel-Hex
	{{0, ":"}, Format::INTEL_HEX},
	// Mach-O
	{{0, "\xFE""\xED""\xFA""\xCE"}, Format::MACHO}, // Mach-O
	{{0, "\xFE""\xED""\xFA""\xCF"}, Format::MACHO}, // Mach-O
	{{0, "\xCE""\xFA""\xED""\xFE"}, Format::MACHO}, // Mach-O
	{{0, "\xCF""\xFA""\xED""\xFE"}, Format::MACHO}, // Mach-O
	{{0, "\xCA""\xFE""\xBA""\xBE"}, Format::MACHO}  // Mach-O fat binary
};

const std::map<std::pair<std::size_t, std::string>, Format> unknownFormatMap =
{
	{{0, "\x7""\x1""\x64""\x00"}, Format::UNKNOWN}, // a.out
	{{0, "PS-X EXE"}, Format::UNKNOWN}, // PS-X
	{{257, "ustar"}, Format::UNKNOWN} // tar
};

void resetStream(std::istream& stream)
{
	stream.clear();
	stream.seekg(0, std::ios::beg);
}

std::uint64_t streamSize(std::istream& stream)
{
	stream.seekg(0, std::ios::end);
	std::uint64_t sz =stream.tellg();
	resetStream(stream);
	return sz;
}

/**
 * Check if input file contains PE signature
 * @param stream Input stream
 * @return @c true if input file contains PE signature, @c false otherwise
 */
bool isPe(std::istream& stream)
{
	// Create instance of the ImageLoader with most benevolent flags
	ImageLoader imgLoader(0);

	// Load the image from stream. Only load headers
	return (imgLoader.Load(stream, 0, true) == ERROR_NONE);
}

/**
 * Check if file is Java class
 * @param stream Input stream
 * @return @c true if input file is Java class file, @c false otherwise
 */
bool isJava(std::istream& stream)
{
	resetStream(stream);

	if (!stream)
	{
		return false;
	}

	std::uint32_t magic = 0;
	stream.read(reinterpret_cast<char*>(&magic), 4);

	// Same for both Java and fat Mach-O
	if (magic == 0xcafebabe || magic == 0xbebafeca)
	{
		std::uint32_t fatCount = 0;
		stream.read(reinterpret_cast<char*>(&fatCount), 4);

		if (sys::IsLittleEndianHost)
		{
			// Both are in big endian std::uint8_t order
			fatCount = sys::SwapByteOrder_32(fatCount);
		}

		// Mach-O currently supports up to 18 architectures
		// Java version starts at 39. However file utility uses value 30
		return fatCount > 30;
	}

	return false;
}

/**
 * Check if file is strange format with Mach-O magic.
 * @param stream Input stream
 * @return @c true if input file is likely not Mach-O, @c false otherwise
 */
bool isStrangeFeedface(std::istream& stream)
{
	resetStream(stream);

	if (!stream)
	{
		return false;
	}

	std::uint32_t ints[4];
	stream.read(reinterpret_cast<char*>(&ints), 16);

	if (sys::IsBigEndianHost)
	{
		// All such files found were in little endian std::uint8_t order
		for (int i = 0; i < 4; ++i)
		{
			ints[i] = sys::SwapByteOrder_32(ints[i]);
		}
	}

	if (ints[0] == 0xfeedface && ints[1] == 0x10 && ints[2] == 0x02)
	{
		// Maximal valid Mach-O value is 0x0b but 0x10 will be safer and
		// still remove all unwanted files
		return ints[3] > 0x10;
	}

	return false;
}

} // anonymous namespace

Format detectFileFormat(std::istream &inputStream, bool isRaw)
{
	if (isRaw)
	{
		return Format::RAW_DATA;
	}

	// Try unknown formats.
	//
	resetStream(inputStream);
	std::size_t umagicSize = 0;
	for(const auto &item : unknownFormatMap)
	{
		umagicSize = std::max(umagicSize, item.first.first + item.first.second.length());
	}
	std::string umagic;
	try
	{
		umagic.resize(umagicSize);
		inputStream.read(&umagic[0], umagicSize);
		for(const auto &item : unknownFormatMap)
		{
			if(hasSubstringOnPosition(umagic, item.first.second, item.first.first))
			{
				return Format::UNKNOWN;
			}
		}
	}
	catch(...)
	{
		// ignore
	}

	// Try known formats.
	//
	resetStream(inputStream);
	std::size_t magicSize = 0;
	for(const auto &item : magicFormatMap)
	{
		magicSize = std::max(magicSize, item.first.first + item.first.second.length());
	}
	std::string magic;
	try
	{
		magic.resize(magicSize);
		inputStream.read(&magic[0], magicSize);
	}
	catch(...)
	{
		return Format::UNDETECTABLE;
	}

	for(const auto &item : magicFormatMap)
	{
		if(hasSubstringOnPosition(magic, item.first.second, item.first.first))
		{
			switch(item.second)
			{
				case Format::PE:
					return isPe(inputStream) ? Format::PE : Format::UNKNOWN;
				case Format::COFF:
					if (streamSize(inputStream) < COFF_FILE_HEADER_BYTE_SIZE)
						return Format::UNKNOWN;
					return Format::COFF;
				case Format::MACHO:
					if (isStrangeFeedface(inputStream) || isJava(inputStream))
					{
						// Java class and some other format use Mach-O magics
						return Format::UNKNOWN;
					}
					return item.second;
				default:
					return item.second;
			}
		}
	}

	return Format::UNKNOWN;
}

/**
 * Detects file format of input file
 * @param filePath Path to input file
 * @param isRaw Is the input is a raw binary?
 * @return Detected file format in enumeration representation
 */
Format detectFileFormat(const std::string &filePath, bool isRaw)
{
	std::ifstream stream(filePath, std::ifstream::in | std::ifstream::binary);
	if(!stream.is_open())
	{
		return Format::UNDETECTABLE;
	}

	return detectFileFormat(stream, isRaw);
}

Format detectFileFormat(const std::uint8_t* data, std::size_t size, bool isRaw)
{
	byte_array_buffer bab(data, size);
	std::istream istream(&bab);

	return detectFileFormat(istream, isRaw);
}

} // namespace fileformat
} // namespace retdec
