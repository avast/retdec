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
#include <pelib/PeLib.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/byte_array_buffer.h"
#include "retdec/fileformat/utils/format_detection.h"

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
	{{0, "MZ"}, Format::PE},
	{{0, "ZM"}, Format::PE},
	{{0, "\x7F""ELF"}, Format::ELF},
	{{0, ":"}, Format::INTEL_HEX},
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

/**
 * Check if input file contains PE signature
 * @param stream Input stream
 * @return @c true if input file contains PE signature, @c false otherwise
 */
bool isPe(std::istream& stream)
{
	resetStream(stream);

	std::unique_ptr<PeFile> file(openPeFile(stream));
	if(!file)
	{
		return false;
	}

	dword signature = 0;
	try
	{
		file->readMzHeader();
		file->readPeHeader();
		switch(getFileType(stream))
		{
			case PEFILE32:
				signature = static_cast<PeFileT<32>*>(file.get())->peHeader().getNtSignature();
				break;
			case PEFILE64:
				signature = static_cast<PeFileT<64>*>(file.get())->peHeader().getNtSignature();
				break;
			default:;
		}
	} catch(...)
	{
		return false;
	}

	return signature == 0x4550 || signature == 0x50450000;
}

/**
 * Check if input file is in COFF format
 * @param stream Input stream
 * @param header First bytes of input file (COFF file header)
 * @return @c true if input file is COFF file, @c false otherwise
 */
bool isCoff(std::istream& stream, const std::string &header)
{
	resetStream(stream);

	if(header.size() < COFF_FILE_HEADER_BYTE_SIZE
			|| hasSubstringOnPosition(header, "ELF", 1))
	{
		return false;
	}

	std::string s(std::istreambuf_iterator<char>(stream), {});

	auto buffer = MemoryBuffer::getMemBuffer(
			llvm::StringRef(
					reinterpret_cast<const char*>(s.data()),
					s.size()),
			"",
			false);

	if(buffer == nullptr)
	{
		return false;
	}

	std::error_code errorCode;
	COFFObjectFile coff(buffer.get()->getMemBufferRef(), errorCode);
	PELIB_IMAGE_FILE_MACHINE_ITERATOR it;
	return !errorCode
			&& it.isValidMachineCode(
					static_cast<PELIB_IMAGE_FILE_MACHINE>(coff.getMachine()));
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
			// Both are in big endian byte order
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
		// All such files found were in little endian byte order
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
	resetStream(inputStream);

	std::size_t magicSize = 0;

	for(const auto &formatMap : {magicFormatMap, unknownFormatMap})
	{
		for(const auto &item : formatMap)
		{
			magicSize = std::max(magicSize, item.first.first + item.first.second.length());
		}
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

	for(const auto &item : unknownFormatMap)
	{
		if(hasSubstringOnPosition(magic, item.first.second, item.first.first))
		{
			return Format::UNKNOWN;
		}
	}

	for(const auto &item : magicFormatMap)
	{
		if(hasSubstringOnPosition(magic, item.first.second, item.first.first))
		{
			switch(item.second)
			{
				case Format::PE:
					return isPe(inputStream) ? Format::PE : Format::UNKNOWN;
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

	if(isCoff(inputStream, magic))
	{
		return Format::COFF;
	}
	else if(isRaw)
	{
		return Format::RAW_DATA;
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
