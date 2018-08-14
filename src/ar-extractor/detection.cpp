/**
 * @file src/ar-extractor/detection.cpp
 * @brief Detection methods.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <istream>

#include <llvm/Support/Host.h>
#include <llvm/Support/MachO.h>
#include <llvm/Support/SwapByteOrder.h>

#include "retdec/utils/string.h"
#include "retdec/ar-extractor/detection.h"

using namespace retdec::utils;
using namespace llvm::MachO;

namespace {

/**
 * Archive magic constant.
 */
const std::string archMagic = "!<arch>";

/**
 * Thin archive magic constant.
 *
 * Thin archives contain only paths to files so they are not fit for
 * decompilation nor extraction.
 */
const std::string thinMagic = "!<thin>";

/**
 * Size of string to search for when detecting archives.
 *
 * Size is same for both thin and normal archives.
 */
constexpr std::size_t arMagicSize = 7;

/**
 * What portion of file will be loaded at start for Mach-O archives detection.
 *
 * Structure for 64-bit files is larger so we have to use fat_arch_64.
 */
constexpr std::size_t fatLoadSize = sizeof(fat_header) + sizeof(fat_arch_64);

/**
 * Byte order swap of structure if necessary.
 *
 * Mach-O Universal headers are in big endian byte order so swap will be made
 * only if host is in little endian byte order.
 *
 * @param structure input Mach-O structure
 */
template<typename StructType>
inline void swapStructByteOrderIfNecessary(
	StructType &structure)
{
	if (llvm::sys::IsLittleEndianHost) {
		llvm::MachO::swapStruct(structure);
	}
}

/**
 * Check for archive magic string in Mach-O file.
 *
 * @param inputStream input file stream
 * @param offset archive magic string offset
 *
 * @return @c true if archive magic was found, @c false otherwise
 */
bool checkArchMagicAtOffset(
	std::ifstream &inputStream,
	const std::size_t &offset)
{
	// Load bytes at given offset.
	inputStream.seekg(offset);
	char arStart[arMagicSize + 1] = {};
	inputStream.read(arStart, arMagicSize);

	// Check if it is archive.
	return arStart == archMagic || arStart == thinMagic;
}

} // anonymous namespace

namespace retdec {
namespace ar_extractor {

/**
 * Check if file is an archive (normal or thin).
 *
 * @param path input file path
 *
 * @return @c true if file is an archive, @c false otherwise
 */
bool isArchive(
	const std::string &path)
{
	std::ifstream inputFile(path, std::ifstream::binary);
	if (inputFile) {
		char start[arMagicSize + 1] = {};
		inputFile.read(start, arMagicSize);

		return start == archMagic || start == thinMagic;
	}

	return false;
}

/**
 * Check if file is a thin archive.
 *
 * @param path input file path
 *
 * @return @c true if file is a thin archive, @c false otherwise
 */
bool isThinArchive(
	const std::string &path)
{
	std::ifstream inputFile(path, std::ifstream::binary);
	if (inputFile) {
		char start[arMagicSize + 1] = {};
		inputFile.read(start, arMagicSize);

		return start == thinMagic;
	}

	return false;
}

/**
 * Check if file is a normal (not thin) archive.
 *
 * @param path input file path
 *
 * @return @c true if file is a normal archive, @c false otherwise
 */
bool isNormalArchive(
	const std::string &path)
{
	std::ifstream inputFile(path, std::ifstream::binary);
	if (inputFile) {
		char start[arMagicSize + 1] = {};
		inputFile.read(start, arMagicSize);

		return start == archMagic;
	}

	return false;
}

/**
 * Check if file is a Mach-O Universal Binary archive.
 *
 * @param path input file path
 *
 * @return @c true if file is a Mach-O archive, @c false otherwise
 */
bool isFatMachOArchive(
	const std::string &path)
{
	std::ifstream inputFile(path, std::ifstream::binary);
	if (inputFile) {
		// Load start of the file.
		char start[fatLoadSize] = {};
		inputFile.read(start, fatLoadSize);

		// Interpret as main fat header.
		auto* header = reinterpret_cast<fat_header*>(start);
		swapStructByteOrderIfNecessary(*header);

		// Check 32-bit files.
		if (header->magic == FAT_CIGAM || header->magic == FAT_MAGIC) {
			auto* arch = reinterpret_cast<fat_arch*>(
				start + sizeof(fat_header));
			swapStructByteOrderIfNecessary(*arch);
			return checkArchMagicAtOffset(inputFile, arch->offset);
		}

		// Check 64-bit files.
		if (header->magic == FAT_CIGAM_64 || header->magic == FAT_MAGIC_64) {
			auto* arch = reinterpret_cast<fat_arch_64*>(
				start + sizeof(fat_header));
			swapStructByteOrderIfNecessary(*arch);
			return checkArchMagicAtOffset(inputFile, arch->offset);
		}
	}

	return false;
}

} // namespace ar_extractor
} // namespace retdec
