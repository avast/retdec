/**
 * @file src/macho-extractor/break_fat.cpp
 * @brief Definition of BreakMachOUniversal class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include <llvm/Support/MachO.h>
#include <llvm/Support/Path.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/macho-extractor/break_fat.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::MachO;
using namespace llvm::object;
using namespace llvm::sys;
using namespace rapidjson;

namespace {
constexpr auto AR_NAME_OFFSET = 0U;
constexpr auto AR_SIZE_OFFSET = 48U;

constexpr auto AR_NAME_SIZE = 16U;
constexpr auto AR_SIZE_SIZE = 10U;
constexpr auto AR_HEADER_SIZE = 60U;
}

namespace retdec {
namespace macho_extractor {

/**
 * BreakMachOUniversal constructor
 * @param filePath Path to input file
 *
 * Verify success with isValid() function
 */
BreakMachOUniversal::BreakMachOUniversal(const std::string &filePath) : filePath(filePath),
	fileBuffer(MemoryBuffer::getFile(Twine(filePath)))
{
	if(fileBuffer && !fileBuffer.getError())
	{
		auto object = MachOUniversalBinary::create(fileBuffer.get()->getMemBufferRef());
		if(!object)
		{
			// Call consumeError in case of error to "handle" it
			// Unhandled errors cause abort()
			consumeError(object.takeError());
			valid = false;
		}
		else
		{
			fatFile = std::move(object.get());
			// Check if file contains static libraries.
			valid = isStaticLibrary();
		}
	}
	else
	{
		valid = false;
	}
}

/**
 * BreakMachOUniversal destructor
 */
BreakMachOUniversal::~BreakMachOUniversal()
{
}

/**
 * Check if input binary contains static libraries
 * @return @c true if file contains static libraries, @c false otherwise
 */
bool BreakMachOUniversal::isStaticLibrary()
{
	if(!fatFile->getNumberOfObjects())
	{
		// No objects!
		return false;
	}

	auto result = fatFile->begin_objects()->getAsArchive();
	if(!result)
	{
		// Call consumeError in case of error to "handle" it
		// Unhandled errors cause abort()
		consumeError(result.takeError());
		return false;
	}

	return true;
}

/**
 * BreakMachOUniversal::isSupported
 * @param cpuType Mach-O specific CPU type constant
 * @return @c true is architecture is supported by decompiler, @c false otherwise
 */
bool BreakMachOUniversal::isSupported(std::uint32_t cpuType)
{
	switch(cpuType)
	{
		case CPU_TYPE_ARM:
		case CPU_TYPE_I386:
		case CPU_TYPE_POWERPC:
			return true;
		default:
			return false;
	}
	return false;
}

/**
 * Get file memory buffer start
 * @return Pointer to file memory buffer start
 */
const char *BreakMachOUniversal::getFileBufferStart()
{
	return fileBuffer.get()->getBufferStart();
}

/**
 * Get Mach-O Universal object iterator by architecture
 * @param cpuType Mach-O specific CPU type constant
 * @param res Resulting iterator
 * @return @c true if object with selected CPU type was found, @c false otherwise
 */
bool BreakMachOUniversal::getByArchFamily(std::uint32_t cpuType, MachOUniversalBinary::object_iterator &res)
{
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		if(cpuType == i->getCPUType())
		{
			res = i;
			return true;
		}
	}

	return false;
}

/**
 * Extract object pointed by iterator
 * @param object Object iterator
 * @param outPath Output file path
 * @return @c true if archive was created successfully, @c false otherwise
 */
bool BreakMachOUniversal::extract(MachOUniversalBinary::object_iterator &object, const std::string &outPath)
{
	std::ofstream output(outPath, std::ios::binary);
	if(!output.is_open())
	{
		return false;
	}
	if(!output.write(getFileBufferStart() + object->getOffset(), object->getSize()))
	{
		return false;
	}
	return true;
}

/**
 * Get file names of objects stored in archive
 * @param archOffset Start of archive in Mach-O Universal Binary
 * @param archSize Size of archive in Mach-O Universal Binary
 * @param result Vector with names
 * @return @c true if names were retrieved successfully, @c false otherwise
 *
 * Actual LLVM implementation is problematic but changed a lot in newer versions,
 * so in future, it may be possible to remove this function and use getAsArchive
 * function and llvm::Archive interface instead.
 *
 * Function is fit only for Apple OS (BSD) archive variant.
 */
bool BreakMachOUniversal::getObjectNamesForArchive(std::uintptr_t archOffset,
						std::size_t archSize, std::vector<std::string> &result)
{
	result.clear();
	const char* buffStart = getFileBufferStart();

	// Add 8 bytes to skip arch signature
	std::uintptr_t offset = archOffset + 8;
	std::uintptr_t endOffset = offset + archSize - AR_HEADER_SIZE;

	while(offset < endOffset)
	{
		// Archive attributes in header are stored as ASCII text
		std::string nameStr = trim(std::string(buffStart + offset + AR_NAME_OFFSET, AR_NAME_SIZE), " ");
		std::string sizeStr = trim(std::string(buffStart + offset + AR_SIZE_OFFSET, AR_SIZE_SIZE), " ");

		// Get size
		std::uint64_t size = 0;
		if(!strToNum(sizeStr, size, std::dec))
		{
			return false;
		}

		const char *longNameMagic = "#1/";
		if(startsWith(nameStr, longNameMagic))
		{
			// Cut '#1/' a convert to number
			std::string nameSizeStr = nameStr.substr(strlen(longNameMagic), std::string::npos);
			std::uint64_t nameSize = 0;
			if(!strToNum(nameSizeStr, nameSize, std::dec))
			{
				return false;
			}
			nameStr = std::string(buffStart + offset + AR_HEADER_SIZE, nameSize);
			// Name is sometimes aligned with trailing zeroes
			nameStr = std::string(nameStr.c_str());
		}

		// Ignore symbol tables
		if(!startsWith(nameStr, "__.SYMDEF"))
		{
			result.push_back(nameStr);
		}
		offset += AR_HEADER_SIZE + size;
	}
	return true;
}

/**
 * Returns name of architecture as valid --family option value
 * @param cpuType Mach-O specific CPU number
 * @return Name of valid --arch option value
 */
std::string BreakMachOUniversal::cpuTypeToString(std::uint32_t cpuType)
{
	switch(cpuType)
	{
		case CPU_TYPE_ARM:
			return "arm";
		case CPU_TYPE_I386:
			return "x86";
		case CPU_TYPE_POWERPC:
			return "powerpc";
		case CPU_TYPE_ARM64:
			return "arm64";
		case CPU_TYPE_X86_64:
			return "x86-64";
		case CPU_TYPE_POWERPC64:
			return "powerpc64";
		case CPU_TYPE_SPARC:
			return "sparc";
		case CPU_TYPE_MC98000:
			return "mc98000";
		default:
			return "unknown";
	}
}

/**
 * Verify state of instance after construction
 * @return @c true if file was read successfully, @c false otherwise
 */
bool BreakMachOUniversal::isValid()
{
	return valid;
}

/**
 * List architectures
 * @param output Stream to print result to
 * @param withObjects @c true when archives content is to be included
 * @return @c true if file was read successfully, @c false otherwise
 */
bool BreakMachOUniversal::listArchitectures(std::ostream &output, bool withObjects)
{
	if (!fatFile)
	{
		return false;
	}

	unsigned archIndex = 0;
	output << "Index\tName\tFamily\tSupported\n";
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		if(withObjects && archIndex != 0)
		{
			output << "\n\n";
			output << "Index\tName\tFamily\tSupported\n";
		}

		output << std::to_string(archIndex++) << "\t";
		output << i->getArchTypeName() << "\t";
		output << cpuTypeToString(i->getCPUType()) << "\t";
		isSupported(i->getCPUType()) ? output << "yes\n" : output << "no\n";

		if(withObjects)
		{
			std::vector<std::string> objNames;
			if(!getObjectNamesForArchive(i->getOffset(), i->getSize(), objNames))
			{
				return false;
			}

			if(objNames.empty())
			{
				output << "\n\tEmpty archive.\n";
				continue;
			}
			output << "\n\tIndex\tName\n";

			unsigned childIndex = 0;
			for(const auto &name : objNames)
			{
				output << "\t" << childIndex++ << "\t" << name << "\n";
			}
		}
	}
	return output.good();
}

/**
 * List architectures in JSON format
 * @param output Stream to print result to
 * @param withObjects @c true when archives content is to be included
 * @return @c true if file was read successfully, @c false otherwise
 */
bool BreakMachOUniversal::listArchitecturesJson(std::ostream &output, bool withObjects)
{
	if (!fatFile)
	{
		return false;
	}

	Document outDoc(kObjectType);
	auto& allocator = outDoc.GetAllocator();
	Value architectures(kArrayType);

	unsigned archIndex = 0;
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		Value arch(kObjectType);
		Value objects(kArrayType);
		arch.AddMember("index", archIndex++, allocator);
		arch.AddMember("name", Value(i->getArchTypeName().c_str(), allocator).Move(), allocator);
		arch.AddMember("cpuFamily", Value(cpuTypeToString(i->getCPUType()).c_str(), allocator).Move(), allocator);
		arch.AddMember("supported", isSupported(i->getCPUType()), allocator);

		if(withObjects)
		{
			std::vector<std::string> objNames;
			if(!getObjectNamesForArchive(i->getOffset(), i->getSize(), objNames))
			{
				return false;
			}

			unsigned childIndex = 0;
			for(const auto &name : objNames)
			{
				Value obj(kObjectType);
				obj.AddMember("name", Value(name.c_str(), allocator).Move(), allocator);
				obj.AddMember("index", childIndex++, allocator);
				objects.PushBack(obj, allocator);
			}
			arch.AddMember("objects", objects, allocator);
		}
		architectures.PushBack(arch, allocator);
	}
	outDoc.AddMember("architectures", architectures, allocator);

	StringBuffer outBuffer;
	PrettyWriter<StringBuffer> outWriter(outBuffer);
	outDoc.Accept(outWriter);

	output << outBuffer.GetString();
	return output.good();
}

/**
 * Extract all archives, simulates ar x behavior
 * @return @c true if all files were extracted successfully, @c false otherwise
 */
bool BreakMachOUniversal::extractAllArchives()
{
	if (!fatFile)
	{
		return false;
	}

	const char *bytes = getFileBufferStart();
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		// Object within Mach-O Universal Binary are not named
		// Name will be created from architecture and file name
		std::string arch = i->getArchTypeName();
		// Print files
		std::ofstream output(path::filename(filePath).str() + "." + arch + ".a", std::ios::binary);
		if(!output.is_open())
		{
			return false;
		}
		if(!output.write(bytes + i->getOffset(), i->getSize()))
		{
			return false;
		}
	}
	return true;
}

/**
 * Extract archive with best architecture for decompilation
 * @param outPath Output file path
 */
bool BreakMachOUniversal::extractBestArchive(const std::string &outPath)
{
	if (!fatFile)
	{
		return false;
	}

	auto obj = fatFile->begin_objects();
	if(getByArchFamily(CPU_TYPE_X86, obj) || getByArchFamily(CPU_TYPE_ARM, obj) || getByArchFamily(CPU_TYPE_POWERPC, obj))
	{
		return extract(obj, outPath);
	}
	else
	{
		// If none of above, just pick first.
		return extract(obj, outPath);
	}
}

/**
 * Extract archive on selected index
 * @param index Index of archive to extract
 * @param outPath Output file path
 * @return @c true on success, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveWithIndex(unsigned index, const std::string &outPath)
{
	if(!fatFile || index >= fatFile->getNumberOfObjects())
	{
		return false;
	}

	unsigned idx = 0;
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		if(index != idx++)
		{
			continue;
		}
		return extract(i, outPath);
	}
	return false;
}

/**
 * Extract archive by architecture family
 * @param archFamilyName String with family name
 * @param outPath Path to output file
 * @return @c true on success, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveForFamily(const std::string &archFamilyName, const std::string &outPath)
{
	if (!fatFile)
	{
		return false;
	}

	auto obj = fatFile->begin_objects();
	if(archFamilyName == "x86")
	{
		if(getByArchFamily(CPU_TYPE_X86, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "arm" || archFamilyName == "thumb")
	{
		// Same family
		if(getByArchFamily(CPU_TYPE_ARM, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "powerpc")
	{
		if(getByArchFamily(CPU_TYPE_POWERPC, obj))
		{
			return extract(obj, outPath);
		}
	}
	if(archFamilyName == "x86-64")
	{
		if(getByArchFamily(CPU_TYPE_X86_64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "arm64")
	{
		if(getByArchFamily(CPU_TYPE_ARM64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "powerpc64")
	{
		if(getByArchFamily(CPU_TYPE_POWERPC64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "sparc")
	{
		if(getByArchFamily(CPU_TYPE_SPARC, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(archFamilyName == "mc98000")
	{
		if(getByArchFamily(CPU_TYPE_MC98000, obj))
		{
			return extract(obj, outPath);
		}
	}
	// Not supported by Mach-O format
	return false;
}

/**
 * Extract archive by architecture
 * @param machoArchName Mach-O specific architecture string
 * @param outPath Path to output file
 * @return @c true on success, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveForArchitecture(const std::string &machoArchName, const std::string &outPath)
{
	if (!fatFile)
	{
		return false;
	}

	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		std::string archName = i->getArchTypeName();
		if(archName != machoArchName)
		{
			// Not desired architecture.
			continue;
		}
		return extract(i, outPath);
	}
	return false;
}

} // namespace macho_extractor
} // namespace retdec
