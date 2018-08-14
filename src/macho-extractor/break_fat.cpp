/**
 * @file src/macho-extractor/break_fat.cpp
 * @brief Definition of BreakMachOUniversal class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <fstream>

#include <llvm/Support/MachO.h>
#include <llvm/Support/Path.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/macho-extractor/break_fat.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using namespace llvm;
using namespace llvm::MachO;
using namespace llvm::object;
using namespace llvm::sys;
using namespace rapidjson;
using namespace retdec::utils;

namespace {

constexpr auto AR_NAME_OFFSET = 0U;
constexpr auto AR_NAME_SIZE = 16U;

constexpr auto AR_SIZE_OFFSET = 48U;
constexpr auto AR_SIZE_SIZE = 10U;

constexpr auto AR_HEADER_SIZE = 60U;

/**
 * Returns name of architecture as valid --family option value
 * @param cpuType Mach-O specific CPU number
 * @return name of valid --arch option value
 */
std::string cpuTypeToString(
		std::uint32_t cpuType)
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
 * Return LLVM name of architecture
 * @param it object iterator
 * @return LLVM architecture name
 *
 * Function returns RetDec name if LLVM function fails to provide name.
 */
std::string getArchName(
		MachOUniversalBinary::object_iterator &it)
{
	std::string result = it->getArchTypeName();
	if(result.empty())
	{
		result = cpuTypeToString(it->getCPUType());
	}

	return result;
}

} // anonymous namespace

namespace retdec {
namespace macho_extractor {

/**
 * BreakMachOUniversal constructor
 * @param filePath path to input file
 *
 * Verify success with isValid() function.
 */
BreakMachOUniversal::BreakMachOUniversal(
		const std::string &filePath)
	: path(filePath), buffer(MemoryBuffer::getFile(Twine(filePath)))
{
	if(buffer && !buffer.getError())
	{
		auto object = MachOUniversalBinary::create(
						buffer.get()->getMemBufferRef());
		if(!object)
		{
			// Unhandled errors cause abort()
			consumeError(object.takeError());
			valid = false;
		}
		else
		{
			file = std::move(object.get());
			isStatic = isArchive();
			valid = true;
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
bool BreakMachOUniversal::isArchive()
{
	if(!file->getNumberOfObjects())
	{
		// No objects!
		return false;
	}

	auto result = file->begin_objects()->getAsArchive();
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
 * Get file memory buffer start
 * @return pointer to file memory buffer start
 */
const char *BreakMachOUniversal::getFileBufferStart()
{
	return buffer.get()->getBufferStart();
}

/**
 * Get Mach-O Universal object iterator by architecture
 * @param cpuType Mach-O specific CPU type constant
 * @param res reference for storing result
 * @return @c true if object with @p cpuType was found, @c false otherwise
 */
bool BreakMachOUniversal::getByArchFamily(
		std::uint32_t cpuType,
		llvm::object::MachOUniversalBinary::object_iterator &res)
{
	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
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
 * Extract object by iterator
 * @param it object iterator
 * @param outPath output file path
 * @return @c true if object was created successfully, @c false otherwise
 */
bool BreakMachOUniversal::extract(
		llvm::object::MachOUniversalBinary::object_iterator &it,
		const std::string &outPath)
{
	std::ofstream output(outPath, std::ios::binary);
	if(output)
	{
		output.write(getFileBufferStart() + it->getOffset(), it->getSize());
		return output.good();
	}

	return false;
}

/**
 * Get file names of objects stored in archive
 * @param archOffset start of archive in Mach-O Universal Binary
 * @param archSize size of archive in Mach-O Universal Binary
 * @param result vector with names
 * @return @c true if names were retrieved successfully, @c false otherwise
 *
 * Actual LLVM implementation is problematic but changed a lot in newer
 * versions, so in future, it may be possible to remove this function and use
 * getAsArchive function and llvm::Archive interface instead.
 *
 * Function is fit only for Apple OS (BSD) archive variant used in Mach-O.
 */
bool BreakMachOUniversal::getObjectNamesForArchive(
		std::uintptr_t archOffset,
		std::size_t archSize,
		std::vector<std::string> &result)
{
	result.clear();
	const char* buff = getFileBufferStart();

	// Add 8 bytes to skip arch signature
	std::uintptr_t start = archOffset + 8;
	std::uintptr_t end = start + archSize - AR_HEADER_SIZE;

	while(start < end)
	{
		// Archive attributes in header are stored as ASCII text
		std::string nameStr = trim(std::string(
									buff + start + AR_NAME_OFFSET,
									AR_NAME_SIZE), " ");
		std::string sizeStr = trim(std::string(
									buff + start + AR_SIZE_OFFSET,
									AR_SIZE_SIZE), " ");

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
			std::string nameSizeStr = nameStr.substr(strlen(longNameMagic),
													std::string::npos);
			std::uint64_t nameSize = 0;
			if(!strToNum(nameSizeStr, nameSize, std::dec))
			{
				return false;
			}
			nameStr = std::string(buff + start + AR_HEADER_SIZE, nameSize);
			// Name is sometimes aligned with trailing zeros
			nameStr = std::string(nameStr.c_str());
		}

		// Ignore symbol tables
		if(!startsWith(nameStr, "__.SYMDEF"))
		{
			result.push_back(nameStr);
		}
		start += AR_HEADER_SIZE + size;
	}

	return true;
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
 * Check if input binary contains static library
 * @return @c true if file is fat Mach-O static library, @c false otherwise
 */
bool BreakMachOUniversal::isStaticLibrary()
{
	return isStatic;
}

/**
 * List all architectures contained in fat Mach-O
 * @param output stream to print result to
 * @param withObjects @c true when archive content is to be included
 * @return @c true if all actions were successful, @c false otherwise
 */
bool BreakMachOUniversal::listArchitectures(
		std::ostream &output,
		bool withObjects)
{
	if(!file)
	{
		return false;
	}

	unsigned archIndex = 0;
	output << "Index\tName\tFamily\n";
	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
	{
		if(isStatic && withObjects && archIndex != 0)
		{
			output << "\n\n";
			output << "Index\tName\tFamily\n";
		}

		output << archIndex++ << "\t";
		output << getArchName(i) << "\t";
		output << cpuTypeToString(i->getCPUType()) << "\n";

		if(isStatic && withObjects)
		{
			std::vector<std::string> names;
			if(!getObjectNamesForArchive(i->getOffset(), i->getSize(), names))
			{
				return false;
			}

			if(names.empty())
			{
				output << "\n\tEmpty archive.\n";
				continue;
			}

			output << "\n\tIndex\tName\n";
			unsigned childIndex = 0;
			for(const auto &name : names)
			{
				output << "\t" << childIndex++ << "\t" << name << "\n";
			}
		}
	}

	// Write warning when --object option is used on non-archive target.
	if(!isStatic && withObjects)
	{
		std::cerr << "Warning: input file is not an archive! (--objects)\n";
	}

	return output.good();
}

/**
 * List all architectures contained in fat Mach-O in JSON format
 * @param output stream to print result to
 * @param withObjects @c true when archive content is to be included
 * @return @c true if all actions were successful, @c false otherwise
 */
bool BreakMachOUniversal::listArchitecturesJson(
		std::ostream &output,
		bool withObjects)
{
	if(!file)
	{
		return false;
	}

	Document outDoc(kObjectType);
	auto& allocator = outDoc.GetAllocator();
	Value architectures(kArrayType);

	unsigned archIndex = 0;
	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
	{
		Value arch(kObjectType);
		Value objects(kArrayType);

		auto name = getArchName(i);
		auto family = cpuTypeToString(i->getCPUType());
		arch.AddMember("index", archIndex++, allocator);
		arch.AddMember(
					"name",
					Value(name.c_str(), allocator).Move(),
					allocator);
		arch.AddMember(
					"cpuFamily",
					Value(family.c_str(), allocator).Move(),
					allocator);

		if(isStatic && withObjects)
		{
			std::vector<std::string> names;
			if(!getObjectNamesForArchive(i->getOffset(), i->getSize(), names))
			{
				return false;
			}

			unsigned childIndex = 0;
			for(const auto &name : names)
			{
				Value obj(kObjectType);
				obj.AddMember(
							"name",
							Value(name.c_str(), allocator).Move(),
							allocator);
				obj.AddMember("index", childIndex++, allocator);
				objects.PushBack(obj, allocator);
			}
			arch.AddMember("objects", objects, allocator);
		}
		architectures.PushBack(arch, allocator);
	}

	// Write warning when --object option is used on non-archive target.
	if(!isStatic && withObjects)
	{
		outDoc.AddMember(
					"warning", "input file is not an archive! (--objects)",
					allocator);
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
 * @return @c true if extraction was successful, @c false otherwise
 */
bool BreakMachOUniversal::extractAllArchives()
{
	if(!file)
	{
		return false;
	}

	const char *bytes = getFileBufferStart();
	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
	{
		// Object within Mach-O Universal Binary are not named
		auto fpath = path::filename(path).str() + "." + getArchName(i);
		fpath += isStatic ? ".a" : "";

		std::ofstream output(fpath, std::ios::binary);
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
 * @param outPath output file path
 * @return @c true if extraction was successful, @c false otherwise
 */
bool BreakMachOUniversal::extractBestArchive(
		const std::string &outPath)
{
	if(!file)
	{
		return false;
	}

	auto obj = file->begin_objects();
	if(getByArchFamily(CPU_TYPE_X86, obj)
			|| getByArchFamily(CPU_TYPE_ARM, obj)
			|| getByArchFamily(CPU_TYPE_POWERPC, obj))
	{
		return extract(obj, outPath);
	}

	// If none of above, just pick first.
	return extract(obj, outPath);
}

/**
 * Extract archive with selected index
 * @param index index of archive to extract
 * @param outPath output file path
 * @return @c true if extraction was successful, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveWithIndex(
		unsigned index,
		const std::string &outPath)
{
	if(!file || index >= file->getNumberOfObjects())
	{
		return false;
	}

	unsigned idx = 0;
	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
	{
		if(index == idx++)
		{
			return extract(i, outPath);
		}
	}

	return false;
}

/**
 * Extract archive by architecture family
 * @param familyName  family name
 * @param outPath path to output file
 * @return @c true if extraction was successful, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveForFamily(
		const std::string &familyName,
		const std::string &outPath)
{
	if(!file)
	{
		return false;
	}

	auto obj = file->begin_objects();
	if(familyName == "x86")
	{
		if(getByArchFamily(CPU_TYPE_X86, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "arm" || familyName == "thumb")
	{
		// Same family
		if(getByArchFamily(CPU_TYPE_ARM, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "powerpc")
	{
		if(getByArchFamily(CPU_TYPE_POWERPC, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "x86-64")
	{
		if(getByArchFamily(CPU_TYPE_X86_64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "arm64")
	{
		if(getByArchFamily(CPU_TYPE_ARM64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "powerpc64")
	{
		if(getByArchFamily(CPU_TYPE_POWERPC64, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "sparc")
	{
		if(getByArchFamily(CPU_TYPE_SPARC, obj))
		{
			return extract(obj, outPath);
		}
	}
	else if(familyName == "mc98000")
	{
		if(getByArchFamily(CPU_TYPE_MC98000, obj))
		{
			return extract(obj, outPath);
		}
	}

	return false;
}

/**
 * Extract archive by architecture
 * @param machoArchName Mach-O specific architecture string
 * @param outPath path to output file
 * @return @c true if extraction was successful, @c false otherwise
 */
bool BreakMachOUniversal::extractArchiveForArchitecture(
		const std::string &machoArchName,
		const std::string &outPath)
{
	if(!file)
	{
		return false;
	}

	for(auto i = file->begin_objects(), e = file->end_objects(); i != e; ++i)
	{
		if(machoArchName == getArchName(i))
		{
			return extract(i, outPath);
		}
	}

	return false;
}

} // namespace macho_extractor
} // namespace retdec
