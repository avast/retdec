/**
 * @file include/retdec/macho-extractor/break_fat.h
 * @brief Definition of BreakMachOUniversal class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_MACHO_EXTRACTOR_BREAK_FAT_H
#define RETDEC_MACHO_EXTRACTOR_BREAK_FAT_H

#include <llvm/Object/MachO.h>
#include <llvm/Object/MachOUniversal.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/MachO.h>

namespace retdec {
namespace macho_extractor {

class BreakMachOUniversal
{
	private:
		bool valid = false;
		bool isStatic = false;

		std::string path;
		std::unique_ptr<llvm::object::MachOUniversalBinary> file;
		llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffer;

		/// @brief Auxiliary methods
		/// @{
		bool isArchive();
		const char* getFileBufferStart();
		bool getByArchFamily(
				std::uint32_t cpuType,
				llvm::object::MachOUniversalBinary::object_iterator &res);
		bool extract(
				llvm::object::MachOUniversalBinary::object_iterator &object,
				const std::string &outPath);
		bool getObjectNamesForArchive(
				std::uintptr_t archOffset ,
				std::size_t archSize,
				std::vector<std::string> &result);
		/// @}

	public:
		BreakMachOUniversal(const std::string &path);
		~BreakMachOUniversal();

		/// @brief Information methods
		/// @{
		bool isValid();
		bool isStaticLibrary();
		bool listArchitectures(
				std::ostream &output,
				bool withObjects = false);
		bool listArchitecturesJson(
				std::ostream &output,
				bool withObjects = false);
		/// @}

		/// @brief Extracting methods
		/// @{
		bool extractAllArchives();
		bool extractBestArchive(
				const std::string &outPath);
		bool extractArchiveWithIndex(
				unsigned index,
				const std::string &outPath);
		bool extractArchiveForFamily(
				const std::string &familyName,
				const std::string &outPath);
		bool extractArchiveForArchitecture(
				const std::string &machoArchName,
				const std::string &outPath);
		/// @}
};

} // namespace macho_extractor
} // namespace retdec

#endif
