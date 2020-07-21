/**
 * @file src/fileinfo/file_wrapper/pe_wrapper.h
 * @brief Definition of PeWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_H
#define FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_H

#include "retdec/fileformat/file_format/pe/pe_format.h"
#include "fileinfo/file_information/file_information_types/symbol_table/symbol.h"
#include "fileinfo/file_information/file_information_types/data_directory.h"
#include "fileinfo/file_information/file_information_types/file_section.h"

namespace retdec {
namespace fileinfo {

/**
 * Wrapper for parsing PE files
 */

class PeWrapper : public retdec::fileformat::PeFormat
{
	public:
		PeWrapper(const std::string & pathToFile, const std::string & dllListFile, retdec::fileformat::LoadFlags loadFlags);

		std::uint32_t getBits()
		{
			return file->getBits();
		}

		/// @name Detection methods
		/// {
		std::string getTypeOfFile() const;
		std::string getPeType() const;
		bool getDataDirectory(unsigned long long dirIndex, DataDirectory &directory) const;
		bool getFileSection(unsigned long long secIndex, FileSection &section) const;
		bool getCoffSymbol(unsigned long long index, Symbol &symbol) const;
		/// }
};

} // namespace fileinfo
} // namespace retdec

#endif
