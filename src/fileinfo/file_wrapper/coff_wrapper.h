/**
 * @file src/fileinfo/file_wrapper/coff_wrapper.h
 * @brief Definition of CoffWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_COFF_WRAPPER_H
#define FILEINFO_FILE_WRAPPER_COFF_WRAPPER_H

#include "retdec/fileformat/file_format/coff/coff_format.h"
#include "fileinfo/file_information/file_information_types/file_section.h"
#include "fileinfo/file_information/file_information_types/symbol_table/symbol.h"

namespace fileinfo {

/**
 * Wrapper for parsing COFF files
 */
class CoffWrapper : public retdec::fileformat::CoffFormat
{
	public:
		CoffWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags);
		virtual ~CoffWrapper() override;

		/// @name Detection methods
		/// {
		const llvm::object::COFFObjectFile* getCoffParser() const;
		std::string getTypeOfFile() const;
		/// }
};

} // namespace fileinfo

#endif
