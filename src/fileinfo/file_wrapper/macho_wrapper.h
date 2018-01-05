/**
 * @file src/fileinfo/file_wrapper/macho_wrapper.h
 * @brief Definition of MachOWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_MACHO_WRAPPER_H
#define FILEINFO_FILE_WRAPPER_MACHO_WRAPPER_H

#include "retdec/fileformat/file_format/macho/macho_format.h"

namespace fileinfo {

/**
 * Wrapper for parsing MachO files
 */
class MachOWrapper : public retdec::fileformat::MachOFormat
{
	public:
		MachOWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags);
		virtual ~MachOWrapper() override;

		/// @name Detection methods
		/// {
		const llvm::object::MachOObjectFile* getMachOParser() const;
		std::string getTypeOfFile() const;
		/// }
};

} // namespace fileinfo

#endif
