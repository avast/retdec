/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser.h
 * @brief Definition of PeWrapperParser class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER_H
#define FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER_H

#include <string>

#include "fileinfo/file_information/file_information_types/data_directory.h"
#include "fileinfo/file_information/file_information_types/file_section.h"

namespace fileinfo {

class PeWrapperParser
{
	public:
		PeWrapperParser();
		virtual ~PeWrapperParser();

		/// @name Detection methods
		/// @{
		virtual std::string getPeType() const = 0;
		virtual bool getSection(const unsigned long long secIndex, FileSection &section) const = 0;
		/// @}
};

} // namespace fileinfo

#endif
