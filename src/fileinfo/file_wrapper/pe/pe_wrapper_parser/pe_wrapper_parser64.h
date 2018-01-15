/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser64.h
 * @brief Definition of PeWrapperParser64 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER64_H
#define FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER64_H

#include <pelib/PeLib.h>

#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser.h"

namespace fileinfo {

class PeWrapperParser64 : public PeWrapperParser
{
	private:
		PeLib::PeHeaderT<64> peHeader; ///< header of 64-bit PE file
	public:
		PeWrapperParser64(PeLib::PeHeaderT<64> peHeader64);
		virtual ~PeWrapperParser64() override;

		/// @name Detection methods
		/// @{
		virtual std::string getPeType() const override;
		virtual bool getSection(const unsigned long long secIndex, FileSection &section) const override;
		/// @}
};

} // namespace fileinfo

#endif
