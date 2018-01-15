/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser32.h
 * @brief Definition of PeWrapperParser32 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER32_H
#define FILEINFO_FILE_WRAPPER_PE_PE_WRAPPER_PARSER_PE_WRAPPER_PARSER32_H

#include <pelib/PeLib.h>

#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser.h"

namespace fileinfo {

class PeWrapperParser32 : public PeWrapperParser
{
	private:
		PeLib::PeHeaderT<32> peHeader; ///< header of 32-bit PE file
	public:
		PeWrapperParser32(PeLib::PeHeaderT<32> peHeader32);
		virtual ~PeWrapperParser32() override;

		/// @name Detection methods
		/// @{
		virtual std::string getPeType() const override;
		virtual bool getSection(const unsigned long long secIndex, FileSection &section) const override;
		/// @}
};

} // namespace fileinfo

#endif
