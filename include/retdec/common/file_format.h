/**
 * @file include/retdec/common/file_format.h
 * @brief Common file format representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_FILE_FORMAT_H
#define RETDEC_COMMON_FILE_FORMAT_H

#include <string>

namespace retdec {
namespace common {

/**
 * Represents input binary's file format.
 * In particular its type (i.e ELF, PE, COFF) and bit size (i.e. 32, 64).
 */
class FileFormat
{
	public:
		/// @name File format query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isElf() const;
		bool isElf32() const;
		bool isElf64() const;
		bool isPe() const;
		bool isPe32() const;
		bool isPe64() const;
		bool isCoff() const;
		bool isCoff32() const;
		bool isCoff64() const;
		bool isMacho() const;
		bool isMacho32() const;
		bool isMacho64() const;
		bool isIntelHex() const;
		bool isIntelHex16() const;
		bool isIntelHex32() const;
		bool isIntelHex64() const;
		bool isRaw() const;
		bool isRaw32() const;
		bool isRaw64() const;
		bool is16bit() const;
		bool is32bit() const;
		bool is64bit() const;
		bool isFileClassBits(unsigned b) const;
		/// @}

		/// @name File format set methods.
		/// @{
		void setIsUnknown();
		void setIsElf();
		void setIsElf32();
		void setIsElf64();
		void setIsPe();
		void setIsPe32();
		void setIsPe64();
		void setIsCoff();
		void setIsCoff32();
		void setIsCoff64();
		void setIsMacho();
		void setIsMacho32();
		void setIsMacho64();
		void setIsIntelHex();
		void setIsIntelHex16();
		void setIsIntelHex32();
		void setIsIntelHex64();
		void setIsRaw();
		void setIsRaw32();
		void setIsRaw64();
		void setName(const std::string& n);
		void setIs16bit();
		void setIs32bit();
		void setIs64bit();
		void setFileClassBits(unsigned b);
		/// @}

		/// @name File format get methods.
		/// @{
		std::string getName() const;
		unsigned getFileClassBits() const;
		/// @}

	private:
		enum eFileFormat
		{
			FF_UNKNOWN = 0,
			FF_ELF,
			FF_PE,
			FF_COFF,
			FF_IHEX,
			FF_MACHO,
			FF_RAW
		};

	private:
		eFileFormat _fileFormat = FF_UNKNOWN;
		/// This is bit size associated with file format.
		/// It does not have to be the same as target architecture bit size.
		unsigned _fileClassBits = 0;
};

} // namespace common
} // namespace retdec

#endif
