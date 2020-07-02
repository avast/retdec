/**
 * @file include/retdec/fileformat/types/sec_seg/sec_seg.h
 * @brief Basic class for section and segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_SEC_SEG_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_SEC_SEG_H

#include <string>
#include <vector>

#include <llvm/ADT/StringRef.h>

namespace retdec {
namespace fileformat {

class FileFormat;

/**
 * Base class for section and segment
 */
class SecSeg
{
	public:
		enum class Type
		{
			UNDEFINED_SEC_SEG, ///< undefined
			CODE,              ///< code
			DATA,              ///< data
			CODE_DATA,         ///< code and (or) data
			CONST_DATA,        ///< constant data
			BSS,               ///< uninitialized data
			DEBUG,             ///< debug information
			INFO               ///< auxiliary information
		};
	private:
		std::string crc32;                    ///< CRC32 of section or segment data
		std::string md5;                      ///< MD5 of section or segment data
		std::string sha256;                   ///< SHA256 of section or segment data
		std::string name;                     ///< name of section or segment
		llvm::StringRef bytes;                ///< reference to content of section or segment
		Type type = Type::UNDEFINED_SEC_SEG;  ///< type
		unsigned long long index = 0;         ///< index
		unsigned long long offset = 0;        ///< start offset in file
		unsigned long long fileSize = 0;      ///< size in file
		unsigned long long address = 0;       ///< start address in memory
		unsigned long long memorySize = 0;    ///< size in memory
		unsigned long long entrySize = 0;     ///< size of one entry in file
		double entropy = 0.0;                 ///< entropy in <0,8>
		bool memorySizeIsValid = false;       ///< @c true if size in memory is valid
		bool entrySizeIsValid = false;        ///< size of one entry in section or segment
		bool isInMemory = false;              ///< @c true if the section or segment will appear in the memory image of a process
		bool loaded = false;                  ///< @c true if content of section or segment was successfully loaded from input file
		bool isEntropyValid = false;          ///< @c true if entropy has been computed

		void computeHashes();
	public:
		virtual ~SecSeg() = default;

		/// @name Query methods
		/// @{
		bool isUndefined() const;
		bool isCode() const;
		bool isData() const;
		bool isCodeAndData() const;
		bool isConstData() const;
		bool isBss() const;
		bool isDebug() const;
		bool isInfo() const;
		bool isSomeData() const;
		bool isSomeCode() const;
		bool isDataOnly() const;
		bool isReadOnly() const;
		/// @}

		/// @name Virtual query methods
		/// @{
		virtual bool isValid(const FileFormat *sOwner) const;
		/// @}

		/// @name Getters
		/// @{
		std::string getCrc32() const;
		std::string getMd5() const;
		std::string getSha256() const;
		std::string getName() const;
		const char* getNameAsCStr() const;
		const llvm::StringRef getBytes(unsigned long long sOffset = 0, unsigned long long sSize = 0) const;
		SecSeg::Type getType() const;
		unsigned long long getIndex() const;
		unsigned long long getOffset() const;
		unsigned long long getEndOffset() const;
		unsigned long long getSizeInFile() const;
		unsigned long long getLoadedSize() const;
		unsigned long long getAddress() const;
		unsigned long long getEndAddress() const;
		bool getSizeInMemory(unsigned long long &sMemorySize) const;
		bool getSizeOfOneEntry(unsigned long long &sEntrySize) const;
		bool getMemory() const;
		bool getEntropy(double &res) const;

		/**
		 * Read bytes from the given offset as a number of the given type.
		 * @param sOffset Index from which the number should be read.
		 * @return The read number. Returns zero if the offset is out-of-bounds or
		 *         if there are not enough bytes to read.
		 * @tparam NumberType Type of the number to read and return.
		 */
		template<typename NumberType>
		NumberType getBytesAtOffsetAsNumber(unsigned long long sOffset) const
		{
			if(bytes.size() < sizeof(NumberType) || sOffset > bytes.size() - sizeof(NumberType))
			{
				return {};
			}

			auto rawBytes = bytes.data();
			return *reinterpret_cast<const NumberType *>(&rawBytes[sOffset]);
		}
		/// @}

		/// @name Getters of section or segment content
		/// @{
		bool getBits(std::string &sResult) const;
		bool getBytes(std::vector<unsigned char> &sResult, unsigned long long sOffset = 0, unsigned long long sSize = 0) const;
		bool getString(std::string &sResult, unsigned long long sOffset = 0, unsigned long long sSize = 0) const;
		bool getHexBytes(std::string &sResult) const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string sName);
		void setType(SecSeg::Type sType);
		void setIndex(unsigned long long sIndex);
		void setOffset(unsigned long long sOffset);
		void setSizeInFile(unsigned long long sFileSize);
		void setAddress(unsigned long long sAddress);
		void setSizeInMemory(unsigned long long sMemorySize);
		void setSizeOfOneEntry(unsigned long long sEntrySize);
		void setMemory(bool sMemory);
		/// @}

		/// @name Other methods
		/// @{
		void computeEntropy();
		void invalidateMemorySize();
		void invalidateEntrySize();
		void load(const FileFormat *sOwner);
		void dump(std::string &sDump) const;
		bool hasCrc32() const;
		bool hasMd5() const;
		bool hasSha256() const;
		bool hasEmptyName() const;
		bool belong(unsigned long long sAddress) const;
		bool operator<(const SecSeg &sOther) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
