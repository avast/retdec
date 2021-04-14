/**
 * @file include/retdec/fileformat/types/rich_header/rich_header.h
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RICH_HEADER_RICH_HEADER_H
#define RETDEC_FILEFORMAT_TYPES_RICH_HEADER_RICH_HEADER_H

#include <string>
#include <vector>

#include "retdec/fileformat/types/rich_header/linker_info.h"

namespace retdec {
namespace fileformat {

/**
 * Rich header
 */
class RichHeader
{
	private:
		using richHeaderIterator = std::vector<LinkerInfo>::const_iterator;
		std::string signature;           ///< header in string representation
		unsigned long long offset = 0;   ///< offset of rich header in file
		unsigned long long key = 0;      ///< key for decryption
		std::vector<LinkerInfo> header;  ///< all records in header
		bool isOffsetValid = false;      ///< @c true if @a offset is valid
		bool isKeyValid = false;         ///< @c true if @a key is valid
		bool isValidStructure = false;   ///< @c true if header has valid structure
		bool isSuspicious = false;       ///< @c true if content of header is suspicious
		std::vector<std::uint8_t> bytes; ///< decrypted content of rich header
		/// hashes of decrypted rich header
		std::string sha256;
		std::string md5;
		std::string crc32;
	public:
		/// @name Getters
		/// @{
		std::string getSignature() const;
		std::size_t getSignatureLength() const;
		bool getOffset(unsigned long long &richOffset) const;
		bool getKey(unsigned long long &richKey) const;
		std::size_t getNumberOfRecords() const;
		const LinkerInfo* getRecord(std::size_t recordIndex) const;
		const LinkerInfo* getLastRecord() const;
		bool getValidStructure() const;
		bool getSuspicious() const;
		std::string getSha256() const;
		std::string getCrc32() const;
		std::string getMd5() const;
		const std::vector<std::uint8_t>& getBytes() const;
		/// @}

		/// @name Setters
		/// @{
		void setSignature(std::string richSignature);
		void setOffset(unsigned long long richOffset);
		void setKey(unsigned long long richKey);
		void setValidStructure(bool richValidStructure);
		void setSuspicious(bool richSuspicious);
		void setBytes(const std::vector<std::uint8_t>& richHeaderBytes);
		void setSha256(const std::string& sha256);
		void setCrc32(const std::string& crc32);
		void setMd5(const std::string& md5);
		/// @}

		/// @name Iterators
		/// @{
		richHeaderIterator begin() const;
		richHeaderIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void clear();
		void invalidateOffset();
		void invalidateKey();
		void addRecord(LinkerInfo &record);
		bool hasRecords() const;
		void dump(std::string &dumpHeader) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
