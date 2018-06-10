/**
 * @file src/fileformat/types/rich_header/rich_header.cpp
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/fileformat/types/rich_header/rich_header.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
RichHeader::RichHeader()
{
	clear();
}

/**
 * Destructor
 */
RichHeader::~RichHeader()
{

}

/**
 * Get decrypted header as string
 * @return Decrypted header as string
 */
std::string RichHeader::getSignature() const
{
	return signature;
}

/**
 * Get length of signature
 * @return Length of signature
 */
std::size_t RichHeader::getSignatureLength() const
{
	return signature.size();
}

/**
 * Get offset of header in file
 * @param richOffset Into this parameter is stored offset of rich header
 * @return @c true if offset of rich header is detected, @c false otherwise
 *
 * If method returns @c false, @a richOffset is left unchanged
 */
bool RichHeader::getOffset(unsigned long long &richOffset) const
{
	if(isOffsetValid)
	{
		richOffset = offset;
	}

	return isOffsetValid;
}

/**
 * Get key for decryption of header
 * @param richKey Into this parameter is stored key of rich header
 * @return @c true if key of rich header is detected, @c false otherwise
 *
 * If method returns @c false, @a richKey is left unchanged
 */
bool RichHeader::getKey(unsigned long long &richKey) const
{
	if(isKeyValid)
	{
		richKey = key;
	}

	return isKeyValid;
}

/**
 * Get number of records in header
 * @return Number of records in header
 */
std::size_t RichHeader::getNumberOfRecords() const
{
	return header.size();
}

/**
 * Get record from header
 * @param recordIndex Index of record in header (indexed from 0)
 * @return Pointer to selected record or @c nullptr if index of record is incorrect
 */
const LinkerInfo* RichHeader::getRecord(std::size_t recordIndex) const
{
	return (recordIndex < getNumberOfRecords()) ? &header[recordIndex] : nullptr;
}

/**
 * Get last record from header
 * @return Pointer to the last record from rich header
 */
const LinkerInfo* RichHeader::getLastRecord() const
{
	return getNumberOfRecords() ? &header[getNumberOfRecords() - 1] : nullptr;
}

/**
 * Check if header has valid structure
 * @return @c true if header has valid structure, @c false otherwise
 */
bool RichHeader::getValidStructure() const
{
	return isValidStructure;
}

/**
 * Check if content of rich header is suspicious
 * @return @c true if content of rich header is suspicious, @c false otherwise
 */
bool RichHeader::getSuspicious() const
{
	return isSuspicious;
}

/**
 * Returns the decrypted bytes of the rich header.
 * @return Decrypted bytes of rich header.
 */
const std::vector<std::uint8_t>& RichHeader::getBytes() const
{
	return bytes;
}

/**
 * Set signature
 * @param richSignature Decrypted header
 */
void RichHeader::setSignature(std::string richSignature)
{
	signature = richSignature;
}

/**
 * Set offset of header in file
 * @param richOffset Offset of rich header in file
 */
void RichHeader::setOffset(unsigned long long richOffset)
{
	offset = richOffset;
	isOffsetValid = true;
}

/**
 * Set key for decryption of header
 * @param richKey Key for decryption of header
 */
void RichHeader::setKey(unsigned long long richKey)
{
	key = richKey;
	isKeyValid = true;
}

/**
 * Set if rich header has valid structure
 * @param richValidStructure @c true if rich header has valid structure,
 *    @c false otherwise
 */
void RichHeader::setValidStructure(bool richValidStructure)
{
	isValidStructure = richValidStructure;
}

/**
 * Set if content of rich header is suspicious
 * @param richSuspicious @c true if content of rich header is suspicious,
 *    @c false otherwise
 */
void RichHeader::setSuspicious(bool richSuspicious)
{
	isSuspicious = richSuspicious;
}

/**
 * Sets the decrypted bytes of the rich header.
 * @param richHeaderBytes Rich header bytes of the signature.
 */
void RichHeader::setBytes(const std::vector<std::uint8_t>& richHeaderBytes)
{
	bytes = richHeaderBytes;
}

/**
 * Get begin of records
 * @return Begin of rich header records
 */
RichHeader::richHeaderIterator RichHeader::begin() const
{
	return header.begin();
}

/**
 * Get end of records
 * @return End of rich header records
 */
RichHeader::richHeaderIterator RichHeader::end() const
{
	return header.end();
}

/**
 * Reset rich header and delete all records from it
 */
void RichHeader::clear()
{
	offset = 0;
	key = 0;
	invalidateOffset();
	invalidateKey();
	setValidStructure(false);
	setSuspicious(false);
	signature.clear();
	header.clear();
}

/**
 * Invalidate offset of rich header
 *
 * Instance method @a getOffset() returns @c false after invocation of
 * this method. Offset is possible to revalidate by invocation
 * of method @a setOffset().
 */
void RichHeader::invalidateOffset()
{
	isOffsetValid = false;
}

/**
 * Invalidate key of rich header
 *
 * Instance method @a getKey() returns @c false after invocation of
 * this method. Key is possible to revalidate by invocation
 * of method @a setKey().
 */
void RichHeader::invalidateKey()
{
	isKeyValid = false;
}

/**
 * Add new record
 * @param record Record which will be added
 */
void RichHeader::addRecord(LinkerInfo &record)
{
	header.push_back(record);
}

/**
 * Find out if there are any records
 * @return @c true if there are some records, @c false otherwise
 */
bool RichHeader::hasRecords() const
{
	return !header.empty();
}

/**
 * Dump information about rich header
 * @param dumpHeader Into this parameter is stored dump of rich header in an LLVM style
 */
void RichHeader::dump(std::string &dumpHeader) const
{
	std::stringstream ret;
	unsigned long long tmp;

	ret << "; ------------ Rich header ------------\n";
	if(getOffset(tmp))
	{
		ret << "; Offset in file: " << tmp << "\n";
	}
	if(getKey(tmp))
	{
		ret << "; Key for decryption: " << tmp << "\n";
	}
	ret << "; Decrypted signature: " << getSignature() << "\n";
	ret << "; Number of records: " << getNumberOfRecords() << "\n";
	ret << "; Valid structure: " << (getValidStructure() ? "yes" : "no") << "\n";
	ret << "; Suspicious content: " << (getSuspicious() ? "yes" : "no") << "\n";

	if(hasRecords())
	{
		ret << ";\n";
		for(const auto &item : header)
		{
			ret << "; (major: " << item.getMajorVersion() <<
				", minor: " << item.getMinorVersion() <<
				", build: " << item.getBuildVersion() <<
				", count: " << item.getNumberOfUses() << ")\n";
		}
	}

	dumpHeader = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
