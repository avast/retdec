/**
 * @file src/fileinfo/file_information/file_information_types/rich_header.cpp
 * @brief Rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/rich_header.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 */
RichHeader::RichHeader() : header(nullptr)
{

}

/**
 * Destructor
 */
RichHeader::~RichHeader()
{

}

/**
 * Get number of records in header
 * @return Number of records in header
 */
std::size_t RichHeader::getNumberOfStoredRecords() const
{
	return header ? header->getNumberOfRecords() : 0;
}

/**
 * Get decrypted header as string
 * @return Decrypted header as string
 */
std::string RichHeader::getSignature() const
{
	return header ? header->getSignature() : "";
}

/**
 * Get offset of header in file
 * @return Offset of header in file
 */
std::string RichHeader::getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	unsigned long long aux;
	return header && header->getOffset(aux) ? getNumberAsString(aux, format) : "";
}

/**
 * Get key for decryption of header
 * @return Key for decryption of header
 */
std::string RichHeader::getKeyStr(std::ios_base &(* format)(std::ios_base &)) const
{
	unsigned long long aux;
	return header && header->getKey(aux) ? getNumberAsString(aux, format) : "";
}

/**
 * Get major version
 * @param position Index of selected record from header (indexed from 0)
 * @return Major version of linker
 */
std::string RichHeader::getRecordMajorVersionStr(std::size_t position) const
{
	const auto *record = header ? header->getRecord(position) : nullptr;
	return record ? getNumberAsString(record->getMajorVersion()) : "";
}

/**
 * Get minor version
 * @param position Index of selected record from header (indexed from 0)
 * @return Minor version of linker
 */
std::string RichHeader::getRecordMinorVersionStr(std::size_t position) const
{
	const auto *record = header ? header->getRecord(position) : nullptr;
	return record ? getNumberAsString(record->getMinorVersion()) : "";
}

/**
 * Get build version
 * @param position Index of selected record from header (indexed from 0)
 * @return Build version of linker
 */
std::string RichHeader::getRecordBuildVersionStr(std::size_t position) const
{
	const auto *record = header ? header->getRecord(position) : nullptr;
	return record ? getNumberAsString(record->getBuildVersion()) : "";
}

/**
 * Get number of uses
 * @param position Index of selected record from header (indexed from 0)
 * @return Number of uses
 */
std::string RichHeader::getRecordNumberOfUsesStr(std::size_t position) const
{
	const auto *record = header ? header->getRecord(position) : nullptr;
	return record ? getNumberAsString(record->getNumberOfUses()) : "";
}

/**
 * Get raw bytes
 * @return Raw bytes of rich header.
 */
std::vector<std::uint8_t> RichHeader::getRawBytes() const
{
	return header ? header->getBytes() : std::vector<std::uint8_t>{};
}

/**
 * Set rich header data
 * @param richHeader Instance of class with original information about rich header
 */
void RichHeader::setHeader(const retdec::fileformat::RichHeader *richHeader)
{
	header = richHeader;
}

/**
 * Find out if there are any records
 * @return @c true if there are some records, @c false otherwise
 */
bool RichHeader::hasRecords() const
{
	return header ? header->hasRecords() : false;
}

} // namespace fileinfo
