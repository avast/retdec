/**
 * @file src/fileinfo/file_information/file_information_types/data_directory.cpp
 * @brief Class for data directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/data_directory.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
DataDirectory::DataDirectory() : address(std::numeric_limits<unsigned long long>::max()),
									size(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
DataDirectory::~DataDirectory()
{

}

/**
 * Get type (description) of directory
 * @return Type of directory
 */
std::string DataDirectory::getType() const
{
	return type;
}

/**
 * Get start address (in memory) of directory
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Start address (in memory) of directory
 */
std::string DataDirectory::getAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(address, format);
}

/**
 * Get size of directory
 * @return Size of directory
 */
std::string DataDirectory::getSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(size, format);
}

/**
 * Set type (description) of directory
 * @param dirType Type of directory
 */
void DataDirectory::setType(std::string dirType)
{
	type = dirType;
}

/**
 * Set start address of directory
 * @param dirAddr Start address of directory
 */
void DataDirectory::setAddress(unsigned long long dirAddr)
{
	address = dirAddr;
}

/**
 * Set size of directory
 * @param dirSize Size of directory
 */
void DataDirectory::setSize(unsigned long long dirSize)
{
	size = dirSize;
}

} // namespace fileinfo
