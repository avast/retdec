/**
 * @file src/fileinfo/file_information/file_information_types/pdb_info.cpp
 * @brief Information about related PDB file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/pdb_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
PdbInfo::PdbInfo() : age(std::numeric_limits<std::size_t>::max()),
						timeStamp(std::numeric_limits<std::size_t>::max())
{

}

/**
 * Destructor
 */
PdbInfo::~PdbInfo()
{

}

/**
 * Get type of PDB file
 * @return Type of PDB file
 */
std::string PdbInfo::getType() const
{
	return type;
}

/**
 * Get original path to PDB file
 * @return Original path to PDB file
 */
std::string PdbInfo::getPath() const
{
	return path;
}

/**
 * Get GUID of PDB file
 * @return GUID of PDB file
 */
std::string PdbInfo::getGuid() const
{
	return guid;
}

/**
 * Get age of PDB file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Age of PDB file
 */
std::string PdbInfo::getAgeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(age, format);
}

/**
 * Get timestamp of PDB file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Timestamp of PDB file
 */
std::string PdbInfo::getTimeStampStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(timeStamp, format);
}

/**
 * Set type of PDB file
 * @param sType Type of PDB file
 */
void PdbInfo::setType(std::string sType)
{
	type = sType;
}

/**
 * Set original path to PDB file
 * @param sPath Original path to PDB file
 */
void PdbInfo::setPath(std::string sPath)
{
	path = sPath;
}

/**
 * Set GUID of PDB file
 * @param sGuid GUID of PDB file
 */
void PdbInfo::setGuid(std::string sGuid)
{
	guid = sGuid;
}

/**
 * Set age of PDB file
 * @param sAge Age of PDB file
 */
void PdbInfo::setAge(std::size_t sAge)
{
	age = sAge;
}

/**
 * Set timestamp of PDB file
 * @param sTimeStamp Timestamp of PDB file
 */
void PdbInfo::setTimeStamp(std::size_t sTimeStamp)
{
	timeStamp = sTimeStamp;
}

} // namespace fileinfo
