/**
 * @file src/fileformat/types/pdb_info/pdb_info.cpp
 * @brief Class for information about PDB debug file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/fileformat/types/pdb_info/pdb_info.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
PdbInfo::PdbInfo() : age(0), timeStamp(0)
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
 * Get path to PDB file
 * @return Path to PDB file
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
 * @return Age of PDB file
 */
std::size_t PdbInfo::getAge() const
{
	return age;
}

/**
 * Get timestamp of PDB file
 * @return Timestamp of PDB file
 */
std::size_t PdbInfo::getTimeStamp() const
{
	return timeStamp;
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
 * Set path to PDB file
 * @param sPath Path to PDB file
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

/**
 * Dump information about PDB file
 * @param dumpInfo Into this parameter is stored dump of information about PDB file in an LLVM style
 */
void PdbInfo::dump(std::string &dumpInfo) const
{
	if(type.empty() && path.empty() && guid.empty() && !age && !timeStamp)
	{
		dumpInfo.clear();
		return;
	}

	std::stringstream ret;

	ret << "; ------------ Information about related PDB file ------------\n";
	if(!type.empty())
	{
		ret << "; Type of file: " << getType() << "\n";
	}
	if(!path.empty())
	{
		ret << "; Path to PDB file: " << getPath() << "\n";
	}
	if(!guid.empty())
	{
		ret << "; GUID: " << getGuid() << "\n";
	}
	ret << "; Version of file (age): " << getAge() << "\n";
	ret << "; Timestamp: " << getTimeStamp() << "\n";

	dumpInfo = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
