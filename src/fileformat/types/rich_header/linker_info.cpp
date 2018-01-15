/**
 * @file src/fileformat/types/rich_header/linker_info.cpp
 * @brief Class for information about linker.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/rich_header/linker_info.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
LinkerInfo::LinkerInfo() : majorVersion(0), minorVersion(0), buildVersion(0), count(0)
{

}

/**
 * Destructor
 */
LinkerInfo::~LinkerInfo()
{

}

/**
 * Get major version
 * @return Major version of linker
 */
unsigned long long LinkerInfo::getMajorVersion() const
{
	return majorVersion;
}

/**
 * Get minor version
 * @return Minor version of linker
 */
unsigned long long LinkerInfo::getMinorVersion() const
{
	return minorVersion;
}

/**
 * Get build version
 * @return Build version of linker
 */
unsigned long long LinkerInfo::getBuildVersion() const
{
	return buildVersion;
}

/**
 * Get number of uses
 * @return Number of uses
 */
unsigned long long LinkerInfo::getNumberOfUses() const
{
	return count;
}

/**
 * Set major version of linker
 * @param linkerMajorVersion Major version of linker
 */
void LinkerInfo::setMajorVersion(unsigned long long linkerMajorVersion)
{
	majorVersion = linkerMajorVersion;
}

/**
 * Set minor version of linker
 * @param linkerMinorVersion Minor version of linker
 */
void LinkerInfo::setMinorVersion(unsigned long long linkerMinorVersion)
{
	minorVersion = linkerMinorVersion;
}

/**
 * Set build version
 * @param linkerBuildVersion Build version
 */
void LinkerInfo::setBuildVersion(unsigned long long linkerBuildVersion)
{
	buildVersion = linkerBuildVersion;
}

/**
 * Set number of uses
 * @param linkerCount Number of uses
 */
void LinkerInfo::setNumberOfUses(unsigned long long linkerCount)
{
	count = linkerCount;
}

} // namespace fileformat
} // namespace retdec
