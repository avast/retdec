/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser.cpp
 * @brief Methods of PeWrapperParser class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser.h"

namespace fileinfo {

/**
 * Constructor
 */
PeWrapperParser::PeWrapperParser()
{

}

/**
 * Destructor
 */
PeWrapperParser::~PeWrapperParser()
{

}

/**
 * @fn std::string PeWrapperParser::getPeType() const
 * Get type of PE file (e.g. "PE32" or "PE32+")
 * @return Type of PE file
 */

/**
 * @fn bool PeWrapperParser::getSection(const unsigned long long secIndex, FileSection &section) const
 * Get information about file section
 * @param secIndex Index of section (indexed from 0)
 * @param section Instance of class for save information about file section
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */

} // namespace fileinfo
