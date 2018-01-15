/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/simple_getter.cpp
 * @brief Methods of SimpleGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
SimpleGetter::SimpleGetter(FileInformation &fileInfo) : fileinfo(fileInfo)
{

}

/**
 * Destructor
 */
SimpleGetter::~SimpleGetter()
{

}

/**
 * @fn std::size_t SimpleGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
 * Load information about file
 * @param desc Vector for save descriptions of information
 * @param info Vector for save information about file
 * @return Number of loaded information (this is equal to number of elements in @a desc and in @a info)
 *
 * Before loading information about file, everything from vectors @a desc and @a info is deleted
 */

} // namespace fileinfo
