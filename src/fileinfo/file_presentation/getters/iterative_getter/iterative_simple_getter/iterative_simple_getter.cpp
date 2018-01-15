/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_simple_getter/iterative_simple_getter.cpp
 * @brief Methods of IterativeSimpleGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_simple_getter/iterative_simple_getter.h"

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 *
 * Constructor in subclass must initialize @a elementHeader and other members which
 * are described in constructor of superclass.
 */
IterativeSimpleGetter::IterativeSimpleGetter(FileInformation &fileInfo) : IterativeGetter(fileInfo)
{

}

/**
 * Destructor
 */
IterativeSimpleGetter::~IterativeSimpleGetter()
{

}

/**
 * Get element header (title of every presented structure)
 * @param elemHeader Into this parameter the header is stored
 */
void IterativeSimpleGetter::getElementHeader(std::string &elemHeader) const
{
	elemHeader = elementHeader;
}

/**
 * @fn bool IterativeSimpleGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
 * Get value of flags and their descriptions
 * @param structIndex Index of selected structure (indexed from 0)
 * @param recIndex Index of record in selected structure (indexed from 0)
 * @param flagsValue Into this parameter is stored bit array of flags in string representation
 * @param desc Vector for save descriptors
 * @return @c true if record was successfully saved, @c false otherwise
 *
 * Before loading descriptors, everything from @a desc is deleted.
 *
 * If getter does not support flags, @a flagsValue is erased to zero length.
 *
 * If @a structIndex or @a recIndex is out of range, method returns @c false.
 */

} // namespace fileinfo
