/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_getter.cpp
 * @brief Methods of IterativeGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_getter.h"

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 *
 * Constructor in subclass must initialize @a commonHeaderElements, @a title,
 * @a numberOfStructures, @a numberOfStoredRecords, @a extraHeaderElements
 * and @a numberOfExtraElements.
 *
 * Constructor in subclass must ensure that @a numberOfStoredRecords and
 * @a numberOfExtraElements contains exactly @a numberOfStructures elements.
 *
 * Constructor in subclass must ensure that each element in @a extraHeaderElements
 * contains exactly as many elements as @a numberOfExtraElements[i], where @a i is
 * index of @a extraHeaderElements and @a numberOfExtraElements.
 */
IterativeGetter::IterativeGetter(FileInformation &fileInfo) : fileinfo(fileInfo)
{

}

/**
 * Destructor
 */
IterativeGetter::~IterativeGetter()
{

}

/**
 * Get number of stored structures (e.g. number of symbol tables)
 * @return Number of stored structures
 */
std::size_t IterativeGetter::getNumberOfStructures() const
{
	return numberOfStructures;
}

/**
 * Get number of stored records in selected structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @return Number of stored records in selected structure
 *
 * If @a structIndex is out of range, method returns 0.
 * If structure does not contain any records, value 0 will be returned
 * for a valid index also.
 */
std::size_t IterativeGetter::getNumberOfStoredRecords(std::size_t structIndex) const
{
	return (structIndex < numberOfStructures ? numberOfStoredRecords[structIndex] : 0);
}

/**
 * Get elements of header
 * @param structIndex Index of selected structure (indexed from 0)
 * @param elements Vector for save elements. Into this vector are stored common
 *    elements of all structures a subsequently extra elements for selected
 *    structure.
 * @return Number of stored elements
 *
 * Before loading elements, everything from vector @a elements is deleted.
 * If @a structIndex is out of range, method returns 0 and @a elements is left
 * unchanged.
 */
std::size_t IterativeGetter::getHeaderElements(std::size_t structIndex, std::vector<std::string> &elements) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	elements = commonHeaderElements;
	if(numberOfExtraElements[structIndex])
	{
		elements.insert(elements.end(), extraHeaderElements[structIndex].begin(), extraHeaderElements[structIndex].end());
	}
	return elements.size();
}

/**
 * Get title of presented structure
 * @param structTitle Into this parameter the title is stored
 */
void IterativeGetter::getTitle(std::string &structTitle) const
{
	structTitle = title;
}

/**
 * Check if structure has some basic information
 * @param structIndex Index of selected structure (indexed from 0)
 * @return @c true if structure has at least one basic information, @c false otherwise
 */
bool IterativeGetter::hasBasicInfo(std::size_t structIndex) const
{
	std::vector<std::string> desc, info;
	return getBasicInfo(structIndex, desc, info);
}

/**
 * @fn std::size_t IterativeGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
 * Get basic information about presented structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @param desc Vector for save descriptions of information
 * @param info Vector for save information about file
 * @return Number of loaded information (this is equal to number of elements in @a desc and in @a info)
 *
 * Before loading information, everything from vectors @a desc and @a info is deleted.
 * If structure does not support this feature or @a structIndex is out of range,
 * method returns 0 and vectors are left unchanged.
 */

/**
 * @fn bool IterativeGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
 * Get one record from structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @param recIndex Index of record in selected structure (indexed from 0)
 * @param record Vector for save record. At end of vector are stored special
 *    additional information, if these information are present. Number and
 *    semantics of additional information may be different for every separate
 *    structure.
 * @return @c true if record was successfully saved, @c false otherwise
 *
 * Before loading record, everything from vector @a record is deleted.
 *
 * If method returns @c true, @a record contains as many elements as vector
 * returned by the method @a getHeaderElements(structIndex).
 *
 * If @a structIndex or @a recIndex is out of range, method returns @c false.
 */

} // namespace fileinfo
