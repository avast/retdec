/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/iterative_distribution_getter.cpp
 * @brief Methods of IterativeDistributionGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/iterative_distribution_getter.h"

namespace fileinfo {

namespace
{

/**
 * Get header addend
 * @param elemVal Value of element which will be added to header
 * @param distribution Required length of addend
 * @return Correct value of @a elemVal, which is derived from @a distribution
 */
std::string getHeaderAddend(const std::string &elemVal, std::size_t distribution)
{
	const auto len = elemVal.length();
	return (len < distribution ? elemVal + std::string(distribution - len, ' ') : elemVal.substr(0, distribution - 1) + " ");
}

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 *
 * Constructor in subclass must initialize @a distribution, @a commonHeaderDesc,
 * @a extraDistribution, @a extraDesc and other members which are descripted
 * in constructor of superclass.
 *
 * Constructor in subclass must also ensure that the number of elements in
 * @a distribution, @a commonHeaderElements and @a commonHeaderDesc are the same.
 * Length of element in @a commonHeaderElements may be less than value on corresponding
 * index in @a distribution. In which case header returned by method @a getHeader()
 * is filled by spaces. If length of element is greater or equal, returned header
 * will be automatically erased.
 *
 * Constructor in subclass must furthermore ensure that each element in
 * @a extraDistribution and in @a extraDesc contains exactly as many elements
 * as @a numberOfExtraElements[i], where @a i is index of @a extraDistribution,
 * @a extraDesc and @a numberOfExtraElements.
 *
 * Finally, constructor in subclass must invoke method @a loadRecords.
 */
IterativeDistributionGetter::IterativeDistributionGetter(FileInformation &fileInfo) : IterativeGetter(fileInfo)
{

}

/**
 * Destructor
 */
IterativeDistributionGetter::~IterativeDistributionGetter()
{

}

/**
 * @fn bool IterativeDistributionGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
 * Load one record
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
 * returned by the method @a getHeaderElements(structIndex) as well as vector
 * returned by the method @a getDistribution(structIndex).
 *
 * If @a structIndex or @a recIndex is out of range, method returns @c false.
 */

/**
 * Load records from all structures and store them into member @a records
 *
 * This method load records from all structures and set member @a distFlags.
 * Member @a distFlags represents so-called distribution flags. This flags
 * consist of set of vectors. Each vector represents flags for related structure
 * (first vector represents flags for first structure, etc.). Each distribution
 * flag in each vector is related to one item from @a commonHeaderElements and
 * to one item from @a commonHeaderDesc (first item from @a distFlags to first item
 * from @a commonHeaderElements and to first item from @a commonHeaderDesc, etc.)
 * of related structure. If flag is set to @c false, related item from
 * @a commonHeaderElements (and from @a commonHeaderDesc) will not be included to
 * presented header. If any structure contains extra information, surplus values in
 * @a distFlags represents flags for @a extraHeaderElements[structIndex] and for
 * extraDesc[structIndex].
 *
 * This method must be invoke in constructor of subclass after members @a numberOfStructures
 * and @a numberOfStoredRecords are set.
 */
void IterativeDistributionGetter::loadRecords()
{
	std::vector<std::string> oneRec;
	std::string prefix;

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		std::vector<bool> flags, map;
		std::vector<std::size_t> padding;
		std::vector<std::vector<std::string>> oneStructure;
		std::size_t recSize = 0, len;

		for(std::size_t j = 0; loadRecord(i, j, oneRec); ++j)
		{
			oneStructure.push_back(oneRec);
			if(!j)
			{
				recSize = oneRec.size();
				flags.insert(flags.begin(), recSize, false);
				map.insert(map.begin(), recSize, true);
				padding.insert(padding.begin(), recSize, 0);
			}

			for(std::size_t k = 0; k < recSize; ++k)
			{
				if(!oneRec[k].empty())
				{
					flags[k] = true;
					prefix = oneRec[k].substr(0, 2);

					// detection of elements (columns) which consist from hexadecimal numbers
					if(map[k])
					{
						if(prefix == "0")
						{
							continue;
						}
						else if(prefix == "0x" && (len = oneRec[k].length()) > 2)
						{
							padding[k] = std::max(padding[k], len);
						}
						// current column does not contain hexadecimal numbers
						else
						{
							map[k] = false;
							padding[k] = 0;
						}
					}
				}
			}
		}

		for(std::size_t j = 0; j < recSize; ++j)
		{
			map[j] = map[j] && flags[j];
		}

		records.push_back(oneStructure);
		distFlags.push_back(flags);
		hexMap.push_back(map);
		hexPadding.push_back(padding);
	}
}

/**
 * Get distribution of header
 * @param structIndex Index of selected structure (indexed from 0)
 * @param distr Into this parameter is stored distribution (length) of the individual parts of header.
 *    At end of @a distr is stored distribution for extra elements of selected structure.
 * @return Total length of header
 *
 * Before loading information about distribution, everything from vector @a distr is deleted
 * If @a structIndex is out of range, method returns 0 and @a distr is left unchanged.
 */
std::size_t IterativeDistributionGetter::getDistribution(std::size_t structIndex, std::vector<std::size_t> &distr) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}
	std::size_t length = 0;
	distr.clear();

	for(std::size_t i = 0, e = distribution.size(); i < e; ++i)
	{
		length += distribution[i];
		distr.push_back(distribution[i]);
	}

	for(std::size_t i = 0, e = numberOfExtraElements[structIndex]; i < e; ++i)
	{
		length += extraDistribution[structIndex][i];
		distr.push_back(extraDistribution[structIndex][i]);
	}

	return length;
}

/**
 * Get description of header elements
 * @param structIndex Index of selected structure (indexed from 0)
 * @param desc Vector for save descriptors (descriptor is full description
 *    of header element)
 * @param abb Vector for save abbreviations of descriptors (abbreviation is equal
 *    to short description in header)
 * @return Number of stored descriptors
 *
 * The first element in @a abb corresponds to the first element in @a desc etc.
 * Before loading information, everything from vectors @a desc and @a abb is deleted.
 * It is guaranteed that the number of elements in @a desc and @a abb are the same.
 * At end of both vectors is stored description (or abbreviation) for extra elements
 * of selected structure.
 *
 * If @a structIndex is out of range, method returns 0 and @a desc and @a abb is left unchanged.
 *
 * Into vectors @a desc and @a abb are stored only descriptors of significant elements. Significant
 * element is each element (column), which has set at least one value in related structure.
 */
std::size_t IterativeDistributionGetter::getHeaderDesc(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}
	const std::size_t basicElemSize = commonHeaderElements.size();
	const std::size_t flagsSize = distFlags[structIndex].size();
	desc.clear();
	abb.clear();

	for(std::size_t i = 0, e = std::min(basicElemSize, flagsSize); i < e; ++i)
	{
		if(distFlags[structIndex][i])
		{
			desc.push_back(commonHeaderDesc[i]);
			abb.push_back(commonHeaderElements[i]);
		}
	}

	if(flagsSize > basicElemSize)
	{
		for(std::size_t i = 0, e = std::min(numberOfExtraElements[structIndex], flagsSize - basicElemSize); i < e; ++i)
		{
			if(distFlags[structIndex][basicElemSize + i])
			{
				desc.push_back(extraDesc[structIndex][i]);
				abb.push_back(extraHeaderElements[structIndex][i]);
			}
		}
	}

	return abb.size();
}

/**
 * Get header of presented structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @param header Into this parameter the header is stored. At end of this parameter
 *    is stored short description of extra information for selected structure.
 *
 * If @a structIndex is out of range, @a header is left unchanged
 *
 * Into vectors @a desc and @a abb are stored only descriptors of significant elements. Significant
 * element is each element (column), which has set at least one value in related structure.
 */
void IterativeDistributionGetter::getHeader(std::size_t structIndex, std::string &header) const
{
	if(structIndex >= numberOfStructures)
	{
		return;
	}
	const std::size_t basicElemSize = commonHeaderElements.size();
	const std::size_t flagsSize = distFlags[structIndex].size();
	header.clear();

	for(std::size_t i = 0, e = std::min(basicElemSize, flagsSize); i < e; ++i)
	{
		if(distFlags[structIndex][i])
		{
			header += getHeaderAddend(commonHeaderElements[i], distribution[i]);
		}
	}

	if(flagsSize <= basicElemSize)
	{
		return;
	}

	for(std::size_t i = 0, e = std::min(numberOfExtraElements[structIndex], flagsSize - basicElemSize); i < e; ++i)
	{
		if(distFlags[structIndex][basicElemSize + i])
		{
			header += getHeaderAddend(extraHeaderElements[structIndex][i], extraDistribution[structIndex][i]);
		}
	}
}

/**
 * Get distribution flags of one structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @param flags Into this parameter the flags are stored.
 * @return @c true if flags were successfully saved, @c false otherwise
 *
 * Before loading flags, everything from vector @a flags is deleted.
 *
 * If method returns @c true, @a flags contains as many elements as vector
 * returned by the method @a getDistribution(structIndex).
 *
 * If @a structIndex is out of range, method returns @c false.
 */
bool IterativeDistributionGetter::getDistributionFlags(std::size_t structIndex, std::vector<bool> &flags) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	flags = distFlags[structIndex];
	return true;
}

/**
 * If method returns @c true, @a record contains as many elements as vector
 * returned by the method @a getDistribution(structIndex).
 *
 * More detailed description is in superclass.
 */
bool IterativeDistributionGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record = records[structIndex][recIndex];

	for(std::size_t i = 0, e = hexMap[structIndex].size(); i < e; ++i)
	{
		// hexadecimal prefix (0x) -> 2
		const auto len = record[i].length();
		if(hexMap[structIndex][i] && len > 2)
		{
			record[i].insert(2, hexPadding[structIndex][i] - len, '0');
		}
	}

	return true;
}

/**
 * @fn bool IterativeDistributionGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
 * Get descriptors (and its abbreviations) of all records in structure
 * @param structIndex Index of selected structure (indexed from 0)
 * @param desc Vector for save descriptors
 * @param abbv Vector for save abbreviations
 * @return @c true if index of selected structure is valid, @c false otherwise.
 *    If index is not valid, @a desc and @a abbv are left unchanged.
 *
 * Into @a desc is stored each flag descriptor, which is assigned to at least one record.
 * Into @a abbv are stored abbreviations of descriptors, which are stored in @a desc.
 *
 * Before loading descriptors, everything from vectors @a desc and @a abbv is deleted.
 */

} // namespace fileinfo
