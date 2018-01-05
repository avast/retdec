/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_getter.h
 * @brief Definition of IterativeGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_GETTER_H

#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * Abstract class for loading information about file.
 *
 * This class enable iterative queries to a set of items
 * (e.g. queries to symbols from symbol tables).
 */
class IterativeGetter
{
	protected:
		FileInformation &fileinfo;                                 ///< information about file
		std::size_t numberOfStructures;                            ///< number of presented structures (e.g. number of symbol tables)
		std::vector<std::size_t> numberOfStoredRecords;            ///< number of records in each structure
		std::vector<std::string> commonHeaderElements;             ///< parts of header (common for all structures)
		std::vector<std::size_t> numberOfExtraElements;            ///< number of extra elements in each structure
		std::vector<std::vector<std::string>> extraHeaderElements; ///< parts of header (specific for each structure)
		std::string title;                                         ///< title of presented structure
	public:
		IterativeGetter(FileInformation &fileInfo);
		virtual ~IterativeGetter();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStructures() const;
		std::size_t getNumberOfStoredRecords(std::size_t structIndex) const;
		std::size_t getHeaderElements(std::size_t structIndex, std::vector<std::string> &elements) const;
		void getTitle(std::string &structTitle) const;
		/// @}

		/// @name Other methods
		/// @{
		bool hasBasicInfo(std::size_t structIndex) const;
		/// @}

		/// @name Pure virtual methods
		/// @{
		virtual std::size_t getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const = 0;
		virtual bool getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const = 0;
		/// @}
};

} // namespace fileinfo

#endif
