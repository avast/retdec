/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/iterative_distribution_getter.h
 * @brief Definition of IterativeDistributionGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_DISTRIBUTION_GETTER_ITERATIVE_DISTRIBUTION_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_DISTRIBUTION_GETTER_ITERATIVE_DISTRIBUTION_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_getter.h"

namespace fileinfo {

/**
 * Abstract class for loading information about file.
 *
 * This class enable iterative queries to a set of items
 * (e.g. queries to symbols from symbol tables).
 */
class IterativeDistributionGetter : public IterativeGetter
{
	protected:
		std::vector<std::vector<std::vector<std::string>>> records; ///< records from all structures
		std::vector<std::size_t> distribution;                      ///< distribution of header (common for all structures)
		std::vector<std::string> commonHeaderDesc;                  ///< description of header elements (common for all structures)
		std::vector<std::vector<std::size_t>> extraDistribution;    ///< distribution of extra elements for each structure
		std::vector<std::vector<std::string>> extraDesc;            ///< description of extra header elements for each structure
		std::vector<std::vector<bool>> distFlags;                   ///< distribution flags
		std::vector<std::vector<bool>> hexMap;                      ///< map of hexadecimal elements (columns)
		std::vector<std::vector<std::size_t>> hexPadding;           ///< padding of hexadecimal columns

		/// @name Other pure virtual methods
		/// @{
		virtual bool loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) = 0;
		/// @}

		/// @name Other methods
		/// @{
		void loadRecords();
		/// @}
	public:
		IterativeDistributionGetter(FileInformation &fileInfo);
		virtual ~IterativeDistributionGetter() override;

		/// @name Getters
		/// @{
		std::size_t getDistribution(std::size_t structIndex, std::vector<std::size_t> &distr) const;
		std::size_t getHeaderDesc(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abb) const;
		void getHeader(std::size_t structIndex, std::string &header) const;
		bool getDistributionFlags(std::size_t structIndex, std::vector<bool> &flags) const;
		/// @}

		/// @name Virtual getters
		/// @{
		virtual bool getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const override;
		/// @}

		/// @name Pure virtual getters
		/// @{
		virtual bool getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const = 0;
		/// @}
};

} // namespace fileinfo

#endif
