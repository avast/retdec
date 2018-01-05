/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/dynamic_sections_plain_getter.h
 * @brief Definition of DynamicSectionsPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_DISTRIBUTION_GETTER_DYNAMIC_SECTIONS_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_DISTRIBUTION_GETTER_DYNAMIC_SECTIONS_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/iterative_distribution_getter.h"

namespace fileinfo {

/**
 * Getter for dynamic sections
 */
class DynamicSectionsPlainGetter : public IterativeDistributionGetter
{
	protected:
		virtual bool loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) override;
	public:
		DynamicSectionsPlainGetter(FileInformation &fileInfo);
		virtual ~DynamicSectionsPlainGetter() override;

		virtual std::size_t getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const override;
		virtual bool getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const override;
};

} // namespace fileinfo

#endif
