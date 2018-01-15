/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/pdb_plain_getter.h
 * @brief Definition of PdbPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_PDB_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_PDB_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for information about related PDB file
 */
class PdbPlainGetter : public SimpleGetter
{
	public:
		PdbPlainGetter(FileInformation &fileInfo);
		virtual ~PdbPlainGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
