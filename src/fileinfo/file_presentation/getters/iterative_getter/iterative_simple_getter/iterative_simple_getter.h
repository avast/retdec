/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_simple_getter/iterative_simple_getter.h
 * @brief Definition of IterativeSimpleGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SIMPLE_GETTER_ITERATIVE_SIMPLE_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SIMPLE_GETTER_ITERATIVE_SIMPLE_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_getter.h"

namespace fileinfo {

/**
 * Abstract class for loading information about file.
 *
 * This class enable iterative queries to a set of items
 * (e.g. queries to symbols from symbol tables).
 */
class IterativeSimpleGetter : public IterativeGetter
{
	protected:
		std::string elementHeader; ///< header for every presented structure
	public:
		IterativeSimpleGetter(FileInformation &fileInfo);
		virtual ~IterativeSimpleGetter() override;

		/// @name Getters
		/// @{
		void getElementHeader(std::string &elemHeader) const;
		/// @}

		/// @name Pure virtual methods
		/// @{
		virtual bool getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const = 0;
		/// @}
};

} // namespace fileinfo

#endif
