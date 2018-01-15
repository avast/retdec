/**
 * @file src/fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.h
 * @brief Definition of PatternConfigGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_PATTERN_CONFIG_GETTER_PATTERN_CONFIG_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_PATTERN_CONFIG_GETTER_PATTERN_CONFIG_GETTER_H

#include "retdec/config/config.h"
#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * Getter for patterns
 */
class PatternConfigGetter
{
	private:
		const FileInformation &fileinfo; ///< information about input file
		retdec::config::Config *outDoc; ///< output config
		bool allocate;                   ///< @c true if constructor config parameter is nullptr
		bool empty;                      ///< @c false if at least one pattern was detected

		void process();
	public:
		PatternConfigGetter(const FileInformation &pFileinfo, retdec::config::Config *pOutDoc = nullptr);
		~PatternConfigGetter();

		bool isEmpty() const;
		Json::Value getJsonValue() const;
};

} // namespace fileinfo

#endif
