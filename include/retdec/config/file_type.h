/**
 * @file include/retdec/config/file_type.h
 * @brief Decompilation configuration manipulation: file type.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_FILE_TYPE_H
#define RETDEC_CONFIG_FILE_TYPE_H

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents input binary's file type (i.e. shared library,
 * object, executable, archive).
 */
class FileType
{
	public:
		/// @name File type query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isShared() const;
		bool isArchive() const;
		bool isObject() const;
		bool isExecutable() const;
		/// @}

		/// @name File type set methods.
		/// @{
		void setIsUnknown();
		void setIsShared();
		void setIsArchive();
		void setIsObject();
		void setIsExecutable();
		/// @}

		Json::Value getJsonValue() const;
		void readJsonValue(const Json::Value& val);

	private:
		enum eFileType
		{
			FT_UNKNOWN = 0,
			FT_SHARED,
			FT_ARCHIVE,
			FT_OBJECT,
			FT_EXECUTABLE
		};

	private:
		eFileType _fileType = FT_UNKNOWN;
};

} // namespace config
} // namespace retdec

#endif
