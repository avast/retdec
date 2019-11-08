/**
 * @file include/retdec/common/file_type.h
 * @brief Common file type representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_FILE_TYPE_H
#define RETDEC_COMMON_FILE_TYPE_H

namespace retdec {
namespace common {

/**
 * Represents input binary's file type (i.e. shared library,
 * object, executable, archive).
 */
class FileType
{
	public:
		enum eFileType
		{
			FT_UNKNOWN = 0,
			FT_SHARED,
			FT_ARCHIVE,
			FT_OBJECT,
			FT_EXECUTABLE
		};

	public:
		/// @name File type query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isShared() const;
		bool isArchive() const;
		bool isObject() const;
		bool isExecutable() const;
		eFileType getID() const;
		/// @}

		/// @name File type set methods.
		/// @{
		void setIsUnknown();
		void setIsShared();
		void setIsArchive();
		void setIsObject();
		void setIsExecutable();
		void set(eFileType ft);
		/// @}

	private:
		eFileType _fileType = FT_UNKNOWN;
};

} // namespace common
} // namespace retdec

#endif
