/**
 * @file include/retdec/fileformat/types/strings/string.h
 * @brief Class for string in the file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_STRINGS_STRING_H
#define RETDEC_FILEFORMAT_TYPES_STRINGS_STRING_H

#include <string>

namespace retdec {
namespace fileformat {

enum class StringType
{
	Ascii,
	Wide
};

class String
{
	private:
		StringType type;
		std::uint64_t fileOffset;
		std::string sectionName;
		std::string content;
	public:
		template <typename SectionNameT, typename ContentT>
		String(StringType type, std::uint64_t fileOffset, SectionNameT&& sectionName, ContentT&& content)
			: type(type), fileOffset(fileOffset), sectionName(std::forward<SectionNameT>(sectionName)), content(std::forward<ContentT>(content)) {}
		String(const String&) = default;
		String(String&&) noexcept = default;
		~String() = default;

		String& operator=(const String&) = default;
		String& operator=(String&&) = default;

		StringType getType() const;
		std::uint64_t getFileOffset() const;
		const std::string& getSectionName() const;
		const std::string& getContent() const;

		bool isAscii() const;
		bool isWide() const;

		void setType(StringType stringType);
		void setFileOffset(std::uint64_t stringFileOffset);
		void setSectionName(const std::string& sectionName);
		void setSectionName(std::string&& sectionName);
		void setContent(const std::string& stringContent);
		void setContent(std::string&& stringContent);

		bool operator<(const String& rhs) const;
		bool operator==(const String& rhs) const;
		bool operator!=(const String& rhs) const;
};

} // namespace fileformat
} // namespace retdec

#endif
