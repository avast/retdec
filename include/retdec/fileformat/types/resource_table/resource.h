/**
 * @file include/retdec/fileformat/types/resource_table/resource.h
 * @brief Class for one resource.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_H

#include <string>
#include <vector>

#include <llvm/ADT/StringRef.h>

namespace retdec {
namespace fileformat {

class FileFormat;

/**
 * One resource
 */
class Resource
{
	private:
		std::string crc32;                ///< CRC32 of resource content
		std::string md5;                  ///< MD5 of resource content
		std::string sha256;               ///< SHA256 of resource content
		std::string name;                 ///< resource name
		std::string type;                 ///< resource type
		std::string language;             ///< resource language
		llvm::StringRef bytes;            ///< reference to resource data
		std::size_t offset;               ///< offset in file
		std::size_t size;                 ///< size in file
		std::size_t nameId;               ///< resource name identifier
		std::size_t typeId;               ///< resource type identifier
		std::size_t languageId;           ///< resource language identifier
		std::size_t sublanguageId;        ///< resource sublanguage identifier
		bool nameIdIsValid;               ///< @c true if name ID is valid
		bool typeIdIsValid;               ///< @c true if type ID is valid
		bool languageIdIsValid;           ///< @c true if language ID is valid
		bool sublanguageIdIsValid;        ///< @c true if sublanguage ID is valid
		bool loaded;                      ///< @c true if content of resource was successfully loaded from input file
	public:
		Resource();
		~Resource();

		/// @name Getters
		/// @{
		std::string getCrc32() const;
		std::string getMd5() const;
		std::string getSha256() const;
		std::string getName() const;
		std::string getType() const;
		std::string getLanguage() const;
		const llvm::StringRef getBytes(std::size_t sOffset = 0, std::size_t sSize = 0) const;
		std::size_t getOffset() const;
		std::size_t getSizeInFile() const;
		std::size_t getLoadedSize() const;
		bool getNameId(std::size_t &rId) const;
		bool getTypeId(std::size_t &rId) const;
		bool getLanguageId(std::size_t &rId) const;
		bool getSublanguageId(std::size_t &rId) const;
		/// @}

		/// @name Getters of resource content
		/// @{
		bool getBits(std::string &sResult) const;
		bool getBytes(std::vector<unsigned char> &sResult, std::size_t sOffset = 0, std::size_t sSize = 0) const;
		bool getString(std::string &sResult, std::size_t sOffset = 0, std::size_t sSize = 0) const;
		bool getHexBytes(std::string &sResult) const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string rName);
		void setType(std::string rType);
		void setLanguage(std::string rLan);
		void setOffset(std::size_t rOffset);
		void setSizeInFile(std::size_t rSize);
		void setNameId(std::size_t rId);
		void setTypeId(std::size_t rId);
		void setLanguageId(std::size_t rId);
		void setSublanguageId(std::size_t rId);
		/// @}

		/// @name Other methods
		/// @{
		void invalidateNameId();
		void invalidateTypeId();
		void invalidateLanguageId();
		void invalidateSublanguageId();
		void load(const FileFormat *rOwner);
		bool hasCrc32() const;
		bool hasMd5() const;
		bool hasSha256() const;
		bool hasEmptyName() const;
		bool hasEmptyType() const;
		bool hasEmptyLanguage() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
