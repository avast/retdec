/**
 * @file RichHeader.h
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RICHHEADER_H
#define RICHHEADER_H

#include <cstdint>
#include <vector>
#include <map>

namespace PeLib
{
	/**
	 * This class handless rich header.
	 */
	class RichHeader
	{
		public:
			typedef std::vector<PELIB_IMAGE_RICH_HEADER_RECORD>::const_iterator richHeaderIterator;
		private:
			bool headerIsValid;
			bool validStructure;
			dword key;
			std::size_t noOfIters;
			std::vector<dword> decryptedHeader;
			std::vector<PELIB_IMAGE_RICH_HEADER_RECORD> records;

			void init();
			void setValidStructure();
			void getUserFriendlyProductName(PELIB_IMAGE_RICH_HEADER_RECORD & record);
			bool analyze(bool ignoreInvalidKey = false);
			void read(InputBuffer& inputbuffer, std::size_t uiSize, bool ignoreInvalidKey);
		public:
			RichHeader();
			~RichHeader();

			int read(
					std::istream& inStream,
					std::size_t uiOffset,
					std::size_t uiSize,
					bool ignoreInvalidKey);
			bool isHeaderValid() const;
			bool isStructureValid() const;
			std::size_t getNumberOfIterations() const;
			dword getKey() const;
			const dword* getDecryptedHeaderItem(std::size_t index) const;
			std::string getDecryptedHeaderItemSignature(std::size_t index) const;
			std::string getDecryptedHeaderItemsSignature(std::initializer_list<std::size_t> indexes) const;
			std::vector<std::uint8_t> getDecryptedHeaderBytes() const;
			richHeaderIterator begin() const;
			richHeaderIterator end() const;
	};
}

#endif
