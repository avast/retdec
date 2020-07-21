/**
 * @file CoffSymbolTable.h
 * @brief Class for COFF symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PELIB_COFFSYMBOLTABLE_H
#define RETDEC_PELIB_COFFSYMBOLTABLE_H

#include "retdec/pelib/PeLibInc.h"

namespace PeLib
{
	/**
	 * This class handless the COFF symbol table.
	 */
	class CoffSymbolTable
	{
		private:
			std::size_t stringTableSize;
			std::uint32_t numberOfStoredSymbols;
			ByteBuffer stringTable;
			ByteBuffer symbolTableDump;
			std::vector<PELIB_IMAGE_COFF_SYMBOL> symbolTable;
			LoaderError m_ldrError;

			void read(InputBuffer& inputbuffer, unsigned int uiSize);
		public:
			CoffSymbolTable();
			~CoffSymbolTable();

			LoaderError loaderError() const;
			void setLoaderError(LoaderError ldrError);

			int read(ByteBuffer & fileData, std::size_t uiOffset, std::size_t uiSize);
			std::size_t getSizeOfStringTable() const;
			std::size_t getNumberOfStoredSymbols() const;
			std::uint32_t getSymbolIndex(std::size_t ulSymbol) const;
			const std::string & getSymbolName(std::size_t ulSymbol) const;
			std::uint32_t getSymbolValue(std::size_t ulSymbol) const;
			std::uint16_t getSymbolSectionNumber(std::size_t ulSymbol) const;
			std::uint8_t getSymbolTypeComplex(std::size_t ulSymbol) const;
			std::uint8_t getSymbolTypeSimple(std::size_t ulSymbol) const;
			std::uint8_t getSymbolStorageClass(std::size_t ulSymbol) const;
			std::uint8_t getSymbolNumberOfAuxSymbols(std::size_t ulSymbol) const;
	};
}

#endif
