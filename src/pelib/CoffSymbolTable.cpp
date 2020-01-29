/**
 * @file CoffSymbolTable.cpp
 * @brief Class for COFF symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "pelib/PeLibInc.h"
#include "pelib/CoffSymbolTable.h"

namespace PeLib
{
	CoffSymbolTable::CoffSymbolTable() : stringTableSize(0), numberOfStoredSymbols(0), m_ldrError(LDR_ERROR_NONE)
	{

	}

	CoffSymbolTable::~CoffSymbolTable()
	{

	}

	void CoffSymbolTable::read(InputBuffer& inputbuffer, unsigned int uiSize)
	{
		PELIB_IMAGE_COFF_SYMBOL symbol;

		for (std::size_t i = 0, e = uiSize / PELIB_IMAGE_SIZEOF_COFF_SYMBOL; i < e; ++i)
		{
			symbol.Name.clear();
			dword Zeroes, NameOffset;
			inputbuffer >> Zeroes;
			inputbuffer >> NameOffset;
			inputbuffer >> symbol.Value;
			inputbuffer >> symbol.SectionNumber;
			inputbuffer >> symbol.TypeComplex;
			inputbuffer >> symbol.TypeSimple;
			inputbuffer >> symbol.StorageClass;
			inputbuffer >> symbol.NumberOfAuxSymbols;
			symbol.Index = (PeLib::dword)i;
			if (!Zeroes)
			{
				if (stringTableSize && NameOffset)
				{
					for (std::size_t j = NameOffset; j < stringTableSize && stringTable[j] != '\0'; ++j)
					{
						// If we have symbol name with length of 96 and it contains non-printable character, stop there because it does not seem to be valid.
						if (j - NameOffset == COFF_SYMBOL_NAME_MAX_LENGTH)
						{
							auto nonPrintableChars = std::count_if(symbol.Name.begin(), symbol.Name.end(), [](unsigned char c) { return !isprint(c); });
							if (nonPrintableChars != 0)
								break;
						}

						symbol.Name += stringTable[j];
					}
				}
			}
			else
			{
				for (std::size_t j = i * PELIB_IMAGE_SIZEOF_COFF_SYMBOL, k = 0; k < 8 && symbolTableDump[j] != '\0'; ++j, ++k)
				{
					symbol.Name += symbolTableDump[j];
				}
			}

			i += symbol.NumberOfAuxSymbols;
			inputbuffer.move(symbol.NumberOfAuxSymbols * PELIB_IMAGE_SIZEOF_COFF_SYMBOL);
			symbolTable.push_back(symbol);
		}

		numberOfStoredSymbols = (dword)symbolTable.size();
	}

	int CoffSymbolTable::read(
			std::istream& inStream,
			unsigned int uiOffset,
			unsigned int uiSize)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		// Check for overflow
		if ((uiOffset + uiSize) < uiOffset)
		{
			return ERROR_INVALID_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		std::uint64_t stringTableOffset = uiOffset + uiSize;
		if (uiOffset >= ulFileSize || stringTableOffset >= ulFileSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);
		symbolTableDump.resize(uiSize);
		inStream_w.read(reinterpret_cast<char*>(symbolTableDump.data()), uiSize);
		InputBuffer ibBuffer(symbolTableDump);

		// read size of string table
		if (ulFileSize >= stringTableOffset + 4)
		{
			stringTable.resize(4);
			inStream_w.read(reinterpret_cast<char*>(stringTable.data()), 4);
			InputBuffer strBuf(stringTable);
			strBuf >> stringTableSize;
		}

		if (inStream_w.gcount() < 4)
		{
			stringTableSize = (std::size_t)inStream_w.gcount();
		}
		else if (inStream_w.gcount() == 4 && stringTableSize < 4)
		{
			stringTableSize = 4;
		}

		if (stringTableSize > ulFileSize || uiOffset + stringTableSize > ulFileSize)
		{
			stringTableSize = (std::size_t)(ulFileSize - uiOffset);
		}

		// read string table
		if (stringTableSize > 4)
		{
			stringTable.resize(stringTableSize);
			inStream_w.read(reinterpret_cast<char*>(stringTable.data() + 4), stringTableSize - 4);
		}

		read(ibBuffer, uiSize);

		return ERROR_NONE;
	}

	LoaderError CoffSymbolTable::loaderError() const
	{
		return m_ldrError;
	}

	void CoffSymbolTable::setLoaderError(LoaderError ldrError)
	{
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	std::size_t CoffSymbolTable::getSizeOfStringTable() const
	{
		return stringTableSize;
	}

	std::size_t CoffSymbolTable::getNumberOfStoredSymbols() const
	{
		return numberOfStoredSymbols;
	}

	dword CoffSymbolTable::getSymbolIndex(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Index;
	}

	std::string CoffSymbolTable::getSymbolName(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Name;
	}

	dword CoffSymbolTable::getSymbolValue(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Value;
	}

	word CoffSymbolTable::getSymbolSectionNumber(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].SectionNumber;
	}

	byte CoffSymbolTable::getSymbolTypeComplex(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].TypeComplex;
	}

	byte CoffSymbolTable::getSymbolTypeSimple(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].TypeSimple;
	}

	byte CoffSymbolTable::getSymbolStorageClass(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].StorageClass;
	}

	byte CoffSymbolTable::getSymbolNumberOfAuxSymbols(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].NumberOfAuxSymbols;
	}
}
