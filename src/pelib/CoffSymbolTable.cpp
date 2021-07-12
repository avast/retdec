/**
 * @file CoffSymbolTable.cpp
 * @brief Class for COFF symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/CoffSymbolTable.h"

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
			std::uint32_t Zeroes, NameOffset;
			inputbuffer >> Zeroes;
			inputbuffer >> NameOffset;
			inputbuffer >> symbol.Value;
			inputbuffer >> symbol.SectionNumber;
			inputbuffer >> symbol.TypeComplex;
			inputbuffer >> symbol.TypeSimple;
			inputbuffer >> symbol.StorageClass;
			inputbuffer >> symbol.NumberOfAuxSymbols;
			symbol.Index = (std::uint32_t)i;
			if (!Zeroes)
			{
				if (stringTableSize && NameOffset)
				{
					for (std::size_t j = NameOffset; j < stringTableSize && stringTable[j] != '\0'; ++j)
					{
						// If we have symbol name with length of COFF_SYMBOL_NAME_MAX_LENGTH and it
						// contains non-printable character, stop there because it does not seem to be valid.
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

		numberOfStoredSymbols = (std::uint32_t)symbolTable.size();
	}

	int CoffSymbolTable::read(ByteBuffer & fileData, std::size_t uiOffset, std::size_t uiSize)
	{
		// Check for overflow
		if ((uiOffset + uiSize) < uiOffset)
		{
			return ERROR_INVALID_FILE;
		}

		std::size_t ulFileSize = fileData.size();
		std::size_t stringTableOffset = uiOffset + uiSize;
		if (uiOffset >= ulFileSize || stringTableOffset >= ulFileSize)
		{
			return ERROR_INVALID_FILE;
		}

		// Copy part of the file data into symbol table dump
		symbolTableDump.assign(fileData.begin() + uiOffset, fileData.begin() + uiOffset + uiSize);
		uiOffset += uiSize;

		InputBuffer ibBuffer(symbolTableDump);

		// Read size of string table
		if (ulFileSize >= stringTableOffset + 4)
		{
			stringTable.resize(sizeof(std::uint32_t));
			memcpy(&stringTableSize, fileData.data() + stringTableOffset, sizeof(uint32_t));
			*reinterpret_cast<std::uint32_t *>(stringTable.data()) = stringTableSize;
			uiOffset = stringTableOffset + sizeof(uint32_t);
		}

		if(ulFileSize > uiOffset)
		{
			if ((ulFileSize - uiOffset) < 4)
			{
				memcpy(&stringTableSize, fileData.data() + stringTableOffset, sizeof(uint32_t));
			}
			else if ((ulFileSize - uiOffset) == 4 && stringTableSize < 4)
			{
				stringTableSize = 4;
			}
		}

		if (stringTableSize > ulFileSize || uiOffset + stringTableSize > ulFileSize)
		{
			stringTableSize = (ulFileSize - uiOffset) + 4;
		}

		// read string table
		if (stringTableSize > 4)
		{
			stringTable.resize(stringTableSize);
			memcpy(stringTable.data() + 4, fileData.data() + uiOffset, stringTableSize - 4);
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

	std::uint32_t CoffSymbolTable::getSymbolIndex(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Index;
	}

	const std::string & CoffSymbolTable::getSymbolName(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Name;
	}

	std::uint32_t CoffSymbolTable::getSymbolValue(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].Value;
	}

	std::uint16_t CoffSymbolTable::getSymbolSectionNumber(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].SectionNumber;
	}

	std::uint8_t CoffSymbolTable::getSymbolTypeComplex(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].TypeComplex;
	}

	std::uint8_t CoffSymbolTable::getSymbolTypeSimple(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].TypeSimple;
	}

	std::uint8_t CoffSymbolTable::getSymbolStorageClass(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].StorageClass;
	}

	std::uint8_t CoffSymbolTable::getSymbolNumberOfAuxSymbols(std::size_t ulSymbol) const
	{
		return symbolTable[ulSymbol].NumberOfAuxSymbols;
	}
}
