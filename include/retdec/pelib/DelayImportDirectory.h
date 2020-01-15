/**
 * @file DelayImportDirectory.h
 * @brief Class for delay import directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef DELAY_IMPORT_DIRECTORY_H
#define DELAY_IMPORT_DIRECTORY_H

#include "pelib/PeLibInc.h"
#include "pelib/PeHeader.h"

namespace PeLib
{
	/**
	 * This class handless delay import directory.
	 */
	template<int bits>
	class DelayImportDirectory
	{
		typedef typename std::vector<PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD<bits> >::const_iterator DelayImportDirectoryIterator;
		typedef typename FieldSizes<bits>::VAR4_8 VAR4_8;

		private:
			std::vector<PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD<bits> > records;

			void init()
			{
				records.clear();
			}

		public:
			DelayImportDirectory()
			{
				init();
			}

			~DelayImportDirectory()
			{

			}

			// Delay-import descriptors made by MS Visual C++ 6.0 has an old format
			// of delay import directory, where all entries are VAs (as opposite to RVAs from newer MS compilers).
			// We convert the delay-import directory entries to RVAs by checking the lowest bit in the delay-import descriptor's Attributes value
			VAR4_8 normalizeDelayImportValue(const PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD<bits> & rec, const PeHeaderT<bits>& peHeader, VAR4_8 valueToConvert)
			{
				// Ignore zero items
				if (valueToConvert != 0)
				{
					// Is this the old format version?
					if((rec.Attributes & 0x01) == 0)
					{
						// Sample: 0fc4cb0620f95bdd624f2c78eea4d2b59594244c6671cf249526adf2f2cb71ec
						// Contains artificially created delay import directory with incorrect values:
						//
						//  Attributes                      0x00000000 <-- Old MS delay import record, contains VAs
						//  NameRva                         0x004010e6
						//  ModuleHandleRva                 0x00000000
						//  DelayImportAddressTableRva      0x00001140 <-- WRONG! This is an RVA
						//  DelayImportNameTableRva         0x004010c0
						//  BoundDelayImportTableRva        0x00000000
						//  ...

						if (valueToConvert > peHeader.getImageBase())
						{
							valueToConvert = valueToConvert - peHeader.getImageBase();
						}
					}
				}

				return valueToConvert;
			}

			int read(std::istream& inStream, const PeHeaderT<bits>& peHeader)
			{
				init();

				IStreamWrapper inStream_w(inStream);
				if (!inStream_w)
				{
					return ERROR_OPENING_FILE;
				}

				std::uint64_t ulFileSize = fileSize(inStream_w);
				std::uint64_t uiOffset = peHeader.rvaToOffset(peHeader.getIddDelayImportRva());
				if (uiOffset >= ulFileSize)
				{
					return ERROR_INVALID_FILE;
				}

				PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD<bits> rec;
				std::vector<unsigned char> dump;
				dump.resize(PELIB_IMAGE_SIZEOF_DELAY_IMPORT_DIRECTORY_RECORD);

				// Keep loading until we encounter an entry filles with zeros
				for(std::size_t i = 0;; i += PELIB_IMAGE_SIZEOF_DELAY_IMPORT_DIRECTORY_RECORD)
				{
					InputBuffer inputbuffer(dump);

					// Read the n-th import sdirectory entry
					if (!inStream_w.seekg(uiOffset + i, std::ios::beg))
						break;
					if (!inStream_w.read(reinterpret_cast<char*>(dump.data()), PELIB_IMAGE_SIZEOF_DELAY_IMPORT_DIRECTORY_RECORD))
						break;

					rec.init();
					inputbuffer >> rec.Attributes;
					inputbuffer >> rec.NameRva;
					inputbuffer >> rec.ModuleHandleRva;
					inputbuffer >> rec.DelayImportAddressTableRva;
					inputbuffer >> rec.DelayImportNameTableRva;
					inputbuffer >> rec.BoundDelayImportTableRva;
					inputbuffer >> rec.UnloadDelayImportTableRva;
					inputbuffer >> rec.TimeStamp;
					if ( rec.Attributes == 0 && rec.NameRva == 0 && rec.ModuleHandleRva == 0 && rec.DelayImportAddressTableRva == 0 &&
						rec.DelayImportNameTableRva == 0 && rec.BoundDelayImportTableRva == 0 && rec.UnloadDelayImportTableRva == 0 &&
						rec.TimeStamp == 0)
					{
						break;
					}

					// Convert older (MS Visual C++ 6.0) delay-import descriptor to newer one.
					// These delay-import descriptors are distinguishable by lowest bit in rec.Attributes to be zero.
					// Sample: 2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4
					rec.NameRva                    = (dword)normalizeDelayImportValue(rec, peHeader, rec.NameRva);
					rec.ModuleHandleRva            = (dword)normalizeDelayImportValue(rec, peHeader, rec.ModuleHandleRva);
					rec.DelayImportAddressTableRva = (dword)normalizeDelayImportValue(rec, peHeader, rec.DelayImportAddressTableRva);
					rec.DelayImportNameTableRva    = (dword)normalizeDelayImportValue(rec, peHeader, rec.DelayImportNameTableRva);
					rec.BoundDelayImportTableRva   = (dword)normalizeDelayImportValue(rec, peHeader, rec.BoundDelayImportTableRva);
					rec.UnloadDelayImportTableRva  = (dword)normalizeDelayImportValue(rec, peHeader, rec.UnloadDelayImportTableRva);

					rec.DelayImportAddressTableOffset = (dword)peHeader.rvaToOffset(rec.DelayImportAddressTableRva);
					rec.DelayImportNameTableOffset = (dword)peHeader.rvaToOffset(rec.DelayImportNameTableRva);

					// Get name of library
					getStringFromFileOffset(inStream_w, rec.Name, (std::size_t)peHeader.rvaToOffset(rec.NameRva), IMPORT_LIBRARY_MAX_LENGTH);

					//
					//  LOADING NAME ADDRESSES/NAME ORDINALS
					//

					// Address table is not guaranteed to be null-terminated and therefore we need to first read name table.
					inStream_w.seekg(rec.DelayImportNameTableOffset, std::ios::beg);
					if(!inStream_w)
					{
						return ERROR_INVALID_FILE;
					}

					// Read all RVAs (or VAs) of import names
					std::vector<PELIB_VAR_SIZE<bits>> nameAddresses;
					for(;;)
					{
						PELIB_VAR_SIZE<bits> nameAddr;
						std::vector<byte> vBuffer(sizeof(nameAddr.Value));

						// Read the value from the file
						inStream_w.read(reinterpret_cast<char*>(vBuffer.data()), sizeof(nameAddr.Value));
						if (!inStream_w || inStream_w.gcount() < sizeof(nameAddr.Value))
							break;

						InputBuffer inb(vBuffer);
						inb >> nameAddr.Value;

						// Value of zero means that this is the end of the bound import name table
						if (nameAddr.Value == 0)
							break;
						nameAddresses.push_back(nameAddr);
					}

					//
					//  LOADING FUNCTION POINTERS
					//

					// Move to the offset of function addresses
					inStream_w.seekg(rec.DelayImportAddressTableOffset, std::ios::beg);
					if (!inStream_w)
					{
						return ERROR_INVALID_FILE;
					}

					// Read all (VAs) of import names
					std::vector<PELIB_VAR_SIZE<bits>> funcAddresses;
					for (std::size_t i = 0, e = nameAddresses.size(); i < e; ++i)
					{
						PELIB_VAR_SIZE<bits> funcAddr;
						std::vector<byte> vBuffer(sizeof(funcAddr.Value));

						// Read the value from the file
						inStream_w.read(reinterpret_cast<char*>(vBuffer.data()), sizeof(funcAddr.Value));
						if (!inStream_w || inStream_w.gcount() < sizeof(funcAddr.Value))
							break;

						InputBuffer inb(vBuffer);
						inb >> funcAddr.Value;

						// The value of zero means terminator of the function table
						if (funcAddr.Value == 0)
							break;
						funcAddresses.push_back(funcAddr);
					}

					//
					//  MERGE BOTH TOGETHER
					//

					std::size_t numberOfFunctions = std::min(nameAddresses.size(), funcAddresses.size());
					for (std::size_t i = 0; i < numberOfFunctions; i++)
					{
						PELIB_DELAY_IMPORT<bits> function;
						PELIB_VAR_SIZE<bits> nameAddr = nameAddresses[i];
						PELIB_VAR_SIZE<bits> funcAddr = funcAddresses[i];

						// Check name address. It could be ordinal, VA or RVA
						if (!(nameAddr.Value & PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG))
						{
							// Convert value to RVA, if needed
							nameAddr.Value = normalizeDelayImportValue(rec, peHeader, nameAddr.Value);

							// Read the function hint
							inStream_w.seekg(peHeader.rvaToOffset(nameAddr.Value), std::ios::beg);
							inStream_w.read(reinterpret_cast<char*>(&function.hint), sizeof(function.hint));
							if (!inStream_w || inStream_w.gcount() < sizeof(function.hint))
								break;

							// Read the function name
							getStringFromFileOffset(inStream_w, function.fname, inStream_w.tellg(), IMPORT_SYMBOL_MAX_LENGTH);
						}
						else
						{
							function.hint = (word)(nameAddr.Value & 0xFFFF);
						}

						// Fill-in function address. The table is always in the image itself
						if (peHeader.getImageBase() <= funcAddr.Value && funcAddr.Value < peHeader.getImageBase() + peHeader.getSizeOfImage())
							funcAddr.Value -= peHeader.getImageBase();
						function.address.Value = funcAddr.Value;

						// Insert the function to the list
						rec.addFunction(function);
					}

					records.push_back(rec);
				}

				return ERROR_NONE;
			}

			std::size_t getNumberOfFiles() const
			{
				return records.size();
			}

			const PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD<bits> *getFile(std::size_t index) const
			{
				return index < getNumberOfFiles() ? &records[index] : nullptr;
			}

			DelayImportDirectoryIterator begin() const
			{
				return records.begin();
			}

			DelayImportDirectoryIterator end() const
			{
				return records.end();
			}
	};
}

#endif
