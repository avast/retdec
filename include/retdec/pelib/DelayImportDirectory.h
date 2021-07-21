/**
 * @file DelayImportDirectory.h
 * @brief Class for delay import directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PELIB_DELAY_IMPORT_DIRECTORY_H
#define RETDEC_PELIB_DELAY_IMPORT_DIRECTORY_H

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/ImageLoader.h"

namespace PeLib
{
	/**
	 * This class handles delay import directory.
	 */

	class DelayImportDirectory
	{
		typedef typename std::vector<PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD >::const_iterator DelayImportDirectoryIterator;

		private:
			std::vector<PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD> records;

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

			// Delay-import descriptors made by MS Visual C++ 6.0 have old format
			// of delay import directory, where all entries are VAs (as opposite to RVAs from newer MS compilers).
			// We convert the delay-import directory entries to RVAs by checking the lowest bit in the delay-import descriptor's Attributes value
			std::uint64_t normalizeDelayImportValue(std::uint64_t imageBase, std::uint64_t virtualAddress)
			{
				// Ignore zero items
				if (virtualAddress != 0)
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

					if (virtualAddress > imageBase)
					{
						virtualAddress = virtualAddress - imageBase;
					}
				}

				return virtualAddress;
			}

			void normalize32BitDelayImport(PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR & rec, std::uint64_t imageBase)
			{
				rec.NameRva                    = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.NameRva);
				rec.ModuleHandleRva            = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.ModuleHandleRva);
				rec.DelayImportAddressTableRva = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.DelayImportAddressTableRva);
				rec.DelayImportNameTableRva    = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.DelayImportNameTableRva);
				rec.BoundDelayImportTableRva   = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.BoundDelayImportTableRva);
				rec.UnloadDelayImportTableRva  = (std::uint32_t)normalizeDelayImportValue(imageBase, rec.UnloadDelayImportTableRva);
			}

			bool isTerminationEntry(PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR & importDescriptor)
			{
				return (importDescriptor.Attributes == 0 &&
						importDescriptor.NameRva == 0 &&
						importDescriptor.ModuleHandleRva == 0 &&
						importDescriptor.DelayImportAddressTableRva == 0 &&
						importDescriptor.DelayImportNameTableRva == 0 &&
						importDescriptor.BoundDelayImportTableRva == 0 &&
						importDescriptor.UnloadDelayImportTableRva == 0 &&
						importDescriptor.TimeStamp == 0);
			}

			int read(ImageLoader & imageLoader)
			{
				std::uint32_t rva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
				std::uint32_t size = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
				std::uint32_t sizeOfImage = imageLoader.getSizeOfImage();
				std::uint32_t pointerSize = imageLoader.getPointerSize();
				std::uint64_t imageBase   = imageLoader.getImageBase();
				std::uint64_t ordinalMask = imageLoader.getOrdinalMask();

				if(rva >= sizeOfImage)
					return ERROR_INVALID_FILE;
				init();

				// Keep loading until we encounter an entry filled with zeros
				for(std::uint32_t i = 0;; i += sizeof(PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR))
				{
					PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD rec;

					// Read the n-th import directory entry
					if((rva + i) >= sizeOfImage)
						break;
					if(!imageLoader.readImage(&rec.delayedImport, rva + i, sizeof(PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR)))
						break;

					// Valid delayed import entry starts either with 0 or 0x01.
					// We strict require one of the valid values here
					if(rec.delayedImport.Attributes > PELIB_DELAY_ATTRIBUTE_V2)
						break;

					// Stop on blatantly invalid entries
					if(rec.delayedImport.NameRva < sizeof(PELIB_IMAGE_DOS_HEADER) ||
					   rec.delayedImport.DelayImportNameTableRva < sizeof(PELIB_IMAGE_DOS_HEADER))
						break;

					// Check for the termination entry
					if(isTerminationEntry(rec.delayedImport))
						break;

					// Convert older (MS Visual C++ 6.0) delay-import descriptor to newer one.
					// These delay-import descriptors are distinguishable by lowest bit in rec.Attributes to be zero.
					// Sample: 2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4
					if(imageLoader.getImageBitability() == 32 && (rec.delayedImport.Attributes & PELIB_DELAY_ATTRIBUTE_V2) == 0)
						normalize32BitDelayImport(rec.delayedImport, (std::uint32_t)imageBase);

					// Stop on blatantly invalid delay import entries (old PELIB behavior)
					if(rec.delayedImport.DelayImportNameTableRva >= sizeOfImage || rec.delayedImport.DelayImportAddressTableRva >= sizeOfImage)
						return ERROR_INVALID_FILE;

					// Get name of library
					imageLoader.readString(rec.Name, rec.delayedImport.NameRva, IMPORT_LIBRARY_MAX_LENGTH);

					//
					//  LOADING NAME ADDRESSES/NAME ORDINALS
					//

					std::vector<uint64_t> nameAddresses;
					std::uint32_t rva2 = rec.delayedImport.DelayImportNameTableRva;

					for(;;)
					{
						std::uint64_t nameAddress;

						// Read single name address. Also stop processing if the RVA gets out of image
						if(imageLoader.readPointer(rva2, nameAddress) != pointerSize)
							return ERROR_INVALID_FILE;
						rva2 += pointerSize;

						// Value of zero means that this is the end of the bound import name table
						if(nameAddress == 0)
							break;
						nameAddresses.push_back(nameAddress);
					}

					//
					//  LOADING FUNCTION POINTERS
					//

					std::vector<uint64_t> funcAddresses;
					rva2 = rec.delayedImport.DelayImportAddressTableRva;

					// Read all (VAs) of import names
					for (std::size_t i = 0; i < nameAddresses.size(); i++)
					{
						std::uint64_t funcAddress;

						// Read single name address. Also stop processing if the RVA gets out of image
						if(imageLoader.readPointer(rva2, funcAddress) != pointerSize)
							return ERROR_INVALID_FILE;
						rva2 += pointerSize;

						// Value of zero means that this is the end of the bound import name table
						if(funcAddress == 0)
							break;
						funcAddresses.push_back(funcAddress);
					}

					//
					//  MERGE BOTH TOGETHER
					//

					std::size_t numberOfFunctions = std::min(nameAddresses.size(), funcAddresses.size());
					for (std::size_t i = 0; i < numberOfFunctions; i++)
					{
						PELIB_DELAY_IMPORT function;
						std::uint64_t nameAddress = nameAddresses[i];
						std::uint64_t funcAddress = funcAddresses[i];

						// Check name address. It could be ordinal, VA or RVA
						if (!(nameAddress & ordinalMask))
						{
							// Convert name address to RVA, if needed
							if((rec.delayedImport.Attributes & PELIB_DELAY_ATTRIBUTE_V2) == 0)
								nameAddress = normalizeDelayImportValue(imageBase, nameAddress);

							// Read the function hint
							if(imageLoader.readImage(&function.hint, nameAddress, sizeof(function.hint)) != sizeof(function.hint))
								break;

							// Read the function name
							imageLoader.readString(function.fname, nameAddress + sizeof(function.hint), IMPORT_SYMBOL_MAX_LENGTH);
						}
						else
						{
							function.hint = (std::uint16_t)(nameAddress & 0xFFFF);
						}

						// Convert function address to RVA, if needed
						if(imageBase <= funcAddress && funcAddress < imageBase + sizeOfImage)
							funcAddress -= imageBase;
						function.address = funcAddress;

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

			const PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD *getFile(std::size_t index) const
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
