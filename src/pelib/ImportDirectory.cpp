/*
* ImportDirectory.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "retdec/pelib/ImageLoader.h"
#include "retdec/pelib/ImportDirectory.h"

namespace PeLib
{
	/**
	 * Returns whether OriginalFirstThunk of specified import descriptor is valid with a given PE header.
	 * OriginalFirstThunk is valid if it has value higher than file alignment and its RVA can be translated to some offset in the file.
	 *
	 * @param impDesc Import descriptor.
	 * @param peHeader PE header.
	 *
	 * @return True if valid, otherwise false.
	 */

	inline bool hasValidOriginalFirstThunk(const PELIB_IMAGE_IMPORT_DESCRIPTOR& impDesc, const ImageLoader & imageLoader)
	{
		return (impDesc.OriginalFirstThunk < imageLoader.getSizeOfImageAligned());
	}

	/**
	* Add another import (by Ordinal) to the current file. Note that the import table is not automatically updated.
	* The new imported functions will be added when you recalculate the import table as it's necessary
	* to specify the address the import table will have in the file.
	* @param strFilename The name of a DLL.
	* @param wHint The ordinal of the function in the DLL.
	**/
	int ImportDirectory::addFunction(const std::string& strFilename, std::uint16_t wHint)
	{
		if (hasFunction(strFilename, wHint, &PELIB_THUNK_DATA::equalHint))
		{
			return ERROR_DUPLICATE_ENTRY;
		}

	 	// Find the imported file.
		ImpDirFileIterator FileIter = std::find_if(
				m_vNewiid.begin(),
				m_vNewiid.end(),
				[&](const auto& i) { return i == strFilename; }
		);

		PELIB_IMAGE_IMPORT_DIRECTORY iid;
		PELIB_THUNK_DATA td;
		td.hint = wHint;
		td.itd.Ordinal = wHint /* | PELIB_IMAGE_ORDINAL_FLAGS::PELIB_IMAGE_ORDINAL_FLAG */;
		iid.name = strFilename;
		if (FileIter == m_vNewiid.end())
		{
			iid.originalfirstthunk.push_back(td);
			iid.firstthunk.push_back(td);
			m_vNewiid.push_back(iid);
		}
		else
		{
			FileIter->originalfirstthunk.push_back(td);
			FileIter->firstthunk.push_back(td);
		}

		return ERROR_NONE;
	}

	/**
	* Add a function to the Import Directory.
	* @param strFilename Name of the file which will be imported
	* @param strFuncname Name of the function which will be imported.
	**/
	int ImportDirectory::addFunction(const std::string& strFilename, const std::string& strFuncname)
	{
		if (hasFunction(strFilename, strFuncname, &PELIB_THUNK_DATA::equalFunctionName))
		{
			return ERROR_DUPLICATE_ENTRY;
		}

	 	// Find the imported file.
		ImpDirFileIterator FileIter = std::find_if(
				m_vNewiid.begin(),
				m_vNewiid.end(),
				[&](const auto& i) { return i == strFilename; }
		);

		PELIB_IMAGE_IMPORT_DIRECTORY iid;
		PELIB_THUNK_DATA td;
		td.fname = strFuncname;
		iid.name = strFilename;
		if (FileIter == m_vNewiid.end())
		{
			iid.originalfirstthunk.push_back(td);
			iid.firstthunk.push_back(td);
			m_vNewiid.push_back(iid);
		}
		else
		{
			FileIter->originalfirstthunk.push_back(td);
			FileIter->firstthunk.push_back(td);
		}

		return ERROR_NONE;
	}

	/**
	* Searches through the import directory and returns the number of the import
	* directory entry which belongs to the given filename.
	* @param strFilename Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return The ID of an imported file.
	**/
	unsigned int ImportDirectory::getFileIndex(const std::string& strFilename, bool bOldDir) const
	{
		const std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>* currDir;

		if (bOldDir)
		{
			 currDir = &m_vOldiid;
		}
		else
		{
			 currDir = &m_vNewiid;
		}

		ConstImpDirFileIterator FileIter = std::find_if(
				currDir->begin(),
				currDir->end(),
				[&](const auto& i) { return i == strFilename; }
		);

		if (FileIter != currDir->end())
		{
			return static_cast<unsigned int>(std::distance(currDir->begin(), FileIter));
		}
		else
		{
			return -1;
			// throw Exceptions::InvalidName(ImportDirectoryId, __LINE__);
		}

		return ERROR_NONE;
	}

	/**
	* Searches through an imported file for a specific function.
	* @param strFilename Name of the imported file.
	* @param strFuncname Name of the imported function.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ID of the imported function.
	**/
	unsigned int ImportDirectory::getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, bool bOldDir) const
	{
		unsigned int uiFile = getFileIndex(strFilename, bOldDir);

		for (unsigned int i=0;i<getNumberOfFunctions(uiFile, bOldDir);i++)
		{
			if (getFunctionName(uiFile, i, bOldDir) == strFuncname) return i;
		}

		return -1;
	}

	/**
	* Get the name of an imported file.
	* @param dwFilenr Identifies which file should be checked.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported file.
	**/
	std::string ImportDirectory::getFileName(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir) return m_vOldiid[dwFilenr].name;
		else return m_vNewiid[dwFilenr].name;
	}

	void ImportDirectory::setFileName(std::uint32_t filenr, bool bOldDir, const std::string& name)
	{
		if (bOldDir) m_vOldiid[filenr].name = name;
		else m_vNewiid[filenr].name = name;
	}

	/**
	* Get the name of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported function.
	* \todo Marked line is unsafe (function should be rewritten).
	**/
	std::string ImportDirectory::getFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir) const
	{
		if (bOldDir)
		{
			// Unsafe
			// mz: fix #1189
			if (m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk && dwFuncnr < m_vOldiid[dwFilenr].originalfirstthunk.size())
			{
				return m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].fname;
			}
			else
			{
				return m_vOldiid[dwFilenr].firstthunk[dwFuncnr].fname;
			}
		}
		else
		{
			if (m_vNewiid[dwFilenr].impdesc.OriginalFirstThunk)
			{
				return m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].fname;
			}
			else
			{
				return m_vNewiid[dwFilenr].firstthunk[dwFuncnr].fname;
			}
		}
	}

	void ImportDirectory::setFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir, const std::string& functionName)
	{
		if (bOldDir)
		{
			// Unsafe
			if (m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk)
			{
				m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].fname = functionName;
			}
			else
			{
				m_vOldiid[dwFilenr].firstthunk[dwFuncnr].fname = functionName;
			}
		}
		else
		{
			if (m_vNewiid[dwFilenr].impdesc.OriginalFirstThunk)
			{
				m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].fname = functionName;
			}
			else
			{
				m_vNewiid[dwFilenr].firstthunk[dwFuncnr].fname = functionName;
			}
		}
	}

	/**
	* Get the error that was detected during import table parsing
	**/
	LoaderError ImportDirectory::loaderError() const
	{
		return m_ldrError;
	}

	void ImportDirectory::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing loader error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	/**
	* Get the hint of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Hint of an imported function.
	**/
	std::uint16_t ImportDirectory::getFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir) const
	{
		if (bOldDir)
		{
			// mz: fix #1189
			if (m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk && dwFuncnr < m_vOldiid[dwFilenr].originalfirstthunk.size())
			{
				return m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].hint;
			}
			else
			{
				return m_vOldiid[dwFilenr].firstthunk[dwFuncnr].hint;
			}
		}
		else return m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].hint;
	}

	void ImportDirectory::setFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir, std::uint16_t value)
	{
		if (bOldDir)
		{
			if (m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk)
			{
				m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].hint = value;
			}
			else
			{
				m_vOldiid[dwFilenr].firstthunk[dwFuncnr].hint = value;
			}
		}
		else m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].hint = value;
	}

	/**
	* Get the number of files which are currently being imported.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of files which are currently being imported.
	**/
	std::uint32_t ImportDirectory::getNumberOfFiles(bool bOldDir) const
	{
		if (bOldDir) return static_cast<std::uint32_t>(m_vOldiid.size());
		else return static_cast<std::uint32_t>(m_vNewiid.size());
	}

	/**
	* Get the number of functions which are currently being imported from a specific file.
	* @param dwFilenr Identifies which file should be checked.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of functions which are currently being imported from a specific file.
	**/
	std::uint32_t ImportDirectory::getNumberOfFunctions(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir) return static_cast<unsigned int>(m_vOldiid[dwFilenr].firstthunk.size());
		else return static_cast<unsigned int>(m_vNewiid[dwFilenr].firstthunk.size());
	}

	/**
	* Read an import directory from a file.
	* \todo Check if streams failed.
	* @param inStream Input stream.
	* @param peHeader A valid PE header.
	**/
	int ImportDirectory::read(ImageLoader & imageLoader)
	{
		std::uint64_t OrdinalMask = ((std::uint64_t)1 << (imageLoader.getPeFileBitability() - 1));
		std::uint32_t SizeOfImage = imageLoader.getSizeOfImage();
		std::uint32_t uiIndex;
		std::uint32_t rvaBegin = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT);
		std::uint32_t rva = rvaBegin;

		m_thunkSize = imageLoader.getPeFileBitability() / 8;
		m_ldrError = LDR_ERROR_NONE;

		// Verify whether the import directory is within the image
		if(rva > SizeOfImage)
		{
			setLoaderError(LDR_ERROR_IMPDIR_OUT_OF_FILE);
			return ERROR_INVALID_FILE;
		}

		// For tracking unique imported DLLs
		std::vector<PELIB_IMAGE_IMPORT_DIRECTORY> vOldIidCurr;
		std::unordered_map<std::string, int> uniqueDllList;
		std::uint32_t uiDescCounter = 0;

		// Read and store all descriptors
		for (;;)
		{
			PELIB_IMAGE_IMPORT_DIRECTORY iidCurr;

			// If the required range is within the file, then we read the data.
			// If not, it's RVA may still be valid due mapping -> keep zeros.
			// Example sample: de0dea00414015bacbcbfc1fa53af9f6731522687d82f5de2e9402410488d190
			// (single entry in the import directory at file offset 0x3EC4 followed by end-of-file)
			if ((rva + sizeof(PELIB_IMAGE_IMPORT_DESCRIPTOR)) >= SizeOfImage)
			{
				setLoaderError(LDR_ERROR_IMPDIR_CUT);
				break;
			}

			// The offset is within the file range -> read it from the image
			imageLoader.readImage(&iidCurr.impdesc, rva, sizeof(PELIB_IMAGE_IMPORT_DESCRIPTOR));
			rva += sizeof(PELIB_IMAGE_IMPORT_DESCRIPTOR);
			uiDescCounter++;

			// If Name or FirstThunk are 0, this descriptor is considered as null-terminator.
			if (iidCurr.impdesc.Name == 0 || iidCurr.impdesc.FirstThunk == 0)
				break;

			// We ignore import names that go beyond the file
			if (iidCurr.impdesc.Name > SizeOfImage)
			{
				setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
				break;
			}

			if (iidCurr.impdesc.FirstThunk > SizeOfImage)
			{
				setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
				break;
			}

			// Retrieve the library name from the image as ASCIIZ string
			imageLoader.readString(iidCurr.name, iidCurr.impdesc.Name);

			// Ignore too large import directories
			// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE, # of impdesc 0x6253 (invalid)
			// Sample: 395e64e7071d35cb85d8312095aede5166db731aac44920679eee5c7637cc58c, # of impdesc 0x0131 (valid)
			if (uniqueDllList.find(iidCurr.name) == uniqueDllList.end())
			{
				// Remember that the DLL was imported before
				uniqueDllList.emplace(iidCurr.name, 1);

				// Check the total number of imported DLLs
				if(uniqueDllList.size() > PELIB_MAX_IMPORT_DLLS)
				{
					setLoaderError(LDR_ERROR_IMPDIR_COUNT_EXCEEDED);
					break;
				}
			}

			// Mark the range occupied by name
			// +1 for null terminator
			// If the end address is even, we need to align it by 2, so next name always starts at even address
			m_occupiedAddresses.emplace_back(iidCurr.impdesc.Name, iidCurr.impdesc.Name + iidCurr.name.length() + 1);
			if (!(m_occupiedAddresses.back().second & 1))
				m_occupiedAddresses.back().second += 1;

			// Push the import descriptor into the vector
			vOldIidCurr.push_back(iidCurr);
		}

		// Space occupied by import descriptors
		m_occupiedAddresses.emplace_back(rvaBegin, rva);

		// OriginalFirstThunk - ILT
		for(std::size_t i = 0; i < vOldIidCurr.size(); i++)
		{
			if (vOldIidCurr[i].impdesc.OriginalFirstThunk >= imageLoader.getSizeOfImage())
				continue;

			PELIB_THUNK_DATA tdCurr;
			std::uint32_t uiVaoft = vOldIidCurr[i].impdesc.OriginalFirstThunk;

			for(uiIndex = 0; ; uiIndex++)
			{
				// Read single value (32-bit or 64-bit) from the thunk chain
				if(!imageLoader.readPointer(uiVaoft, tdCurr.itd.Ordinal))
					break;

				// Are we at the end of the list?
				if (tdCurr.itd.Ordinal == 0)
					break;

				// Did we exceed the count of imported functions?
				if(uiIndex >= PELIB_MAX_IMPORTED_FUNCTIONS)
				{
					setLoaderError(LDR_ERROR_IMPDIR_IMPORT_COUNT_EXCEEDED);
					break;
				}

				// Check samples that have import name out of the image
				// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE
				if ((tdCurr.itd.Ordinal & OrdinalMask) == 0 && (tdCurr.itd.Ordinal >= SizeOfImage))
				{
					setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
					break;
				}

				// Insert ordinal to the list
				vOldIidCurr[i].originalfirstthunk.push_back(tdCurr);
			}

			// Space occupied by OriginalFirstThunks
			// -1 because we need open interval
			if (vOldIidCurr[i].impdesc.OriginalFirstThunk < uiVaoft)
				m_occupiedAddresses.emplace_back(vOldIidCurr[i].impdesc.OriginalFirstThunk, uiVaoft - 1);
		}

/*

		// OriginalFirstThunk - ILT
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			if (!hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, peHeader))
				continue;

			PELIB_THUNK_DATA tdCurr;
			std::uint32_t uiVaoft = vOldIidCurr[i].impdesc.OriginalFirstThunk;

			inStream_w.clear();
			inStream_w.seekg(static_cast<unsigned int>(peHeader.rvaToOffset(uiVaoft)), std::ios_base::beg);

			for(uiIndex = 0; ; uiIndex++)
			{
				if (ulFileSize < peHeader.rvaToOffset(uiVaoft) + sizeof(tdCurr.itd.Ordinal))
				{
					return ERROR_INVALID_FILE;
				}
				uiVaoft += sizeof(tdCurr.itd.Ordinal);

				inStream_w.read(reinterpret_cast<char*>(&tdCurr.itd.Ordinal), sizeof(tdCurr.itd.Ordinal));

				// Are we at the end of the list?
				if (tdCurr.itd.Ordinal == 0)
					break;

				// Did we exceed the count of imported functions?
				if(uiIndex >= PELIB_MAX_IMPORTED_FUNCTIONS)
				{
					setLoaderError(LDR_ERROR_IMPDIR_IMPORT_COUNT_EXCEEDED);
					break;
				}

				// Check samples that have import name out of the image
				// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE
				if ((tdCurr.itd.Ordinal & OrdinalMask) == 0 && (tdCurr.itd.Ordinal >= SizeOfImage))
				{
					setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
					break;
				}

				// Insert ordinal to the list
				vOldIidCurr[i].originalfirstthunk.push_back(tdCurr);
			}

			// Space occupied by OriginalFirstThunks
			// -1 because we need open interval
			if (vOldIidCurr[i].impdesc.OriginalFirstThunk < uiVaoft)
				m_occupiedAddresses.emplace_back(vOldIidCurr[i].impdesc.OriginalFirstThunk, uiVaoft - 1);
		}

		// FirstThunk - IAT
		std::set<std::uint32_t> seenOffsets;
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			bool hasValidIlt = hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, peHeader);

			std::uint32_t uiVaoft = vOldIidCurr[i].impdesc.FirstThunk;
			if (!peHeader.isValidRva(uiVaoft))
			{
				return ERROR_INVALID_FILE;
			}
			if (seenOffsets.count(uiVaoft))
			{
				continue;
			}
			seenOffsets.insert(uiVaoft);
			PELIB_THUNK_DATA tdCurr;

			inStream_w.clear();
			inStream_w.seekg(static_cast<unsigned int>(peHeader.rvaToOffset(uiVaoft)), std::ios_base::beg);

			for(uiIndex = 0; ; uiIndex++)
			{
				if (ulFileSize < peHeader.rvaToOffset(uiVaoft) + sizeof(tdCurr.itd.Ordinal))
				{
					setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
					return ERROR_INVALID_FILE;
				}

				uiVaoft += sizeof(tdCurr.itd.Ordinal);

				// Read the import thunk. Make sure it's initialized in case the file read fails
				tdCurr.itd.Ordinal = 0;
				inStream_w.read(reinterpret_cast<char*>(&tdCurr.itd.Ordinal), sizeof(tdCurr.itd.Ordinal));

				// Are we at the end of the list?
				if (tdCurr.itd.Ordinal == 0)
					break;

				// Did the number of imported functions exceede maximum?
				if(uiIndex >= PELIB_MAX_IMPORTED_FUNCTIONS)
				{
					setLoaderError(LDR_ERROR_IMPDIR_IMPORT_COUNT_EXCEEDED);
					break;
				}

				// Check samples that have import name out of the image
				// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE
//				if ((tdCurr.itd.Ordinal & OrdinalMask) == 0 && (tdCurr.itd.Ordinal >= SizeOfImage))
//					break;

				vOldIidCurr[i].firstthunk.push_back(tdCurr);

				// If this import descriptor has valid ILT, then size of IAT is determined from the size of ILT
				if (hasValidIlt && vOldIidCurr[i].originalfirstthunk.size() == vOldIidCurr[i].firstthunk.size())
				{
					// We need to move this offset in this case because otherwise we would calculate the occupied addresses wrongly
					uiVaoft += sizeof(tdCurr.itd.Ordinal);
					break;
				}
			}

			// Space occupied by FirstThunks
			// -1 because we need open interval
			if (vOldIidCurr[i].impdesc.FirstThunk < uiVaoft)
				m_occupiedAddresses.emplace_back(vOldIidCurr[i].impdesc.FirstThunk, uiVaoft - 1);
		}

		// Names
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			if (hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, peHeader))
			{
				for (unsigned int j=0;j<vOldIidCurr[i].originalfirstthunk.size();j++)
				{
					if (vOldIidCurr[i].originalfirstthunk[j].itd.Ordinal & PELIB_IMAGE_ORDINAL_FLAGS::PELIB_IMAGE_ORDINAL_FLAG)
					{
						vOldIidCurr[i].originalfirstthunk[j].hint = 0;
						continue;
					}

					inStream_w.seekg(static_cast<unsigned int>(peHeader.rvaToOffset(vOldIidCurr[i].originalfirstthunk[j].itd.Ordinal)), std::ios_base::beg);

					inStream_w.read(reinterpret_cast<char*>(&vOldIidCurr[i].originalfirstthunk[j].hint), sizeof(vOldIidCurr[i].originalfirstthunk[j].hint));

					if (!inStream_w)
						return ERROR_INVALID_FILE;

					getStringFromFileOffset(
							inStream_w,
							vOldIidCurr[i].originalfirstthunk[j].fname,
							inStream_w.tellg(),
							IMPORT_SYMBOL_MAX_LENGTH);

					// Space occupied by names
					// +1 for null terminator
					// If the end address is even, we need to align it by 2, so next name always starts at even address
					m_occupiedAddresses.emplace_back(
						static_cast<unsigned int>(vOldIidCurr[i].originalfirstthunk[j].itd.Ordinal),
						static_cast<unsigned int>(vOldIidCurr[i].originalfirstthunk[j].itd.Ordinal + sizeof(vOldIidCurr[i].originalfirstthunk[j].hint) + vOldIidCurr[i].originalfirstthunk[j].fname.length() + 1)
						);
					if (!(m_occupiedAddresses.back().second & 1))
						m_occupiedAddresses.back().second += 1;
				}
			}
			else
			{
				for (unsigned int j=0;j<vOldIidCurr[i].firstthunk.size();j++)
				{
					if (vOldIidCurr[i].firstthunk[j].itd.Ordinal & PELIB_IMAGE_ORDINAL_FLAGS::PELIB_IMAGE_ORDINAL_FLAG)
					{
						continue;
					}

					inStream_w.seekg(static_cast<unsigned int>(peHeader.rvaToOffset(vOldIidCurr[i].firstthunk[j].itd.Ordinal)), std::ios_base::beg);

					inStream_w.read(reinterpret_cast<char*>(&vOldIidCurr[i].firstthunk[j].hint), sizeof(vOldIidCurr[i].firstthunk[j].hint));

					if (!inStream_w)
						return ERROR_INVALID_FILE;

					getStringFromFileOffset(
							inStream_w,
							vOldIidCurr[i].firstthunk[j].fname,
							inStream_w.tellg(),
							IMPORT_SYMBOL_MAX_LENGTH);

					// Space occupied by names
					// +1 for null terminator
					// If the end address is even, we need to align it by 2, so next name always starts at even address
					m_occupiedAddresses.emplace_back(
							static_cast<unsigned int>(vOldIidCurr[i].firstthunk[j].itd.Ordinal),
						    static_cast<unsigned int>(vOldIidCurr[i].firstthunk[j].itd.Ordinal + sizeof(vOldIidCurr[i].firstthunk[j].hint) + vOldIidCurr[i].firstthunk[j].fname.length() + 1)
						);
					if (!(m_occupiedAddresses.back().second & 1))
						m_occupiedAddresses.back().second += 1;
				}
			}
		}
		std::swap(vOldIidCurr, m_vOldiid);
		*/
		return ERROR_NONE;
	}

	/**
	* Rebuilds the import directory.
	* @param vBuffer Buffer the rebuilt import directory will be written to.
	* @param dwRva The RVA of the ImportDirectory in the file.
	* @param fixEntries Boolean flag.
	* \todo uiSizeoffuncnames is not used.
	**/
	void ImportDirectory::rebuild(std::vector<std::uint8_t>& vBuffer, std::uint32_t dwRva, bool fixEntries)
	{
		unsigned int uiImprva = dwRva;
		unsigned int uiSizeofdescriptors = (static_cast<unsigned int>(m_vNewiid.size() + m_vOldiid.size()) + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();

		unsigned int uiSizeofdllnames = 0, uiSizeoffuncnames = 0;
		unsigned int uiSizeofoft = 0;

		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			uiSizeofdllnames += static_cast<unsigned int>(m_vNewiid[i].name.size()) + 1;
			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk.size())+1) * m_thunkSize;

			for(unsigned int j=0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				// +3 for hint (std::uint16_t) and 00-std::uint8_t
				uiSizeoffuncnames += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 3);
			}
		}

//		for (unsigned int i=0;i<m_vNewiid.size();i++)
//		{
//			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk.size())+1) * PELIB_IMAGE_THUNK_DATA::size();
//		}

		OutputBuffer obBuffer(vBuffer);

		// Rebuild IMAGE_IMPORT_DESCRIPTORS
		for (unsigned int i=0;i<m_vOldiid.size();i++)
		{
			obBuffer << m_vOldiid[i].impdesc.OriginalFirstThunk;
			obBuffer << m_vOldiid[i].impdesc.TimeDateStamp;
			obBuffer << m_vOldiid[i].impdesc.ForwarderChain;
			obBuffer << m_vOldiid[i].impdesc.Name;
			obBuffer << m_vOldiid[i].impdesc.FirstThunk;
		}

		unsigned int dllsize = 0;

		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			std::uint32_t dwPoft = uiSizeofdescriptors + uiImprva;

			for (unsigned int j=1;j<=i;j++)
			{
				dwPoft += (static_cast<unsigned int>(m_vNewiid[j-1].originalfirstthunk.size()) + 1) * m_thunkSize;
			}

			obBuffer << (fixEntries ? dwPoft : m_vNewiid[i].impdesc.OriginalFirstThunk);
			obBuffer << m_vNewiid[i].impdesc.TimeDateStamp;
			obBuffer << m_vNewiid[i].impdesc.ForwarderChain;
			std::uint32_t dwPdll = uiSizeofdescriptors + uiSizeofoft + uiImprva + dllsize;
			obBuffer << (fixEntries ? dwPdll : m_vNewiid[i].impdesc.Name);
			obBuffer << m_vNewiid[i].impdesc.FirstThunk;

			// store the recalculated values
			if (fixEntries)
			{
				m_vNewiid[i].impdesc.OriginalFirstThunk = dwPoft;
				m_vNewiid[i].impdesc.Name = dwPdll;
			}

			dllsize += static_cast<unsigned int>(m_vNewiid[i].name.size()) + 1;
		}

		obBuffer << static_cast<std::uint32_t>(0);
		obBuffer << static_cast<std::uint32_t>(0);
		obBuffer << static_cast<std::uint32_t>(0);
		obBuffer << static_cast<std::uint32_t>(0);
		obBuffer << static_cast<std::uint32_t>(0);

		std::uint64_t uiPfunc = uiSizeofdescriptors + uiSizeofoft + uiSizeofdllnames + uiImprva;

		// Rebuild original first thunk
		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			for (unsigned int j=0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				if (m_vNewiid[i].originalfirstthunk[j].itd.Ordinal & m_ordinalMask
					|| fixEntries == false)
				{
					obBuffer << m_vNewiid[i].originalfirstthunk[j].itd.Ordinal;
				}
				else
				{
					obBuffer << uiPfunc;
					// store the offset in Ordinal, they cannot overlay thanks to PELIB_IMAGE_ORDINAL_FLAG
					m_vNewiid[i].originalfirstthunk[j].itd.Ordinal = uiPfunc;
				}
				uiPfunc += static_cast<std::uint64_t>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 3;
			}
			obBuffer << static_cast<std::uint64_t>(0);
		}

		// Write dllnames into import directory
		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			obBuffer.add(m_vNewiid[i].name.c_str(), static_cast<unsigned int>(m_vNewiid[i].name.size())+1);
		}

		// Write function names into directory
		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			for (unsigned int j=0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				obBuffer << m_vNewiid[i].originalfirstthunk[j].hint;
				obBuffer.add(m_vNewiid[i].originalfirstthunk[j].fname.c_str(), static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 1);
			}
		}
	}

	/**
	* Removes a specific file and all functions of it from the import directory.
	* @param strFilename Name of the file which will be removed.
	**/

	int ImportDirectory::removeFile(const std::string& strFilename)
	{
		unsigned int oldSize = static_cast<unsigned int>(m_vNewiid.size());

		m_vNewiid.erase(
			std::remove_if(
				m_vNewiid.begin(),
				m_vNewiid.end(),
				[&](const auto& i) { return i == strFilename; }
			),
			m_vNewiid.end()
		);

		return oldSize == m_vNewiid.size() ? 1 : 0;
	}

	/**
	* Removes a specific function from the import directory.
	* @param strFilename Name of the file which exports the function.
	* @param strFuncname Name of the imported function.
	**/
	int ImportDirectory::removeFunction(const std::string& strFilename, const std::string& strFuncname)
	{
		ImpDirFileIterator viPos = m_vNewiid.begin();

		int notFound = 1;

		while (viPos != m_vNewiid.end())
		{
			if (isEqualNc(viPos->name, strFilename))
			{
				unsigned int oldSize = static_cast<unsigned int>(viPos->originalfirstthunk.size());
				viPos->originalfirstthunk.erase(
					std::remove_if(
						viPos->originalfirstthunk.begin(),
						viPos->originalfirstthunk.end(),
						[&](const auto& i) { return i.equalFunctionName(strFuncname); }
					),
					viPos->originalfirstthunk.end()
				);
				if (viPos->originalfirstthunk.size() != oldSize) notFound = 0;
			}
			++viPos;
		}

		return notFound;
	}

	/**
	* Removes a specific function from the import directory.
	* @param strFilename Name of the file which exports the function.
	* @param wHint The hint of the function.
	**/
	int ImportDirectory::removeFunction(const std::string& strFilename, std::uint16_t wHint)
	{
		ImpDirFileIterator viPos = m_vNewiid.begin();
		int notFound = 1;

		while (viPos != m_vNewiid.end())
		{
			if (isEqualNc(viPos->name, strFilename))
			{
				unsigned int oldSize = static_cast<unsigned int>(viPos->originalfirstthunk.size());
				viPos->originalfirstthunk.erase(
					std::remove_if(
						viPos->originalfirstthunk.begin(),
						viPos->originalfirstthunk.end(),
						[&](const auto& i) { return i.equalHint(wHint); }
					),
					viPos->originalfirstthunk.end()
				);
				if (viPos->originalfirstthunk.size() != oldSize) notFound = 0;
			}
			++viPos;
		}

		return notFound;
	}

	/**
	* Writes the current import directory to a file.
	* @param strFilename Name of the file.
	* @param uiOffset File Offset of the new import directory.
	* @param uiRva RVA which belongs to that file offset.
	**/
	int ImportDirectory::write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva)
	{
		std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

		if (!ofFile)
		{
			ofFile.clear();
			ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
		}
		else
		{
			ofFile.close();
			ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		}

		if (!ofFile)
		{
			return ERROR_OPENING_FILE;
		}

		ofFile.seekp(uiOffset, std::ios_base::beg);

		std::vector<std::uint8_t> vBuffer;

		rebuild(vBuffer, uiRva);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), vBuffer.size());
		ofFile.close();

		std::copy(m_vNewiid.begin(), m_vNewiid.end(), std::back_inserter(m_vOldiid));
		m_vNewiid.clear();

		return ERROR_NONE;
	}

	/**
	* Returns the size of the import directory.
	* @return Size of the import directory.
	**/
	unsigned int ImportDirectory::size() const
	{
		// Only the descriptors of m_vOldiid must be rebuilt, not the data they point to.
		return std::accumulate(m_vNewiid.begin(), m_vNewiid.end(), 0, accumulate<PELIB_IMAGE_IMPORT_DIRECTORY>)
		+ (m_vOldiid.size() + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();
	}

	/**
	* @param strFilename Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	std::uint32_t ImportDirectory::getFirstThunk(const std::string& strFilename, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[getFileIndex(strFilename, bOldDir)].impdesc.FirstThunk;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, bOldDir)].impdesc.FirstThunk;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	std::uint32_t ImportDirectory::getOriginalFirstThunk(const std::string& strFilename, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[getFileIndex(strFilename, bOldDir)].impdesc.OriginalFirstThunk;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, bOldDir)].impdesc.OriginalFirstThunk;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/
	std::uint32_t ImportDirectory::getForwarderChain(const std::string& strFilename, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[getFileIndex(strFilename, bOldDir)].impdesc.ForwarderChain;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, bOldDir)].impdesc.ForwarderChain;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	std::uint32_t ImportDirectory::getTimeDateStamp(const std::string& strFilename, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[getFileIndex(strFilename, bOldDir)].impdesc.TimeDateStamp;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, bOldDir)].impdesc.TimeDateStamp;
		}
	}

	std::uint32_t ImportDirectory::getRvaOfName(const std::string& strFilename, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[getFileIndex(strFilename, bOldDir)].impdesc.Name;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, bOldDir)].impdesc.Name;
		}
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[dwFilenr].impdesc.FirstThunk;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.FirstThunk;
		}
	}

	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir)
		{
			m_vOldiid[dwFilenr].impdesc.FirstThunk = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.FirstThunk = value;
		}
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.OriginalFirstThunk;
		}
	}

	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir)
		{
			m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.OriginalFirstThunk = value;
		}
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/

	std::uint32_t ImportDirectory::getForwarderChain(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[dwFilenr].impdesc.ForwarderChain;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.ForwarderChain;
		}
	}

	void ImportDirectory::setForwarderChain(std::uint32_t dwFilenr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir)
		{
			m_vOldiid[dwFilenr].impdesc.ForwarderChain = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.ForwarderChain = value;
		}
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	std::uint32_t ImportDirectory::getTimeDateStamp(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[dwFilenr].impdesc.TimeDateStamp;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.TimeDateStamp;
		}
	}

	void ImportDirectory::setTimeDateStamp(std::uint32_t dwFilenr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir)
		{
			m_vOldiid[dwFilenr].impdesc.TimeDateStamp = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.TimeDateStamp = value;
		}
	}

	std::uint32_t ImportDirectory::getRvaOfName(std::uint32_t dwFilenr, bool bOldDir) const
	{
		if (bOldDir)
		{
			return m_vOldiid[dwFilenr].impdesc.Name;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.Name;
		}
	}

	void ImportDirectory::setRvaOfName(std::uint32_t dwFilenr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir)
		{
			m_vOldiid[dwFilenr].impdesc.Name = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.Name = value;
		}
	}

	/**
	* @param dwFilenr ID of the imported file.
	* @param dwFuncnr ID of the imported function.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported function.
	**/

	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir) const
	{
		if (bOldDir) return m_vOldiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
		else return m_vNewiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
	}

	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir) m_vOldiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal = value;
		else m_vNewiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal = value;
	}

	/**
	* @param dwFilenr ID of the imported file.
	* @param dwFuncnr ID of the imported function.
	* @param bOldDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported function.
	**/
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir) const
	{
		if (bOldDir)
		{
			if (dwFuncnr < m_vOldiid[dwFilenr].originalfirstthunk.size())
			{
				return m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal;
		}
	}

	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool bOldDir, std::uint32_t value)
	{
		if (bOldDir) m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
		else m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
	}

	const std::vector<std::pair<unsigned int, unsigned int>>& ImportDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}

} // namespace PeLib

