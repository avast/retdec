/*
* ImportDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_IMPORTDIRECTORY_H
#define RETDEC_PELIB_IMPORTDIRECTORY_H

#include <set>
#include <unordered_map>

#include "retdec/pelib/PeLibAux.h"
#include "retdec/pelib/ImageLoader.h"
#include "retdec/pelib/ImageLoader.h"
#include "retdec/utils/ord_lookup.h"
#include "retdec/utils/string.h"

namespace PeLib
{
	class PeLibException;

	/// Class that handles import directories.
	/**
	* This class can read import directories from existing PE files or start completely from scratch.
	* Modifying import directories and writing them to files is also possible.
	* It's worthy to note that many functions require an extra parameter of type newDir
	* because the structure of import directories make it necessary that the OLDDIR import directory
	* must be preserved. That's why some functions (like adding and removing) imported functions
	* only exist for the new import directory, not for the one which is already written to the file.
	* \todo Adding functions by ordinal doesn't work yet (rebuild needs to be changed).
	* \todo Somehow store the rvas of the chunks in the file.
	**/

	class ImportDirectory
	{
		typedef typename std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>::iterator ImpDirFileIterator;
		typedef typename std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>::const_iterator ConstImpDirFileIterator;

		private:
		  /// Stores information about already imported DLLs.
		  std::vector<PELIB_IMAGE_IMPORT_DIRECTORY> m_vOldiid;
		  /// Stores information about imported DLLs which will be added.
		  std::vector<PELIB_IMAGE_IMPORT_DIRECTORY> m_vNewiid;
		  /// Stores RVAs which are occupied by this import directory.
		  std::vector<std::pair<unsigned int, unsigned int>> m_occupiedAddresses;
		  /// Mask for file ordinal
		  std::uint64_t m_ordinalMask;
		  /// Error detected by the import table parser
		  LoaderError m_ldrError;
		  /// size of single thunk item
		  std::size_t m_thunkSize;

		// I can't convince Borland C++ to compile the function outside of the class declaration.
		// That's why the function definition is here.
		/// Tests if a certain function is imported.
		template<typename T> bool hasFunction(std::string strFilename, T value, bool(PELIB_THUNK_DATA::* comp)(T) const) const
		{
			ConstImpDirFileIterator FileIter = m_vOldiid.begin();
			ConstImpDirFileIterator EndIter = m_vOldiid.end();

			for (int i=0;i<=1;i++) // Loop once for m_vOldiid and once for m_vNewiid
			{
				do
				{
					FileIter = std::find_if(
							FileIter,
							EndIter,
							[&](const auto& i) { return i == strFilename; }
					);

					if (FileIter != EndIter)
					{
						auto Iter = std::find_if(
								FileIter->thunk_data.begin(),
								FileIter->thunk_data.end(),
								std::bind(comp, std::placeholders::_1, value)
						);
						if (Iter != FileIter->thunk_data.end())
						{
							return true;
						}
						++FileIter;
					}
				}
				while (FileIter != EndIter);

				FileIter = m_vNewiid.begin();
				EndIter = m_vNewiid.end();
	 		}

	 		return false;
		}

		public:

		  /// Constructor
		  ImportDirectory() : m_ldrError(LDR_ERROR_NONE)
		  {
			  m_ordinalMask = 0x80000000;
			  m_thunkSize = 4;
		  }

		  /// Add a function to the import directory.
		  int addFunction(const std::string& strFilename, std::uint16_t wHint); // EXPORT _byHint
		  /// Add a function to the import directory.
		  int addFunction(const std::string& strFilename, const std::string& strFuncname); // EXPORT _byName

		  /// Get the ID of a file through it's name.
		  unsigned int getFileIndex(const std::string& strFilename, bool newDir) const; // EXPORT
		  /// Get the ID of a function through it's name.
		  unsigned int getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, bool newDir) const; // EXPORT

		  /// Get the name of an imported file.
		  std::string getFileName(std::uint32_t dwFilenr, bool newDir) const; // EXPORT

		  void setFileName(std::uint32_t filenr, bool newDir, const std::string& name); // EXPORT

		  /// Retrieve the loader error
		  LoaderError loaderError() const;
		  void setLoaderError(LoaderError ldrError);

		  /// Get the number of files which are imported.
		  std::uint32_t getNumberOfFiles(bool newDir) const; // EXPORT
		  /// Get the number of functions which are imported by a specific file.
		  std::uint32_t getNumberOfFunctions(std::size_t dwFilenr, bool newDir) const; // EXPORT
		  /// Get information about n-th imported function
		  bool getImportedFunction(std::size_t dwFilenr, std::size_t dwFuncnr, std::string & importName, std::uint16_t & importHint, std::uint32_t & importOrdinal, std::uint32_t & patchRva, bool & isImportByOrdinal, bool newDir) const;

		  /// Get the hint of an imported function.
		  std::uint16_t getFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const; // EXPORT
		  void setFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint16_t value); // EXPORT
		  /// Get the name of an imported function.
		  std::string getFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const; // EXPORT
		  void setFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, const std::string& functionName); // EXPORT
		  /// Read a file's import directory.
		  int read(ImageLoader & imageLoader); // EXPORT
		  /// Writes pointer to the buffer (32-bit or 64-bit)
		  void writePointer(OutputBuffer & obBuffer, std::uint64_t pointerValue);
		  /// Rebuild the import directory.
		  void rebuild(std::vector<std::uint8_t>& vBuffer, std::uint32_t dwRva, bool fixEntries = true); // EXPORT
		  /// Remove a file from the import directory.
		  int removeFile(const std::string& strFilename); // EXPORT
		  /// Remove a function from the import directory.
		  int removeFunction(const std::string& strFilename, const std::string& strFuncname); // EXPORT _byName
		  /// Remove a function from the import directory.
		  int removeFunction(const std::string& strFilename, std::uint16_t wHint); // EXPORT _byHint
		  /// Returns the size of the current import directory.
		  unsigned int calculateSize(std::uint32_t pointerSize) const; // EXPORT
		  /// Writes the import directory to a file.
		  int write(const std::string& strFilename, std::uint32_t uiOffset, std::uint32_t uiRva, std::uint32_t pointerSize); // EXPORT
		  /// Updates the pointer size for the import directory
		  void setPointerSize(std::uint32_t pointerSize);

		  /// Returns the FirstThunk value of a function.
		  std::uint32_t getFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const; // EXPORT _byNumber
		  void setFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint32_t value); // EXPORT _byNumber
		  /// Returns the OriginalFirstThunk value of a function.
		  std::uint32_t getOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const; // EXPORT _byNumber
		  void setOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint32_t value); // EXPORT

//		  std::uint64_t getFirstThunk(const std::string& strFilename, const std::string& strFuncname, bool newDir) const throw (PeLibException);
//		  std::uint64_t getOriginalFirstThunk(const std::string& strFilename, const std::string& strFuncname, bool newDir) const throw (PeLibException);

		  /// Returns the FirstThunk value of a file.
		  std::uint32_t getFirstThunk(const std::string& strFilename, bool newDir) const; // EXPORT _byName
		  /// Returns the OriginalFirstThunk value of a file.
		  std::uint32_t getOriginalFirstThunk(const std::string& strFilename, bool newDir) const; // EXPORT _byName
		  /// Returns the ForwarderChain value of a file.
		  std::uint32_t getForwarderChain(const std::string& strFilename, bool newDir) const; // EXPORT _byName
		  std::uint32_t getRvaOfName(const std::string& strFilename, bool newDir) const; // EXPORT _byName
		  /// Returns the TimeDateStamp value of a file.
		  std::uint32_t getTimeDateStamp(const std::string& strFilename, bool newDir) const; // EXPORT _byName

		  /// Returns the FirstThunk value of a file.
		  std::uint32_t getFirstThunk(std::uint32_t dwFilenr, bool newDir) const; // EXPORT
		  void setFirstThunk(std::uint32_t dwFilenr, bool newDir, std::uint32_t value); // EXPORT _byNumber_function
		  /// Returns the OriginalFirstThunk value of a file.
		  std::uint32_t getOriginalFirstThunk(std::uint32_t dwFilenr, bool newDir) const; // EXPORT
		  void setOriginalFirstThunk(std::uint32_t dwFilenr, bool newDir, std::uint32_t value); // EXPORT _byNumber_function
		  /// Returns the ForwarderChain value of a file.
		  std::uint32_t getForwarderChain(std::uint32_t dwFilenr, bool newDir) const; // EXPORT _byNumber
		  void setForwarderChain(std::uint32_t dwFilenr, bool newDir, std::uint32_t value); // EXPORT _byNumber_function
		  std::uint32_t getRvaOfName(std::uint32_t dwFilenr, bool newDir) const; // EXPORT _byNumber
		  void setRvaOfName(std::uint32_t dwFilenr, bool newDir, std::uint32_t value); // EXPORT
		  /// Returns the TimeDateStamp value of a file.
		  std::uint32_t getTimeDateStamp(std::uint32_t dwFilenr, bool newDir) const; // EXPORT
		  void setTimeDateStamp(std::uint32_t dwFilenr, bool newDir, std::uint32_t value); // EXPORT _byNumber

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;

//		  std::uint16_t getFunctionHint(const std::string& strFilename, const std::string& strFuncname, bool newDir) const throw (PeLibException);

		protected:

		  const std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>& getImportList(bool newDir) const;
		  std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>& getImportList(bool newDir);
	};

	/**
	 * Returns whether OriginalFirstThunk of specified import descriptor is valid with a given PE header.
	 * OriginalFirstThunk is valid if it has value higher than file alignment and its RVA can be translated to some offset in the file.
	 *
	 * @param impDesc Import descriptor.
	 * @param imageLoader Reference to image loader.
	 *
	 * @return True if valid, otherwise false.
	 */

	inline bool hasValidOriginalFirstThunk(const PELIB_IMAGE_IMPORT_DESCRIPTOR& impDesc, const ImageLoader & imageLoader)
	{
		return (imageLoader.getSizeOfHeaders() <= impDesc.OriginalFirstThunk && impDesc.OriginalFirstThunk < imageLoader.getSizeOfImage());
	}

	/**
	* Add another import (by Ordinal) to the current file. Note that the import table is not automatically updated.
	* The new imported functions will be added when you recalculate the import table as it's necessary
	* to specify the address the import table will have in the file.
	* @param strFilename The name of a DLL.
	* @param wHint The ordinal of the function in the DLL.
	**/
	inline
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
		td.itd.Ordinal = wHint | m_ordinalMask;
		iid.name = strFilename;
		if (FileIter == m_vNewiid.end())
		{
			iid.thunk_data.push_back(td);
			m_vNewiid.push_back(iid);
		}
		else
		{
			FileIter->thunk_data.push_back(td);
		}

		return ERROR_NONE;
	}

	/**
	* Add a function to the Import Directory.
	* @param strFilename Name of the file which will be imported
	* @param strFuncname Name of the function which will be imported.
	**/
	inline
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
			iid.thunk_data.push_back(td);
			m_vNewiid.push_back(iid);
		}
		else
		{
			FileIter->thunk_data.push_back(td);
		}

		return ERROR_NONE;
	}

	/**
	* Searches through the import directory and returns the number of the import
	* directory entry which belongs to the given filename.
	* @param strFilename Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return The ID of an imported file.
	**/
	inline
	unsigned int ImportDirectory::getFileIndex(const std::string& strFilename, bool newDir) const
	{
		auto * il = &getImportList(newDir);

		ConstImpDirFileIterator FileIter = std::find_if(
				il->begin(),
				il->end(),
				[&](const auto& i) { return i == strFilename; }
		);

		if (FileIter != il->end())
		{
			return static_cast<unsigned int>(std::distance(il->begin(), FileIter));
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
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ID of the imported function.
	**/
	inline
	unsigned int ImportDirectory::getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, bool newDir) const
	{
		unsigned int uiFile = getFileIndex(strFilename, newDir);

		for (unsigned int i=0;i<getNumberOfFunctions(uiFile, newDir);i++)
		{
			if (getFunctionName(uiFile, i, newDir) == strFuncname) return i;
		}

		return -1;
	}

	/**
	* Get the name of an imported file.
	* @param dwFilenr Identifies which file should be checked.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported file.
	**/
	inline
	std::string ImportDirectory::getFileName(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].name;
	}

	inline
	void ImportDirectory::setFileName(std::uint32_t filenr, bool newDir, const std::string& name)
	{
		getImportList(newDir)[filenr].name = name;
	}

	/**
	* Get the name of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported function.
	* \todo Marked line is unsafe (function should be rewritten).
	**/
	inline
	std::string ImportDirectory::getFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const
	{
		auto & il = getImportList(newDir);

		if(dwFilenr < il.size() && dwFuncnr < il[dwFilenr].thunk_data.size())
		{
			return il[dwFilenr].thunk_data[dwFuncnr].fname;
		}
	}

	inline
	void ImportDirectory::setFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, const std::string& functionName)
	{
		auto & il = getImportList(newDir);

		if(dwFilenr < il.size() && dwFuncnr < il[dwFilenr].thunk_data.size())
		{
			il[dwFilenr].thunk_data[dwFuncnr].fname = functionName;
		}
	}

	/**
	* Get the error that was detected during import table parsing
	**/
	inline
	LoaderError ImportDirectory::loaderError() const
	{
		return m_ldrError;
	}

	inline
	void ImportDirectory::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing loader error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	/**
	* Get the number of files which are currently being imported.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of files which are currently being imported.
	**/
	inline
	std::uint32_t ImportDirectory::getNumberOfFiles(bool newDir) const
	{
		return static_cast<std::uint32_t>(getImportList(newDir).size());
	}

	/**
	* Get the number of functions which are currently being imported from a specific file.
	* @param dwFilenr Identifies which file should be checked.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of functions which are currently being imported from a specific file.
	**/
	inline
	std::uint32_t ImportDirectory::getNumberOfFunctions(std::size_t dwFilenr, bool newDir) const
	{
		auto& il = getImportList(newDir);
		std::uint32_t numFuncs = 0;

		if(dwFilenr < il.size())
			numFuncs = static_cast<std::uint32_t>(il[dwFilenr].thunk_data.size());
		return numFuncs;
	}

	/**
	* Retrieves the n-th import function from the m-th import directory
	* @param dwFilenr Zero-based index of the imported module
	* @param dwFuncnr Zero-based index of the imported function in the module above
	* @param importName If this is import by name, this string is filled by the import name
	* @param importHint If this is import by name, this 16-bit integer will be filled by the import hint
	* @param importOrdinal If this is import by orginal, this 32-bit integer will be filled by the ordinal of the function
	* @param patchRva RVA of the patched address
	* @param isImportByOrdinal Set to true if this is import by ordinal
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return true = the indexes are in range, so an import was returned
	**/
	inline
	bool ImportDirectory::getImportedFunction(
		std::size_t dwFilenr,
		std::size_t dwFuncnr,
		std::string& importName,
		std::uint16_t& importHint,
		std::uint32_t& importOrdinal,
		std::uint32_t& patchRva,
		bool& isImportByOrdinal,
		bool newDir) const
	{
		auto& il = getImportList(newDir);

		// Range check for the number of modules
		if(dwFilenr < il.size())
		{
			// Range check for the number of functions
			if(dwFuncnr < il[dwFilenr].thunk_data.size())
			{
				if(il[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal & m_ordinalMask)
				{
					importOrdinal = il[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal & ~m_ordinalMask;
					isImportByOrdinal = true;
					importHint = 0;
				}
				else
				{
					importHint = il[dwFilenr].thunk_data[dwFuncnr].hint;
					isImportByOrdinal = false;
					importOrdinal = 0;
				}

				// Function name may be present even if import by ordinal
				// (auto-retrieved on well-known ordinals, e.g. ws2_32.dll)
				importName = il[dwFilenr].thunk_data[dwFuncnr].fname;
				patchRva = il[dwFilenr].thunk_data[dwFuncnr].patchRva;
				return true;
			}
		}

		// Out of range
		return false;
	}

	/**
	* Get the hint of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Hint of an imported function.
	**/
	inline
	std::uint16_t ImportDirectory::getFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const
	{
		auto& il = getImportList(newDir);
		std::uint16_t hint = 0;

		if(dwFilenr < il.size() && dwFuncnr < il[dwFilenr].thunk_data.size())
		{
			hint = il[dwFilenr].thunk_data[dwFuncnr].hint;
		}

		return hint;
	}

	inline
	void ImportDirectory::setFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint16_t value)
	{
		auto& il = getImportList(newDir);

		if(dwFilenr < il.size() && dwFuncnr < il[dwFilenr].thunk_data.size())
		{
			il[dwFilenr].thunk_data[dwFuncnr].hint = value;
		}
	}

	/**
	* Updates pointer size for import directory
	* @param pointerSize Size of the pointer (4 or 8 bytes).
	**/

	inline void ImportDirectory::setPointerSize(std::uint32_t pointerSize)
	{
		m_thunkSize = pointerSize;
		m_ordinalMask = (uint64_t)1 << ((pointerSize * 8) - 1);
	}

	inline bool isBadImportName(const std::string & importName)
	{
		// The name be of nonzero length
		if(importName.size() == 0)
			return true;

		// We don't accept space as the first character, but we accept space in the middle
		// retdec-regression-tests\tools\fileinfo\bugs\issue-460-hash-from-empty-string\000b1f22029c979c27c7310712cae66b8ade37378023487277ad7c86d59a34f6
		if(importName[0] <= 0x20)
			return true;

		// All characters of the name must be a valid (printable) ASCII char
		// Sample: retdec-regression-tests\tools\fileinfo\features\malformed-imports-exports\7CE5BB5CA99B3570514AF03782545D41213A77A0F93D4AAC8269823A8D3A58EF.dat
		for(unsigned char singleChar : importName)
		{
			if(singleChar < 0x20 || singleChar >= 0x7f)
				return true;
		}

		// We didn't find any reason to consider this import invalid
		return false;
	}

	/**
	* Read an import directory from a file.
	* \todo Check if streams failed.
	* @param imageLoader A valid PE loader.
	**/
	inline
	int ImportDirectory::read(ImageLoader & imageLoader)
	{
		std::uint64_t OrdinalMask = imageLoader.getOrdinalMask();
		std::uint32_t SizeOfImage = imageLoader.getSizeOfImage();
		std::uint32_t rvaBegin = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT);
		std::uint32_t rva = rvaBegin;
		std::uint32_t uiIndex;

		setPointerSize(imageLoader.getPointerSize());
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
		std::set<std::uint32_t> seenOffsets;
		std::uint32_t uiDescCounter = 0;

		// Read and store all descriptors. Each descriptor corresponds to one imported DLL name.
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
			imageLoader.readString(iidCurr.name, iidCurr.impdesc.Name, IMPORT_LIBRARY_MAX_LENGTH);

			// Sample: 0BBA9D483A5E26932C1BA5904EA8FA2E063E0419C7B8A6342814266E96E1CEA2
			// 4 imports all invalid names. We stop parsing the imports at an invalid entry,
			// but we won't say that the file is invalid
			if (isBadImportName(iidCurr.name))
			{
				setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
				break;
			}

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
			vOldIidCurr.push_back(std::move(iidCurr));
		}

		// Space occupied by import descriptors
		m_occupiedAddresses.emplace_back(rvaBegin, rva);

		// Read the import entries (functions) for each import descriptor. Read both thunks at once
		for(std::size_t i = 0; i < vOldIidCurr.size(); i++)
		{
			// This reflects the check in the Windows loader (LdrpSnapIAT)
			// "If the OriginalFirstThunk field does not point inside the image, then ignore
			// it. This is will detect bogus Borland Linker 2.25 images that did not fill
			// this field in."
			std::uint32_t originalThunk = hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, imageLoader) ?
				                                                     vOldIidCurr[i].impdesc.OriginalFirstThunk :
				                                                     vOldIidCurr[i].impdesc.FirstThunk;
			std::uint32_t firstThunk = vOldIidCurr[i].impdesc.FirstThunk;

			// Don't allow multiple import descriptors to take data from the same RVA
			if(seenOffsets.count(firstThunk))
				continue;
			seenOffsets.insert(firstThunk);

			// Parse individual imports
			for(uiIndex = 0;; uiIndex++)
			{
				PELIB_THUNK_DATA thunkData;

				// Read single value (32-bit or 64-bit) from the thunk chain
				if(!imageLoader.readPointer(originalThunk, thunkData.itd.Ordinal))
					break;

				// Are we at the end of the list?
				if(thunkData.itd.Ordinal == 0)
					break;

				// Did we exceed the count of imported functions?
				if(uiIndex >= PELIB_MAX_IMPORTED_FUNCTIONS)
				{
					setLoaderError(LDR_ERROR_IMPDIR_IMPORT_COUNT_EXCEEDED);
					break;
				}

				// Set the patch RVA
				thunkData.patchRva = firstThunk;

				// Is it an import by name?
				if((thunkData.itd.Ordinal & OrdinalMask) == 0)
				{
					// Check samples that have import name out of the image
					// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE
					if(thunkData.itd.Ordinal < imageLoader.getSizeOfImage())
					{
						// Read the import hint
						if(imageLoader.readImage(&thunkData.hint, thunkData.itd.Ordinal, sizeof(std::uint16_t)) != sizeof(std::uint16_t))
						{
							setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
							thunkData.hint = 0;
						}

						// Read the import name
						imageLoader.readString(thunkData.fname, thunkData.itd.Ordinal + sizeof(std::uint16_t), IMPORT_SYMBOL_MAX_LENGTH);

						// Space occupied by names
						// +1 for null terminator
						// If the end address is even, we need to align it by 2, so next name always starts at even address
						m_occupiedAddresses.emplace_back(
							static_cast<unsigned int>(thunkData.itd.Ordinal),
							static_cast<unsigned int>(thunkData.itd.Ordinal + sizeof(thunkData.hint) + thunkData.fname.length() + 1)
						);

						// Align the end by 2
						m_occupiedAddresses.back().second = (m_occupiedAddresses.back().second + 1) & 0xFFFFFFFFE;
					}
					else
					{
						setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
					}
				}
				else
				{
					// Mask out the ordinal bit. Then, any ordinal must not be larger than 0xFFFF
					std::uint32_t ordinal = thunkData.itd.Ordinal & ~OrdinalMask;

					// Import by ordinal must be lower-word only; any ordinal that is greater than 0xFFFF is invalid.
					// Sample: 7CE5BB5CA99B3570514AF03782545D41213A77A0F93D4AAC8269823A8D3A58EF
					if((ordinal >> 0x10) == 0)
					{
						thunkData.fname = retdec::utils::ordLookUp(vOldIidCurr[i].name, ordinal, false);
						thunkData.hint = 0;
					}
					else
					{
						setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
					}
				}

				// Insert the thunk into the import descriptor
				vOldIidCurr[i].thunk_data.push_back(thunkData);

				// Increment both pointers
				originalThunk += imageLoader.getPointerSize();
				firstThunk += imageLoader.getPointerSize();
			}
		}

		std::swap(vOldIidCurr, m_vOldiid);
		return ERROR_NONE;
	}

	inline void ImportDirectory::writePointer(OutputBuffer & obBuffer, std::uint64_t pointerValue)
	{
		if(m_thunkSize == sizeof(std::uint32_t))
		{
			std::uint32_t pointerValue32 = (std::uint32_t)pointerValue;
			obBuffer << pointerValue32;
		}
		else
		{
			obBuffer << pointerValue;
		}
	}

	/**
	* Rebuilds the import directory.
	* @param vBuffer Buffer the rebuilt import directory will be written to.
	* @param dwRva The RVA of the ImportDirectory in the file.
	* @param fixEntries Boolean flag.
	* \todo uiSizeoffuncnames is not used.
	**/
	inline
	void ImportDirectory::rebuild(std::vector<std::uint8_t>& vBuffer, std::uint32_t dwRva, bool fixEntries)
	{
		unsigned int uiImprva = dwRva;
		unsigned int uiSizeofdescriptors = (static_cast<unsigned int>(m_vNewiid.size() + m_vOldiid.size()) + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();

		unsigned int uiSizeofdllnames = 0, uiSizeoffuncnames = 0;
		unsigned int uiSizeofoft = 0;

		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			uiSizeofdllnames += static_cast<unsigned int>(m_vNewiid[i].name.size()) + 1;
			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].thunk_data.size())+1) * m_thunkSize;

			for(unsigned int j=0;j<m_vNewiid[i].thunk_data.size();j++)
			{
				// +3 for hint (std::uint16_t) and 00-std::uint8_t
				uiSizeoffuncnames += (static_cast<unsigned int>(m_vNewiid[i].thunk_data[j].fname.size()) + 3);
			}
		}

//		for (unsigned int i=0;i<m_vNewiid.size();i++)
//		{
//			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].thunk_data.size())+1) * PELIB_IMAGE_THUNK_DATA::size();
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
				dwPoft += (static_cast<unsigned int>(m_vNewiid[j-1].thunk_data.size()) + 1) * m_thunkSize;
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
		for (std::size_t i = 0;i<m_vNewiid.size();i++)
		{
			for (std::size_t j = 0;j<m_vNewiid[i].thunk_data.size();j++)
			{
				if((m_vNewiid[i].thunk_data[j].itd.Ordinal & m_ordinalMask) || fixEntries == false)
				{
					writePointer(obBuffer, m_vNewiid[i].thunk_data[j].itd.Ordinal);
					//obBuffer << m_vNewiid[i].thunk_data[j].itd.Ordinal;
				}
				else
				{
					writePointer(obBuffer, uiPfunc);
					//obBuffer << uiPfunc;
					// store the offset in Ordinal, they cannot overlay thanks to PELIB_IMAGE_ORDINAL_FLAG
					m_vNewiid[i].thunk_data[j].itd.Ordinal = uiPfunc;
				}
				uiPfunc += static_cast<std::uint64_t>(m_vNewiid[i].thunk_data[j].fname.size()) + 3;
			}
			writePointer(obBuffer, 0);
			//obBuffer << static_cast<std::uint64_t>(0);
		}

		// Write dllnames into import directory
		for (std::size_t i = 0; i < m_vNewiid.size(); i++)
		{
			obBuffer.add(m_vNewiid[i].name.c_str(), static_cast<unsigned int>(m_vNewiid[i].name.size())+1);
		}

		// Write function names into directory
		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			for (unsigned int j=0;j<m_vNewiid[i].thunk_data.size();j++)
			{
				obBuffer << m_vNewiid[i].thunk_data[j].hint;
				obBuffer.add(m_vNewiid[i].thunk_data[j].fname.c_str(), static_cast<unsigned int>(m_vNewiid[i].thunk_data[j].fname.size()) + 1);
			}
		}
	}

	/**
	* Removes a specific file and all functions of it from the import directory.
	* @param strFilename Name of the file which will be removed.
	**/
	inline
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
	inline
	int ImportDirectory::removeFunction(const std::string& strFilename, const std::string& strFuncname)
	{
		ImpDirFileIterator viPos = m_vNewiid.begin();

		int notFound = 1;

		while (viPos != m_vNewiid.end())
		{
			if (isEqualNc(viPos->name, strFilename))
			{
				unsigned int oldSize = static_cast<unsigned int>(viPos->thunk_data.size());
				viPos->thunk_data.erase(
					std::remove_if(
						viPos->thunk_data.begin(),
						viPos->thunk_data.end(),
						[&](const auto& i) { return i.equalFunctionName(strFuncname); }
					),
					viPos->thunk_data.end()
				);
				if (viPos->thunk_data.size() != oldSize) notFound = 0;
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
	inline
	int ImportDirectory::removeFunction(const std::string& strFilename, std::uint16_t wHint)
	{
		ImpDirFileIterator viPos = m_vNewiid.begin();
		int notFound = 1;

		while (viPos != m_vNewiid.end())
		{
			if (isEqualNc(viPos->name, strFilename))
			{
				unsigned int oldSize = static_cast<unsigned int>(viPos->thunk_data.size());
				viPos->thunk_data.erase(
					std::remove_if(
						viPos->thunk_data.begin(),
						viPos->thunk_data.end(),
						[&](const auto& i) { return i.equalHint(wHint); }
					),
					viPos->thunk_data.end()
				);
				if (viPos->thunk_data.size() != oldSize) notFound = 0;
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
	* @param pointerSize Size of the pointer (4 bytes or 8 bytes)
	**/
	inline
	int ImportDirectory::write(const std::string& strFilename, std::uint32_t uiOffset, std::uint32_t uiRva, std::uint32_t pointerSize)
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

		setPointerSize(pointerSize);
		rebuild(vBuffer, uiRva);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), vBuffer.size());
		ofFile.close();

		std::copy(m_vNewiid.begin(), m_vNewiid.end(), std::back_inserter(m_vOldiid));
		m_vNewiid.clear();

		return ERROR_NONE;
	}

	/**
	* Calculates size of import directory that would be written to a PE file.
	* @return Size of the import directory.
	**/
	inline
	std::uint32_t ImportDirectory::calculateSize(std::uint32_t pointerSize) const
	{
		std::uint32_t totalSize = 0;

		// Only the descriptors of m_vOldiid must be rebuilt, not the data they point to.
		for(const auto & element : m_vNewiid)
			totalSize += element.calculateSize(pointerSize);
		return totalSize + (m_vOldiid.size() + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();
	}

	/**
	* @param strFilename Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(const std::string& strFilename, bool newDir) const
	{
		return getImportList(newDir)[getFileIndex(strFilename, newDir)].impdesc.FirstThunk;
	}

	/**
	* @param strFilename Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(const std::string& strFilename, bool newDir) const
	{
		return getImportList(newDir)[getFileIndex(strFilename, newDir)].impdesc.OriginalFirstThunk;
	}

	/**
	* @param strFilename Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getForwarderChain(const std::string& strFilename, bool newDir) const
	{
		return getImportList(newDir)[getFileIndex(strFilename, newDir)].impdesc.ForwarderChain;
	}

	/**
	* @param strFilename Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getTimeDateStamp(const std::string& strFilename, bool newDir) const
	{
		return getImportList(newDir)[getFileIndex(strFilename, newDir)].impdesc.TimeDateStamp;
	}

	inline
	std::uint32_t ImportDirectory::getRvaOfName(const std::string& strFilename, bool newDir) const
	{
		return getImportList(newDir)[getFileIndex(strFilename, newDir)].impdesc.Name;
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].impdesc.FirstThunk;
	}

	inline
	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].impdesc.FirstThunk = value;
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].impdesc.OriginalFirstThunk;
	}

	inline
	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].impdesc.OriginalFirstThunk = value;
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/

	inline
	std::uint32_t ImportDirectory::getForwarderChain(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].impdesc.ForwarderChain;
	}

	inline
	void ImportDirectory::setForwarderChain(std::uint32_t dwFilenr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].impdesc.ForwarderChain = value;
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getTimeDateStamp(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].impdesc.TimeDateStamp;
	}

	inline
	void ImportDirectory::setTimeDateStamp(std::uint32_t dwFilenr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].impdesc.TimeDateStamp = value;
	}

	inline
	std::uint32_t ImportDirectory::getRvaOfName(std::uint32_t dwFilenr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].impdesc.Name;
	}

	inline
	void ImportDirectory::setRvaOfName(std::uint32_t dwFilenr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].impdesc.Name = value;
	}

	/**
	* @param dwFilenr ID of the imported file.
	* @param dwFuncnr ID of the imported function.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported function.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const
	{
		return getImportList(newDir)[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal;
	}

	inline
	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal = value;
	}

	/**
	* @param dwFilenr ID of the imported file.
	* @param dwFuncnr ID of the imported function.
	* @param newDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported function.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir) const
	{
		if (newDir == false)
		{
			if (dwFuncnr < m_vOldiid[dwFilenr].thunk_data.size())
			{
				return m_vOldiid[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return m_vNewiid[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal;
		}
	}

	inline
	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, bool newDir, std::uint32_t value)
	{
		getImportList(newDir)[dwFilenr].thunk_data[dwFuncnr].itd.Ordinal = value;
	}

	inline
	const std::vector<std::pair<unsigned int, unsigned int>>& ImportDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}

	inline const std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>& ImportDirectory::getImportList(bool newDir) const
	{
		return (newDir == false) ? m_vOldiid : m_vNewiid;
	}

	inline std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>& ImportDirectory::getImportList(bool newDir)
	{
		return (newDir == false) ? m_vOldiid : m_vNewiid;
	}


} // namespace PeLib

#endif
