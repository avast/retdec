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

namespace PeLib
{
	/// Parameter for functions that can operate on the OLDDIR or new import directory.
	enum currdir {OLDDIR = 1, NEWDIR};

	class PeLibException;

	/// Class that handles import directories.
	/**
	* This class can read import directories from existing PE files or start completely from scratch.
	* Modifying import directories and writing them to files is also possible.
	* It's worthy to note that many functions require an extra parameter of type currdir
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
								FileIter->originalfirstthunk.begin(),
								FileIter->originalfirstthunk.end(),
								std::bind(comp, std::placeholders::_1, value)
						);
						if (Iter != FileIter->originalfirstthunk.end())
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
		  unsigned int getFileIndex(const std::string& strFilename, currdir cdDir) const; // EXPORT
		  /// Get the ID of a function through it's name.
		  unsigned int getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const; // EXPORT

		  /// Get the name of an imported file.
		  std::string getFileName(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT

		  void setFileName(std::uint32_t filenr, currdir cdDir, const std::string& name); // EXPORT

		  /// Retrieve the loader error
		  LoaderError loaderError() const;
		  void setLoaderError(LoaderError ldrError);

		  /// Get the hint of an imported function.
		  std::uint16_t getFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const; // EXPORT
		  void setFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint16_t value); // EXPORT
		  /// Get the name of an imported function.
		  std::string getFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const; // EXPORT
		  void setFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, const std::string& functionName); // EXPORT
		  /// Get the number of files which are imported.
		  std::uint32_t getNumberOfFiles(currdir cdDir) const; // EXPORT
		  /// Get the number of fucntions which are imported by a specific file.
		  std::uint32_t getNumberOfFunctions(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT
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
		  std::uint32_t getFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const; // EXPORT _byNumber
		  void setFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint32_t value); // EXPORT _byNumber
		  /// Returns the OriginalFirstThunk value of a function.
		  std::uint32_t getOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const; // EXPORT _byNumber
		  void setOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint32_t value); // EXPORT

//		  std::uint64_t getFirstThunk(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);
//		  std::uint64_t getOriginalFirstThunk(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);

		  /// Returns the FirstThunk value of a file.
		  std::uint32_t getFirstThunk(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the OriginalFirstThunk value of a file.
		  std::uint32_t getOriginalFirstThunk(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the ForwarderChain value of a file.
		  std::uint32_t getForwarderChain(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  std::uint32_t getRvaOfName(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the TimeDateStamp value of a file.
		  std::uint32_t getTimeDateStamp(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName

		  /// Returns the FirstThunk value of a file.
		  std::uint32_t getFirstThunk(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT
		  void setFirstThunk(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value); // EXPORT _byNumber_function
		  /// Returns the OriginalFirstThunk value of a file.
		  std::uint32_t getOriginalFirstThunk(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT
		  void setOriginalFirstThunk(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value); // EXPORT _byNumber_function
		  /// Returns the ForwarderChain value of a file.
		  std::uint32_t getForwarderChain(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT _byNumber
		  void setForwarderChain(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value); // EXPORT _byNumber_function
		  std::uint32_t getRvaOfName(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT _byNumber
		  void setRvaOfName(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value); // EXPORT
		  /// Returns the TimeDateStamp value of a file.
		  std::uint32_t getTimeDateStamp(std::uint32_t dwFilenr, currdir cdDir) const; // EXPORT
		  void setTimeDateStamp(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value); // EXPORT _byNumber

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;

//		  std::uint16_t getFunctionHint(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return The ID of an imported file.
	**/
	inline
	unsigned int ImportDirectory::getFileIndex(const std::string& strFilename, currdir cdDir) const
	{
		const std::vector<PELIB_IMAGE_IMPORT_DIRECTORY>* currDir;

		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ID of the imported function.
	**/
	inline
	unsigned int ImportDirectory::getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const
	{
		unsigned int uiFile = getFileIndex(strFilename, cdDir);

		for (unsigned int i=0;i<getNumberOfFunctions(uiFile, cdDir);i++)
		{
			if (getFunctionName(uiFile, i, cdDir) == strFuncname) return i;
		}

		return -1;
	}

	/**
	* Get the name of an imported file.
	* @param dwFilenr Identifies which file should be checked.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported file.
	**/
	inline
	std::string ImportDirectory::getFileName(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return m_vOldiid[dwFilenr].name;
		else return m_vNewiid[dwFilenr].name;
	}

	inline
	void ImportDirectory::setFileName(std::uint32_t filenr, currdir cdDir, const std::string& name)
	{
		if (cdDir == OLDDIR) m_vOldiid[filenr].name = name;
		else m_vNewiid[filenr].name = name;
	}

	/**
	* Get the name of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Name of an imported function.
	* \todo Marked line is unsafe (function should be rewritten).
	**/
	inline
	std::string ImportDirectory::getFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
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

	inline
	void ImportDirectory::setFunctionName(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, const std::string& functionName)
	{
		if (cdDir == OLDDIR)
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
	* Get the hint of an imported function.
	* @param dwFilenr Identifies which file should be checked.
	* @param dwFuncnr Identifies which function should be checked.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Hint of an imported function.
	**/
	inline
	std::uint16_t ImportDirectory::getFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
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

	inline
	void ImportDirectory::setFunctionHint(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint16_t value)
	{
		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of files which are currently being imported.
	**/
	inline
	std::uint32_t ImportDirectory::getNumberOfFiles(currdir cdDir) const
	{
		std::size_t numFiles = (cdDir == OLDDIR) ? m_vOldiid.size() : m_vNewiid.size();

		return static_cast<std::uint32_t>(numFiles);
	}

	/**
	* Get the number of functions which are currently being imported from a specific file.
	* @param dwFilenr Identifies which file should be checked.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of functions which are currently being imported from a specific file.
	**/
	inline
	std::uint32_t ImportDirectory::getNumberOfFunctions(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return static_cast<unsigned int>(m_vOldiid[dwFilenr].firstthunk.size());
		else return static_cast<unsigned int>(m_vNewiid[dwFilenr].firstthunk.size());
	}

	inline bool isInvalidOrdinal(std::uint64_t ordinal, std::uint64_t ordinalMask, std::uint64_t sizeOfImage)
	{
		// Check for invalid name
		if((ordinal & ordinalMask) == 0)
		{
			// Any name RVA that goes out of image is considered invalid
			if(ordinal >= sizeOfImage)
			{
				return true;
			}
		}
		else
		{
			// Mask out the ordinal bit. Then, any ordinal must not be larger than 0xFFFF
			ordinal = ordinal & ~ordinalMask;
			return (ordinal >> 0x10) != 0;
		}

		return false;
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
		std::uint32_t uiIndex;
		std::uint32_t rvaBegin = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT);
		std::uint32_t rva = rvaBegin;

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
			imageLoader.readString(iidCurr.name, iidCurr.impdesc.Name, IMPORT_LIBRARY_MAX_LENGTH);

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

		// OriginalFirstThunk - ILT
		for(std::size_t i = 0; i < vOldIidCurr.size(); i++)
		{
			// OriginalFirstThunk is only valid when pointing within the image, excluding headers
			if(!hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, imageLoader))
				continue;
			std::uint32_t thunkRva = vOldIidCurr[i].impdesc.OriginalFirstThunk;

			PELIB_THUNK_DATA tdCurr;

			for(uiIndex = 0; ; uiIndex++)
			{
				// Read single value (32-bit or 64-bit) from the thunk chain
				if(!imageLoader.readPointer(thunkRva, tdCurr.itd.Ordinal))
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
				// Import by ordinal must be lower-word only; any ordinal that is greater than 0xFFFF is invalid.
				// Sample: 7CE5BB5CA99B3570514AF03782545D41213A77A0F93D4AAC8269823A8D3A58EF
				if(isInvalidOrdinal(tdCurr.itd.Ordinal, OrdinalMask, SizeOfImage))
				{
					setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
					break;
				}

				// Insert ordinal to the list
				vOldIidCurr[i].originalfirstthunk.push_back(tdCurr);
				thunkRva += m_thunkSize;
			}

			// Space occupied by OriginalFirstThunks
			// -1 because we need open interval
			if (vOldIidCurr[i].impdesc.OriginalFirstThunk < thunkRva)
				m_occupiedAddresses.emplace_back(vOldIidCurr[i].impdesc.OriginalFirstThunk, thunkRva - 1);
		}

		// FirstThunk - IAT
		std::set<std::uint32_t> seenOffsets;
		for (std::size_t i = 0; i < vOldIidCurr.size(); i++)
		{
			std::uint32_t thunkRva = vOldIidCurr[i].impdesc.FirstThunk;
			bool hasValidIlt = hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, imageLoader);

			if (thunkRva >= imageLoader.getSizeOfImage())
			{
				setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
				return ERROR_INVALID_FILE;
			}
			if (seenOffsets.count(thunkRva))
			{
				continue;
			}
			seenOffsets.insert(thunkRva);
			PELIB_THUNK_DATA tdCurr;

			for(uiIndex = 0; ; uiIndex++)
			{
				if ((thunkRva + m_thunkSize) > SizeOfImage)
				{
					setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
					return ERROR_INVALID_FILE;
				}

				// Read the import thunk. Make sure it's initialized in case the file read fails
				tdCurr.itd.Ordinal = 0;
				imageLoader.readPointer(thunkRva, tdCurr.itd.Ordinal);
				thunkRva += m_thunkSize;

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
				//if(isInvalidOrdinal(tdCurr.itd.Ordinal, OrdinalMask, SizeOfImage))
				//	break;

				vOldIidCurr[i].firstthunk.push_back(tdCurr);

				// If this import descriptor has valid ILT, then size of IAT is determined from the size of ILT
				if (hasValidIlt && vOldIidCurr[i].originalfirstthunk.size() == vOldIidCurr[i].firstthunk.size())
				{
					// We need to move this offset in this case because otherwise we would calculate the occupied addresses wrongly
					thunkRva += m_thunkSize;
					break;
				}
			}

			// Space occupied by FirstThunks
			// -1 because we need open interval
			if (vOldIidCurr[i].impdesc.FirstThunk < thunkRva)
				m_occupiedAddresses.emplace_back(vOldIidCurr[i].impdesc.FirstThunk, thunkRva - 1);
		}

		// Names
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			std::vector<PELIB_THUNK_DATA> & thunkVector = hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, imageLoader) ?
														  vOldIidCurr[i].originalfirstthunk :
														  vOldIidCurr[i].firstthunk;
			for (auto & thunkData : thunkVector)
			{
				if (thunkData.itd.Ordinal & OrdinalMask)
				{
					thunkData.hint = 0;
					continue;
				}

				if(imageLoader.readImage(&thunkData.hint, thunkData.itd.Ordinal, sizeof(std::uint16_t)) != sizeof(std::uint16_t))
				{
					setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
					return ERROR_INVALID_FILE;
				}

				imageLoader.readString(thunkData.fname, thunkData.itd.Ordinal + sizeof(std::uint16_t), IMPORT_SYMBOL_MAX_LENGTH);

				// Space occupied by names
				// +1 for null terminator
				// If the end address is even, we need to align it by 2, so next name always starts at even address
				m_occupiedAddresses.emplace_back(
					static_cast<unsigned int>(thunkData.itd.Ordinal),
					static_cast<unsigned int>(thunkData.itd.Ordinal + sizeof(thunkData.hint) + thunkData.fname.length() + 1)
					);
				if (!(m_occupiedAddresses.back().second & 1))
					m_occupiedAddresses.back().second += 1;
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
		for (std::size_t i = 0;i<m_vNewiid.size();i++)
		{
			for (std::size_t j = 0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				if((m_vNewiid[i].originalfirstthunk[j].itd.Ordinal & m_ordinalMask) || fixEntries == false)
				{
					writePointer(obBuffer, m_vNewiid[i].originalfirstthunk[j].itd.Ordinal);
					//obBuffer << m_vNewiid[i].originalfirstthunk[j].itd.Ordinal;
				}
				else
				{
					writePointer(obBuffer, uiPfunc);
					//obBuffer << uiPfunc;
					// store the offset in Ordinal, they cannot overlay thanks to PELIB_IMAGE_ORDINAL_FLAG
					m_vNewiid[i].originalfirstthunk[j].itd.Ordinal = uiPfunc;
				}
				uiPfunc += static_cast<std::uint64_t>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 3;
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
	inline
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(const std::string& strFilename, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[getFileIndex(strFilename, cdDir)].impdesc.FirstThunk;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, cdDir)].impdesc.FirstThunk;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(const std::string& strFilename, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[getFileIndex(strFilename, cdDir)].impdesc.OriginalFirstThunk;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, cdDir)].impdesc.OriginalFirstThunk;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getForwarderChain(const std::string& strFilename, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[getFileIndex(strFilename, cdDir)].impdesc.ForwarderChain;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, cdDir)].impdesc.ForwarderChain;
		}
	}

	/**
	* @param strFilename Name of the imported file.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getTimeDateStamp(const std::string& strFilename, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[getFileIndex(strFilename, cdDir)].impdesc.TimeDateStamp;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, cdDir)].impdesc.TimeDateStamp;
		}
	}

	inline
	std::uint32_t ImportDirectory::getRvaOfName(const std::string& strFilename, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[getFileIndex(strFilename, cdDir)].impdesc.Name;
		}
		else
		{
			return m_vNewiid[getFileIndex(strFilename, cdDir)].impdesc.Name;
		}
	}

	/**
	* @param dwFilenr Name of the imported file.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[dwFilenr].impdesc.FirstThunk;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.FirstThunk;
		}
	}

	inline
	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[dwFilenr].impdesc.OriginalFirstThunk;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.OriginalFirstThunk;
		}
	}

	inline
	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return ForwarderChain value of an imported file.
	**/

	inline
	std::uint32_t ImportDirectory::getForwarderChain(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[dwFilenr].impdesc.ForwarderChain;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.ForwarderChain;
		}
	}

	inline
	void ImportDirectory::setForwarderChain(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return TimeDateStamp value of an imported file.
	**/
	inline
	std::uint32_t ImportDirectory::getTimeDateStamp(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[dwFilenr].impdesc.TimeDateStamp;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.TimeDateStamp;
		}
	}

	inline
	void ImportDirectory::setTimeDateStamp(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR)
		{
			m_vOldiid[dwFilenr].impdesc.TimeDateStamp = value;
		}
		else
		{
			m_vNewiid[dwFilenr].impdesc.TimeDateStamp = value;
		}
	}

	inline
	std::uint32_t ImportDirectory::getRvaOfName(std::uint32_t dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
		{
			return m_vOldiid[dwFilenr].impdesc.Name;
		}
		else
		{
			return m_vNewiid[dwFilenr].impdesc.Name;
		}
	}

	inline
	void ImportDirectory::setRvaOfName(std::uint32_t dwFilenr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR)
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
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported function.
	**/
	inline
	std::uint32_t ImportDirectory::getFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return m_vOldiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
		else return m_vNewiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
	}

	inline
	void ImportDirectory::setFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR) m_vOldiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal = value;
		else m_vNewiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal = value;
	}

	/**
	* @param dwFilenr ID of the imported file.
	* @param dwFuncnr ID of the imported function.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return OriginalFirstThunk value of an imported function.
	**/
	inline
	std::uint32_t ImportDirectory::getOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir) const
	{
		if (cdDir == OLDDIR)
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

	inline
	void ImportDirectory::setOriginalFirstThunk(std::uint32_t dwFilenr, std::uint32_t dwFuncnr, currdir cdDir, std::uint32_t value)
	{
		if (cdDir == OLDDIR) m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
		else m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
	}

	inline
	const std::vector<std::pair<unsigned int, unsigned int>>& ImportDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}

} // namespace PeLib

#endif
