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

#ifndef IMPORTDIRECTORY_H
#define IMPORTDIRECTORY_H

#include "pelib/PeLibAux.h"
#include "pelib/PeHeader.h"

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
	template<int bits>
	class ImportDirectory
	{
		typedef typename FieldSizes<bits>::VAR4_8 VAR4_8;
		typedef typename std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> >::iterator ImpDirFileIterator;
		typedef typename std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> >::const_iterator ConstImpDirFileIterator;

		private:
		  /// Stores information about already imported DLLs.
		  std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> > m_vOldiid;
		  /// Stores information about imported DLLs which will be added.
		  std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> > m_vNewiid;
		  /// Stores RVAs which are occupied by this import directory.
		  std::vector<std::pair<unsigned int, unsigned int>> m_occupiedAddresses;
		  /// Error detected by the import table parser
		  LoaderError m_ldrError;

		// I can't convince Borland C++ to compile the function outside of the class declaration.
		// That's why the function definition is here.
		/// Tests if a certain function is imported.
		template<typename T> bool hasFunction(std::string strFilename, T value, bool(PELIB_THUNK_DATA<bits>::* comp)(T) const) const
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
		  {}

		  /// Add a function to the import directory.
		  int addFunction(const std::string& strFilename, word wHint); // EXPORT _byHint
		  /// Add a function to the import directory.
		  int addFunction(const std::string& strFilename, const std::string& strFuncname); // EXPORT _byName

		  /// Get the ID of a file through it's name.
		  unsigned int getFileIndex(const std::string& strFilename, currdir cdDir) const; // EXPORT
		  /// Get the ID of a function through it's name.
		  unsigned int getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const; // EXPORT

		  /// Get the name of an imported file.
		  std::string getFileName(dword dwFilenr, currdir cdDir) const; // EXPORT

		  void setFileName(dword filenr, currdir dir, const std::string& name); // EXPORT

		  /// Retrieve the loader error
		  LoaderError loaderError() const;
		  void setLoaderError(LoaderError ldrError);

		  /// Get the hint of an imported function.
		  word getFunctionHint(dword dwFilenr, dword dwFuncnr, currdir cdDir) const; // EXPORT
		  void setFunctionHint(dword dwFilenr, dword dwFuncnr, currdir cdDir, word value); // EXPORT
		  /// Get the name of an imported function.
		  std::string getFunctionName(dword dwFilenr, dword dwFuncnr, currdir cdDir) const; // EXPORT
		  void setFunctionName(dword dwFilenr, dword dwFuncnr, currdir cdDir, const std::string& functionName); // EXPORT
		  /// Get the number of files which are imported.
		  dword getNumberOfFiles(currdir cdDir) const; // EXPORT
		  /// Get the number of fucntions which are imported by a specific file.
		  dword getNumberOfFunctions(dword dwFilenr, currdir cdDir) const; // EXPORT
		  /// Read a file's import directory.
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader); // EXPORT
		  /// Rebuild the import directory.
		  void rebuild(std::vector<byte>& vBuffer, dword dwRva, bool fixEntries = true); // EXPORT
		  /// Remove a file from the import directory.
		  int removeFile(const std::string& strFilename); // EXPORT
		  /// Remove a function from the import directory.
		  int removeFunction(const std::string& strFilename, const std::string& strFuncname); // EXPORT _byName
		  /// Remove a function from the import directory.
		  int removeFunction(const std::string& strFilename, word wHint); // EXPORT _byHint
		  /// Returns the size of the current import directory.
		  unsigned int size() const; // EXPORT
		  /// Writes the import directory to a file.
		  int write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva); // EXPORT

		  /// Returns the FirstThunk value of a function.
		  VAR4_8 getFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir) const; // EXPORT _byNumber
		  void setFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir, VAR4_8 value); // EXPORT _byNumber
		  /// Returns the OriginalFirstThunk value of a function.
		  VAR4_8 getOriginalFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir) const; // EXPORT _byNumber
		  void setOriginalFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir, VAR4_8 value); // EXPORT

//		  dword getFirstThunk(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);
//		  dword getOriginalFirstThunk(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);

		  /// Returns the FirstThunk value of a file.
		  dword getFirstThunk(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the OriginalFirstThunk value of a file.
		  dword getOriginalFirstThunk(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the ForwarderChain value of a file.
		  dword getForwarderChain(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  dword getRvaOfName(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName
		  /// Returns the TimeDateStamp value of a file.
		  dword getTimeDateStamp(const std::string& strFilename, currdir cdDir) const; // EXPORT _byName

		  /// Returns the FirstThunk value of a file.
		  dword getFirstThunk(dword dwFilenr, currdir cdDir) const; // EXPORT
		  void setFirstThunk(dword dwFilenr, currdir cdDir, dword value); // EXPORT _byNumber_function
		  /// Returns the OriginalFirstThunk value of a file.
		  dword getOriginalFirstThunk(dword dwFilenr, currdir cdDir) const; // EXPORT
		  void setOriginalFirstThunk(dword dwFilenr, currdir cdDir, dword value); // EXPORT _byNumber_function
		  /// Returns the ForwarderChain value of a file.
		  dword getForwarderChain(dword dwFilenr, currdir cdDir) const; // EXPORT _byNumber
		  void setForwarderChain(dword dwFilenr, currdir cdDir, dword value); // EXPORT _byNumber_function
		  dword getRvaOfName(dword dwFilenr, currdir cdDir) const; // EXPORT _byNumber
		  void setRvaOfName(dword dwFilenr, currdir cdDir, dword value); // EXPORT
		  /// Returns the TimeDateStamp value of a file.
		  dword getTimeDateStamp(dword dwFilenr, currdir cdDir) const; // EXPORT
		  void setTimeDateStamp(dword dwFilenr, currdir cdDir, dword value); // EXPORT _byNumber

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;

//		  word getFunctionHint(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const throw (PeLibException);
	};

	/**
	 * Returns whether OriginalFirstThunk of specified import descriptor is valid with a given PE header.
	 * OriginalFirstThunk is valid if it has value higher than file alignment and its RVA can be translated to some offset in the file.
	 *
	 * @param impDesc Import descriptor.
	 * @param peHeader PE header.
	 *
	 * @return True if valid, otherwise false.
	 */
	template<int bits>
	bool hasValidOriginalFirstThunk(const PELIB_IMAGE_IMPORT_DESCRIPTOR& impDesc, const PeHeaderT<bits>& peHeader)
	{
		// This check for file alignment is little bit hacky, but we have no other way to know whether OriginalFirstThunk points to valid data.
		// If it points to the value lower than file alignment, it points PE header and that should not be correct.
		return (impDesc.OriginalFirstThunk >= peHeader.getFileAlignment()) && (peHeader.rvaToOffset(impDesc.OriginalFirstThunk) != -1);
	}

	/**
	* Add another import (by Ordinal) to the current file. Note that the import table is not automatically updated.
	* The new imported functions will be added when you recalculate the import table as it's necessary
	* to specify the address the import table will have in the file.
	* @param strFilename The name of a DLL.
	* @param wHint The ordinal of the function in the DLL.
	**/
	template<int bits>
	int ImportDirectory<bits>::addFunction(const std::string& strFilename, word wHint)
	{
		if (hasFunction(strFilename, wHint, &PELIB_THUNK_DATA<bits>::equalHint))
		{
			return ERROR_DUPLICATE_ENTRY;
		}

	 	// Find the imported file.
		ImpDirFileIterator FileIter = std::find_if(
				m_vNewiid.begin(),
				m_vNewiid.end(),
				[&](const auto& i) { return i == strFilename; }
		);

		PELIB_IMAGE_IMPORT_DIRECTORY<bits> iid;
		PELIB_THUNK_DATA<bits> td;
		td.hint = wHint;
		td.itd.Ordinal = wHint | PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG;
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
	template<int bits>
	int ImportDirectory<bits>::addFunction(const std::string& strFilename, const std::string& strFuncname)
	{
		if (hasFunction(strFilename, strFuncname, &PELIB_THUNK_DATA<bits>::equalFunctionName))
		{
			return ERROR_DUPLICATE_ENTRY;
		}

	 	// Find the imported file.
		ImpDirFileIterator FileIter = std::find_if(
				m_vNewiid.begin(),
				m_vNewiid.end(),
				[&](const auto& i) { return i == strFilename; }
		);

		PELIB_IMAGE_IMPORT_DIRECTORY<bits> iid;
		PELIB_THUNK_DATA<bits> td;
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
	template<int bits>
	unsigned int ImportDirectory<bits>::getFileIndex(const std::string& strFilename, currdir cdDir) const
	{
		const std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> >* currDir;

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
	template<int bits>
	unsigned int ImportDirectory<bits>::getFunctionIndex(const std::string& strFilename, const std::string& strFuncname, currdir cdDir) const
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
	template<int bits>
	std::string ImportDirectory<bits>::getFileName(dword dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return m_vOldiid[dwFilenr].name;
		else return m_vNewiid[dwFilenr].name;
	}

	template<int bits>
	void ImportDirectory<bits>::setFileName(dword filenr, currdir dir, const std::string& name)
	{
		if (dir == OLDDIR) m_vOldiid[filenr].name = name;
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
	template<int bits>
	std::string ImportDirectory<bits>::getFunctionName(dword dwFilenr, dword dwFuncnr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setFunctionName(dword dwFilenr, dword dwFuncnr, currdir cdDir, const std::string& functionName)
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
	template<int bits>
	LoaderError ImportDirectory<bits>::loaderError() const
	{
		return m_ldrError;
	}

	template<int bits>
	void ImportDirectory<bits>::setLoaderError(LoaderError ldrError)
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
	template<int bits>
	word ImportDirectory<bits>::getFunctionHint(dword dwFilenr, dword dwFuncnr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setFunctionHint(dword dwFilenr, dword dwFuncnr, currdir cdDir, word value)
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
	template<int bits>
	dword ImportDirectory<bits>::getNumberOfFiles(currdir cdDir) const
	{
		if (cdDir == OLDDIR) return static_cast<dword>(m_vOldiid.size());
		else return static_cast<dword>(m_vNewiid.size());
	}

	/**
	* Get the number of functions which are currently being imported from a specific file.
	* @param dwFilenr Identifies which file should be checked.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return Number of functions which are currently being imported from a specific file.
	**/
	template<int bits>
	dword ImportDirectory<bits>::getNumberOfFunctions(dword dwFilenr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return static_cast<unsigned int>(m_vOldiid[dwFilenr].firstthunk.size());
		else return static_cast<unsigned int>(m_vNewiid[dwFilenr].firstthunk.size());
	}

	/**
	* Read an import directory from a file.
	* \todo Check if streams failed.
	* @param inStream Input stream.
	* @param peHeader A valid PE header.
	**/
	template<int bits>
	int ImportDirectory<bits>::read(
			std::istream& inStream,
			const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		VAR4_8 OrdinalMask = ((VAR4_8)1 << (bits - 1));
		VAR4_8 SizeOfImage = peHeader.getSizeOfImage();
		dword uiIndex;

		m_ldrError = LDR_ERROR_NONE;

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		if(peHeader.getIddImportRva() > peHeader.getSizeOfImage())
		{
			setLoaderError(LDR_ERROR_IMPDIR_OUT_OF_FILE);
			return ERROR_INVALID_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		unsigned int uiRva = peHeader.getIddImportRva();
		unsigned int uiOffset = (unsigned int)peHeader.rvaToOffset(uiRva);

		if ((uiOffset + PELIB_IMAGE_IMPORT_DESCRIPTOR::size()) > ulFileSize)
		{
			setLoaderError(LDR_ERROR_IMPDIR_OUT_OF_FILE);
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios_base::beg);

		PELIB_IMAGE_IMPORT_DIRECTORY<bits> iidCurr;
		std::vector<PELIB_IMAGE_IMPORT_DIRECTORY<bits> > vOldIidCurr;
		unsigned int uiDescCounter = 0;
		unsigned int uiDescOffset = uiOffset;

		// For tracking unique imported DLLs
		std::unordered_map<std::string, int> uniqueDllList;

		// Read and store all descriptors
		for (;;)
		{
			std::vector<unsigned char> vImportDescriptor(PELIB_IMAGE_IMPORT_DESCRIPTOR::size());

			// If the required range is within the file, then we read the data.
			// If not, it's RVA may still be valid due mapping -> keep zeros.
			// Example sample: de0dea00414015bacbcbfc1fa53af9f6731522687d82f5de2e9402410488d190
			// (single entry in the import directory at file offset 0x3EC4 followed by end-of-file)
			if ((uiDescOffset + PELIB_IMAGE_IMPORT_DESCRIPTOR::size()) <= ulFileSize)
			{
				// The offset is within the file range -> read it from the file
				inStream_w.read(reinterpret_cast<char*>(vImportDescriptor.data()), PELIB_IMAGE_IMPORT_DESCRIPTOR::size());
			}
			else
			{
				// The offset is out of physical file -> is the RVA still valid?
				if (!peHeader.isValidRva(uiRva + PELIB_IMAGE_IMPORT_DESCRIPTOR::size()))
				{
					setLoaderError(LDR_ERROR_IMPDIR_CUT);
					break;
				}
			}

			InputBuffer inpBuffer(vImportDescriptor);

			inpBuffer >> iidCurr.impdesc.OriginalFirstThunk;
			inpBuffer >> iidCurr.impdesc.TimeDateStamp;
			inpBuffer >> iidCurr.impdesc.ForwarderChain;
			inpBuffer >> iidCurr.impdesc.Name;
			inpBuffer >> iidCurr.impdesc.FirstThunk;

			uiDescOffset += PELIB_IMAGE_IMPORT_DESCRIPTOR::size();
			uiRva += PELIB_IMAGE_IMPORT_DESCRIPTOR::size();
			uiDescCounter++;

			// If Name or FirstThunk are 0, this descriptor is considered as null-terminator.
			if (iidCurr.impdesc.Name == 0 || iidCurr.impdesc.FirstThunk == 0)
				break;

			// We ignore import names that go beyond the file
			if (iidCurr.impdesc.Name > SizeOfImage || !peHeader.isValidRva(iidCurr.impdesc.Name))
			{
				setLoaderError(LDR_ERROR_IMPDIR_NAME_RVA_INVALID);
				break;
			}

			if (iidCurr.impdesc.FirstThunk > SizeOfImage)
			{
				setLoaderError(LDR_ERROR_IMPDIR_THUNK_RVA_INVALID);
				break;
			}

			// Retrieve the import name string from the image
			getStringFromFileOffset(inStream_w, iidCurr.name, peHeader.rvaToOffset(iidCurr.impdesc.Name), IMPORT_LIBRARY_MAX_LENGTH);

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
		m_occupiedAddresses.emplace_back(peHeader.getIddImportRva(), peHeader.getIddImportRva() + (uiDescOffset - uiOffset - 1));

		// OriginalFirstThunk - ILT
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			if (!hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, peHeader))
				continue;

			PELIB_THUNK_DATA<bits> tdCurr;
			dword uiVaoft = vOldIidCurr[i].impdesc.OriginalFirstThunk;

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
		for (unsigned int i=0;i<vOldIidCurr.size();i++)
		{
			bool hasValidIlt = hasValidOriginalFirstThunk(vOldIidCurr[i].impdesc, peHeader);

			dword uiVaoft = vOldIidCurr[i].impdesc.FirstThunk;
			if (!peHeader.isValidRva(uiVaoft))
			{
				return ERROR_INVALID_FILE;
			}

			PELIB_THUNK_DATA<bits> tdCurr;

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
					if (vOldIidCurr[i].originalfirstthunk[j].itd.Ordinal & PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG)
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
					if (vOldIidCurr[i].firstthunk[j].itd.Ordinal & PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG)
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
		return ERROR_NONE;
	}

	/**
	* Rebuilds the import directory.
	* @param vBuffer Buffer the rebuilt import directory will be written to.
	* @param dwRva The RVA of the ImportDirectory in the file.
	* @param fixEntries Boolean flag.
	* \todo uiSizeoffuncnames is not used.
	**/
	template<int bits>
	void ImportDirectory<bits>::rebuild(std::vector<byte>& vBuffer, dword dwRva, bool fixEntries)
	{
		unsigned int uiImprva = dwRva;
		unsigned int uiSizeofdescriptors = (static_cast<unsigned int>(m_vNewiid.size() + m_vOldiid.size()) + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();

		unsigned int uiSizeofdllnames = 0, uiSizeoffuncnames = 0;
		unsigned int uiSizeofoft = 0;

		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			uiSizeofdllnames += static_cast<unsigned int>(m_vNewiid[i].name.size()) + 1;
			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk.size())+1) * PELIB_IMAGE_THUNK_DATA<bits>::size();

			for(unsigned int j=0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				// +3 for hint (word) and 00-byte
				uiSizeoffuncnames += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 3);
			}
		}

//		for (unsigned int i=0;i<m_vNewiid.size();i++)
//		{
//			uiSizeofoft += (static_cast<unsigned int>(m_vNewiid[i].originalfirstthunk.size())+1) * PELIB_IMAGE_THUNK_DATA<bits>::size();
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
			dword dwPoft = uiSizeofdescriptors + uiImprva;

			for (unsigned int j=1;j<=i;j++)
			{
				dwPoft += (static_cast<unsigned int>(m_vNewiid[j-1].originalfirstthunk.size()) + 1) * PELIB_IMAGE_THUNK_DATA<bits>::size();
			}

			obBuffer << (fixEntries ? dwPoft : m_vNewiid[i].impdesc.OriginalFirstThunk);
			obBuffer << m_vNewiid[i].impdesc.TimeDateStamp;
			obBuffer << m_vNewiid[i].impdesc.ForwarderChain;
			dword dwPdll = uiSizeofdescriptors + uiSizeofoft + uiImprva + dllsize;
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

		obBuffer << static_cast<dword>(0);
		obBuffer << static_cast<dword>(0);
		obBuffer << static_cast<dword>(0);
		obBuffer << static_cast<dword>(0);
		obBuffer << static_cast<dword>(0);

		VAR4_8 uiPfunc = uiSizeofdescriptors + uiSizeofoft + uiSizeofdllnames + uiImprva;

		// Rebuild original first thunk
		for (unsigned int i=0;i<m_vNewiid.size();i++)
		{
			for (unsigned int j=0;j<m_vNewiid[i].originalfirstthunk.size();j++)
			{
				if (m_vNewiid[i].originalfirstthunk[j].itd.Ordinal & PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG
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
				uiPfunc += static_cast<VAR4_8>(m_vNewiid[i].originalfirstthunk[j].fname.size()) + 3;
			}
			obBuffer << static_cast<VAR4_8>(0);
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
	template<int bits>
	int ImportDirectory<bits>::removeFile(const std::string& strFilename)
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
	template<int bits>
	int ImportDirectory<bits>::removeFunction(const std::string& strFilename, const std::string& strFuncname)
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
	template<int bits>
	int ImportDirectory<bits>::removeFunction(const std::string& strFilename, word wHint)
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
	template<int bits>
	int ImportDirectory<bits>::write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva)
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

		std::vector<byte> vBuffer;

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
	template<int bits>
	unsigned int ImportDirectory<bits>::size() const
	{
		// Only the descriptors of m_vOldiid must be rebuilt, not the data they point to.
		return std::accumulate(m_vNewiid.begin(), m_vNewiid.end(), 0, accumulate<PELIB_IMAGE_IMPORT_DIRECTORY<bits> >)
		+ (m_vOldiid.size() + 1) * PELIB_IMAGE_IMPORT_DESCRIPTOR::size();
	}

	/**
	* @param strFilename Name of the imported file.
	* @param cdDir Flag to decide if the OLDDIR or new import directory is used.
	* @return FirstThunk value of an imported file.
	**/
	template<int bits>
	dword ImportDirectory<bits>::getFirstThunk(const std::string& strFilename, currdir cdDir) const
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
	template<int bits>
	dword ImportDirectory<bits>::getOriginalFirstThunk(const std::string& strFilename, currdir cdDir) const
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
	template<int bits>
	dword ImportDirectory<bits>::getForwarderChain(const std::string& strFilename, currdir cdDir) const
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
	template<int bits>
	dword ImportDirectory<bits>::getTimeDateStamp(const std::string& strFilename, currdir cdDir) const
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

	template<int bits>
	dword ImportDirectory<bits>::getRvaOfName(const std::string& strFilename, currdir cdDir) const
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
	template<int bits>
	dword ImportDirectory<bits>::getFirstThunk(dword dwFilenr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setFirstThunk(dword dwFilenr, currdir cdDir, dword value)
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
	template<int bits>
	dword ImportDirectory<bits>::getOriginalFirstThunk(dword dwFilenr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setOriginalFirstThunk(dword dwFilenr, currdir cdDir, dword value)
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
	template<int bits>
	dword ImportDirectory<bits>::getForwarderChain(dword dwFilenr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setForwarderChain(dword dwFilenr, currdir cdDir, dword value)
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
	template<int bits>
	dword ImportDirectory<bits>::getTimeDateStamp(dword dwFilenr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setTimeDateStamp(dword dwFilenr, currdir cdDir, dword value)
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

	template<int bits>
	dword ImportDirectory<bits>::getRvaOfName(dword dwFilenr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setRvaOfName(dword dwFilenr, currdir cdDir, dword value)
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
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 ImportDirectory<bits>::getFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir) const
	{
		if (cdDir == OLDDIR) return m_vOldiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
		else return m_vNewiid[dwFilenr].firstthunk[dwFuncnr].itd.Ordinal;
	}

	template<int bits>
	void ImportDirectory<bits>::setFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir, VAR4_8 value)
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
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 ImportDirectory<bits>::getOriginalFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir) const
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

	template<int bits>
	void ImportDirectory<bits>::setOriginalFirstThunk(dword dwFilenr, dword dwFuncnr, currdir cdDir, VAR4_8 value)
	{
		if (cdDir == OLDDIR) m_vOldiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
		else m_vNewiid[dwFilenr].originalfirstthunk[dwFuncnr].itd.Ordinal = value;
	}

	template<int bits>
	const std::vector<std::pair<unsigned int, unsigned int>>& ImportDirectory<bits>::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}

	typedef ImportDirectory<32> ImportDirectory32;
	typedef ImportDirectory<64> ImportDirectory64;
}

#endif
