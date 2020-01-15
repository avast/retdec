/*
* ExportDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef EXPORTDIRECTORY_H
#define EXPORTDIRECTORY_H

#include "pelib/PeHeader.h"

namespace PeLib
{
	/// Class that handles the export directory.
	/**
	* This class handles the export directory.
	* \todo getNameString
	**/
	class ExportDirectory
	{
		protected:
		  /// Used to store all necessary information about a file's exported functions.
		  PELIB_IMAGE_EXP_DIRECTORY m_ied;
		  /// Stores RVAs which are occupied by this export directory.
		  std::vector<std::pair<unsigned int, unsigned int>> m_occupiedAddresses;

		public:
		  virtual ~ExportDirectory() = default;

		  /// Add another function to be exported.
		  void addFunction(const std::string& strFuncname, dword dwFuncAddr); // EXPORT
		  unsigned int calcNumberOfFunctions() const; // EXPORT
		  void clear(); // EXPORT
		  /// Identifies a function through it's name.
		  int getFunctionIndex(const std::string& strFunctionName) const; // EXPORT
		  /// Rebuild the current export directory.
		  void rebuild(std::vector<byte>& vBuffer, dword dwRva) const; // EXPORT
		  void removeFunction(unsigned int index); // EXPORT
		  /// Returns the size of the current export directory.
		  unsigned int size() const; // EXPORT
		  /// Writes the current export directory to a file.
		  int write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva) const; // EXPORT

		  /// Changes the name of the file (according to the export directory).
		  void setNameString(const std::string& strFilename); // EXPORT
		  std::string getNameString() const; // EXPORT

		  /// Get the name of an exported function.
		  std::string getFunctionName(std::size_t index) const; // EXPORT
		  /// Get the ordinal of an exported function.
		  word getFunctionOrdinal(std::size_t index) const; // EXPORT
		  /// Get the address of the name of an exported function.
		  dword getAddressOfName(std::size_t index) const; // EXPORT
		  /// Get the address of an exported function.
		  dword getAddressOfFunction(std::size_t index) const; // EXPORT

		  /// Change the name of an exported function.
		  void setFunctionName(std::size_t index, const std::string& strName); // EXPORT
		  /// Change the ordinal of an exported function.
		  void setFunctionOrdinal(std::size_t index, word wValue); // EXPORT
		  /// Change the address of the name of an exported function.
		  void setAddressOfName(std::size_t index, dword dwValue); // EXPORT
		  /// Change the address of an exported function.
		  void setAddressOfFunction(std::size_t index, dword dwValue); // EXPORT

		  /*
		  word getFunctionOrdinal(std::string strFuncname) const;
		  dword getAddressOfName(std::string strFuncname) const;
		  dword getAddressOfFunction(std::string strFuncname) const;

		  void setFunctionOrdinal(std::string strFuncname, word wValue);
		  void setAddressOfName(std::string strFuncname, dword dwValue);
		  void setAddressOfFunction(std::string strFuncname, dword dwValue);
		  */

		  /// Return the Base value of the export directory.
		  dword getBase() const; // EXPORT
		  /// Return the Characteristics value of the export directory.
		  dword getCharacteristics() const; // EXPORT
		  /// Return the TimeDateStamp value of the export directory.
		  dword getTimeDateStamp() const; // EXPORT
		  /// Return the MajorVersion value of the export directory.
		  word getMajorVersion() const; // EXPORT
		  /// Return the MinorVersion value of the export directory.
		  word getMinorVersion() const; // EXPORT
		  /// Return the Name value of the export directory.
		  dword getName() const; // EXPORT
		  /// Return the NumberOfFunctions value of the export directory.
		  dword getNumberOfFunctions() const; // EXPORT
		  /// Return the NumberOfNames value of the export directory.
		  dword getNumberOfNames() const; // EXPORT
		  /// Return the AddressOfFunctions value of the export directory.
		  dword getAddressOfFunctions() const; // EXPORT
		  /// Return the AddressOfNames value of the export directory.
		  dword getAddressOfNames() const; // EXPORT
		  /// Returns the AddressOfNameOrdinals value.
		  dword getAddressOfNameOrdinals() const; // EXPORT

/*		  /// Returns the number of NameOrdinals.
		  dword getNumberOfNameOrdinals() const; // EXPORT
		  /// Returns the number of AddressOfFunctionNames values.
		  dword getNumberOfAddressOfFunctionNames() const; // EXPORT
		  /// Returns the number of AddressOfFunction values.
		  dword getNumberOfAddressOfFunctions() const; // EXPORT
*/
		  /// Set the Base value of the export directory.
		  void setBase(dword dwValue); // EXPORT
		  /// Set the Characteristics value of the export directory.
		  void setCharacteristics(dword dwValue); // EXPORT
		  /// Set the TimeDateStamp value of the export directory.
		  void setTimeDateStamp(dword dwValue); // EXPORT
		  /// Set the MajorVersion value of the export directory.
		  void setMajorVersion(word wValue); // EXPORT
		  /// Set the MinorVersion value of the export directory.
		  void setMinorVersion(word wValue); // EXPORT
		  /// Set the Name value of the export directory.
		  void setName(dword dwValue); // EXPORT
		  /// Set the NumberOfFunctions value of the export directory.
		  void setNumberOfFunctions(dword dwValue); // EXPORT
		  /// Set the NumberOfNames value of the export directory.
		  void setNumberOfNames(dword dwValue); // EXPORT
		  /// Set the AddressOfFunctions value of the export directory.
		  void setAddressOfFunctions(dword dwValue); // EXPORT
		  /// Set the AddressOfNames value of the export directory.
		  void setAddressOfNames(dword dwValue); // EXPORT
		  void setAddressOfNameOrdinals(dword value); // EXPORT

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;
	};

	template <int bits>
	class ExportDirectoryT : public ExportDirectory
	{
		public:
		  /// Read a file's export directory.
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader); // EXPORT
	};

	/**
	* @param inStream Input stream.
	* @param peHeader A valid PE header which is necessary because some RVA calculations need to be done.
	* \todo: Proper use of InputBuffer
	**/
	template <int bits>
	int ExportDirectoryT<bits>::read(
			std::istream& inStream,
			const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		unsigned int dirRva = peHeader.getIddExportRva();
		unsigned int dirOffset = peHeader.rvaToOffset(dirRva);
		if (ulFileSize < dirOffset + PELIB_IMAGE_EXPORT_DIRECTORY::size())
		{
			return ERROR_INVALID_FILE;
		}
		inStream_w.seekg(dirOffset, std::ios::beg);

		std::vector<unsigned char> vExportDirectory(PELIB_IMAGE_EXPORT_DIRECTORY::size());
		inStream_w.read(reinterpret_cast<char*>(vExportDirectory.data()), PELIB_IMAGE_EXPORT_DIRECTORY::size());

		InputBuffer inpBuffer(vExportDirectory);

		PELIB_IMAGE_EXP_DIRECTORY iedCurr;
		inpBuffer >> iedCurr.ied.Characteristics;
		inpBuffer >> iedCurr.ied.TimeDateStamp;
		inpBuffer >> iedCurr.ied.MajorVersion;
		inpBuffer >> iedCurr.ied.MinorVersion;
		inpBuffer >> iedCurr.ied.Name;
		inpBuffer >> iedCurr.ied.Base;
		inpBuffer >> iedCurr.ied.NumberOfFunctions;
		inpBuffer >> iedCurr.ied.NumberOfNames;
		inpBuffer >> iedCurr.ied.AddressOfFunctions;
		inpBuffer >> iedCurr.ied.AddressOfNames;
		inpBuffer >> iedCurr.ied.AddressOfNameOrdinals;
		m_occupiedAddresses.emplace_back(dirRva, dirRva + PELIB_IMAGE_EXPORT_DIRECTORY::size() - 1);

		// Verify the export directory. Do not allow more functions than the limit
		// Sample: CCE461B6EB23728BA3B8A97B9BE84C0FB9175DB31B9949E64144198AB3F702CE
		if (iedCurr.ied.NumberOfFunctions > PELIB_MAX_EXPORTED_FUNCTIONS || iedCurr.ied.NumberOfNames > PELIB_MAX_EXPORTED_FUNCTIONS)
			return ERROR_INVALID_FILE;

		unsigned int offset = peHeader.rvaToOffset(iedCurr.ied.Name);
		if (offset >= ulFileSize)
			return ERROR_INVALID_FILE;
		inStream_w.seekg(offset, std::ios::beg);

		char c = 0;
		std::string strFname = "";
		do
		{
			inStream_w.read(reinterpret_cast<char*>(&c), sizeof(c));
			if (!inStream_w) return ERROR_INVALID_FILE;
			if (c) strFname += c;
		}
		while (c != 0);
		iedCurr.name = strFname;
		m_occupiedAddresses.push_back(std::make_pair(iedCurr.ied.Name, iedCurr.ied.Name + strFname.length() + 1));

		PELIB_EXP_FUNC_INFORMATION efiCurr;
		efiCurr.ordinal = 0; efiCurr.addroffunc = 0; efiCurr.addrofname = 0;
		for (unsigned int i=0;i<iedCurr.ied.NumberOfFunctions;i++)
		{
			unsigned int offset = peHeader.rvaToOffset(iedCurr.ied.AddressOfFunctions) + i * sizeof(efiCurr.addroffunc);
			if (offset >= ulFileSize)
				return ERROR_INVALID_FILE;
			inStream_w.seekg(offset, std::ios::beg);
			inStream_w.read(reinterpret_cast<char*>(&efiCurr.addroffunc), sizeof(efiCurr.addroffunc));
			if (!inStream_w)
				return ERROR_INVALID_FILE;

			efiCurr.ordinal = iedCurr.ied.Base + i;
			iedCurr.functions.push_back(efiCurr);

			m_occupiedAddresses.emplace_back(
					iedCurr.ied.AddressOfFunctions + i*sizeof(efiCurr.addroffunc),
					iedCurr.ied.AddressOfFunctions + i*sizeof(efiCurr.addroffunc) + sizeof(efiCurr.addroffunc) - 1
				);
		}

		for (unsigned int i=0;i<iedCurr.ied.NumberOfNames;i++)
		{
			unsigned int offset = peHeader.rvaToOffset(iedCurr.ied.AddressOfNameOrdinals) + i*sizeof(efiCurr.ordinal);
			if (offset >= ulFileSize)
				return ERROR_INVALID_FILE;
			inStream_w.seekg(offset, std::ios::beg);
			word ordinal;
			inStream_w.read(reinterpret_cast<char*>(&ordinal), sizeof(ordinal));
			m_occupiedAddresses.emplace_back(
					iedCurr.ied.AddressOfNameOrdinals + i*sizeof(efiCurr.ordinal),
					iedCurr.ied.AddressOfNameOrdinals + i*sizeof(efiCurr.ordinal) + sizeof(efiCurr.ordinal) - 1
				);

			if (!inStream_w)
				return ERROR_INVALID_FILE;
			else if (ordinal >= iedCurr.functions.size())
				continue;

			iedCurr.functions[ordinal].ordinal = iedCurr.ied.Base + ordinal;

			offset = peHeader.rvaToOffset(iedCurr.ied.AddressOfNames) + i*sizeof(efiCurr.addrofname);
			if (offset >= ulFileSize)
				return ERROR_INVALID_FILE;
			inStream_w.seekg(offset, std::ios::beg);
			inStream_w.read(reinterpret_cast<char*>(&iedCurr.functions[ordinal].addrofname), sizeof(iedCurr.functions[ordinal].addrofname));
			if (!inStream_w)
				return ERROR_INVALID_FILE;
			m_occupiedAddresses.emplace_back(
					iedCurr.ied.AddressOfNames + i*sizeof(efiCurr.addrofname),
					iedCurr.ied.AddressOfNames + i*sizeof(efiCurr.addrofname) + sizeof(iedCurr.functions[ordinal].addrofname) - 1
				);

			offset = peHeader.rvaToOffset(iedCurr.functions[ordinal].addrofname);
			if (offset >= ulFileSize)
				return ERROR_INVALID_FILE;
			inStream_w.seekg(offset, std::ios::beg);

			char cc = 0;
			std::string strFname2 = "";
			do
			{
				inStream_w.read(reinterpret_cast<char*>(&cc), sizeof(cc));

				if (!inStream_w)
					return ERROR_INVALID_FILE;

				if (cc) strFname2 += cc;
			}
			while (cc != 0);

			iedCurr.functions[ordinal].funcname = strFname2;

			m_occupiedAddresses.emplace_back(
					iedCurr.functions[ordinal].addrofname,
					iedCurr.functions[ordinal].addrofname + strFname2.length() + 1
				);
		}

		std::swap(m_ied, iedCurr);

		return ERROR_NONE;
	}
}
#endif
