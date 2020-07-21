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

#ifndef RETDEC_PELIB_EXPORTDIRECTORY_H
#define RETDEC_PELIB_EXPORTDIRECTORY_H

#include "retdec/pelib/ImageLoader.h"

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

		  void addOccupiedAddress(const std::string & str, std::uint32_t rva);

		public:
		  virtual ~ExportDirectory() = default;

		  /// Load the export directory from the image loader
		  int read(ImageLoader & imageLoader);

		  /// Add another function to be exported.
		  void addFunction(const std::string& strFuncname, std::uint32_t dwFuncAddr); // EXPORT
		  unsigned int calcNumberOfFunctions() const; // EXPORT
		  void clear(); // EXPORT
		  /// Identifies a function through it's name.
		  int getFunctionIndex(const std::string& strFunctionName) const; // EXPORT
		  /// Rebuild the current export directory.
		  void rebuild(std::vector<std::uint8_t>& vBuffer, std::uint32_t dwRva) const; // EXPORT
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
		  std::uint16_t getFunctionOrdinal(std::size_t index) const; // EXPORT
		  /// Get the address of the name of an exported function.
		  std::uint32_t getAddressOfName(std::size_t index) const; // EXPORT
		  /// Get the address of an exported function.
		  std::uint32_t getAddressOfFunction(std::size_t index) const; // EXPORT

		  /// Change the name of an exported function.
		  void setFunctionName(std::size_t index, const std::string& strName); // EXPORT
		  /// Change the ordinal of an exported function.
		  void setFunctionOrdinal(std::size_t index, std::uint16_t wValue); // EXPORT
		  /// Change the address of the name of an exported function.
		  void setAddressOfName(std::size_t index, std::uint32_t dwValue); // EXPORT
		  /// Change the address of an exported function.
		  void setAddressOfFunction(std::size_t index, std::uint32_t dwValue); // EXPORT

		  /*
		  std::uint16_t getFunctionOrdinal(std::string strFuncname) const;
		  std::uint32_t getAddressOfName(std::string strFuncname) const;
		  std::uint32_t getAddressOfFunction(std::string strFuncname) const;

		  void setFunctionOrdinal(std::string strFuncname, std::uint16_t wValue);
		  void setAddressOfName(std::string strFuncname, std::uint32_t dwValue);
		  void setAddressOfFunction(std::string strFuncname, std::uint32_t dwValue);
		  */

		  /// Return the Base value of the export directory.
		  std::uint32_t getBase() const; // EXPORT
		  /// Return the Characteristics value of the export directory.
		  std::uint32_t getCharacteristics() const; // EXPORT
		  /// Return the TimeDateStamp value of the export directory.
		  std::uint32_t getTimeDateStamp() const; // EXPORT
		  /// Return the MajorVersion value of the export directory.
		  std::uint16_t getMajorVersion() const; // EXPORT
		  /// Return the MinorVersion value of the export directory.
		  std::uint16_t getMinorVersion() const; // EXPORT
		  /// Return the Name value of the export directory.
		  std::uint32_t getName() const; // EXPORT
		  /// Return the NumberOfFunctions value of the export directory.
		  std::uint32_t getNumberOfFunctions() const; // EXPORT
		  /// Return the NumberOfNames value of the export directory.
		  std::uint32_t getNumberOfNames() const; // EXPORT
		  /// Return the AddressOfFunctions value of the export directory.
		  std::uint32_t getAddressOfFunctions() const; // EXPORT
		  /// Return the AddressOfNames value of the export directory.
		  std::uint32_t getAddressOfNames() const; // EXPORT
		  /// Returns the AddressOfNameOrdinals value.
		  std::uint32_t getAddressOfNameOrdinals() const; // EXPORT

/*		  /// Returns the number of NameOrdinals.
		  std::uint32_t getNumberOfNameOrdinals() const; // EXPORT
		  /// Returns the number of AddressOfFunctionNames values.
		  std::uint32_t getNumberOfAddressOfFunctionNames() const; // EXPORT
		  /// Returns the number of AddressOfFunction values.
		  std::uint32_t getNumberOfAddressOfFunctions() const; // EXPORT
*/
		  /// Set the Base value of the export directory.
		  void setBase(std::uint32_t dwValue); // EXPORT
		  /// Set the Characteristics value of the export directory.
		  void setCharacteristics(std::uint32_t dwValue); // EXPORT
		  /// Set the TimeDateStamp value of the export directory.
		  void setTimeDateStamp(std::uint32_t dwValue); // EXPORT
		  /// Set the MajorVersion value of the export directory.
		  void setMajorVersion(std::uint16_t wValue); // EXPORT
		  /// Set the MinorVersion value of the export directory.
		  void setMinorVersion(std::uint16_t wValue); // EXPORT
		  /// Set the Name value of the export directory.
		  void setName(std::uint32_t dwValue); // EXPORT
		  /// Set the NumberOfFunctions value of the export directory.
		  void setNumberOfFunctions(std::uint32_t dwValue); // EXPORT
		  /// Set the NumberOfNames value of the export directory.
		  void setNumberOfNames(std::uint32_t dwValue); // EXPORT
		  /// Set the AddressOfFunctions value of the export directory.
		  void setAddressOfFunctions(std::uint32_t dwValue); // EXPORT
		  /// Set the AddressOfNames value of the export directory.
		  void setAddressOfNames(std::uint32_t dwValue); // EXPORT
		  void setAddressOfNameOrdinals(std::uint32_t value); // EXPORT

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;
	};
}
#endif
