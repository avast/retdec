/*
* IatDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef IATDIRECTORY_H
#define IATDIRECTORY_H

#include "pelib/PeLibInc.h"
#include "pelib/PeHeader.h"

namespace PeLib
{
	/// Class that handles the Import Address Table (IAT)
	/**
	* This class can read and modify the Import Address Table of a PE file.
	**/
	class IatDirectory
	{
		protected:
		  std::vector<dword> m_vIat; ///< Stores the individual IAT fields.

		  int read(InputBuffer& inputBuffer, unsigned int dwOffset, unsigned int dwFileSize);

		public:
		  virtual ~IatDirectory() = default;

		  /// Reads the Import Address Table from a PE file.
		  int read(unsigned char* buffer, unsigned int buffersize); // EXPORT
		  /// Returns the number of fields in the IAT.
		  unsigned int calcNumberOfAddresses() const; // EXPORT
		  /// Adds another address to the IAT.
		  void addAddress(dword dwValue); // EXPORT
		  /// Removes an address from the IAT.
		  void removeAddress(unsigned int index); // EXPORT
		  /// Empties the IAT.
		  void clear(); // EXPORT
		  // Rebuilds the IAT.
		  void rebuild(std::vector<byte>& vBuffer) const; // EXPORT
		  /// Returns the size of the current IAT.
		  unsigned int size() const; // EXPORT
		  /// Writes the current IAT to a file.
		  int write(const std::string& strFilename, unsigned int uiOffset) const; // EXPORT

		  /// Retrieve the value of a field in the IAT.
		  dword getAddress(unsigned int index) const; // EXPORT
		  /// Change the value of a field in the IAT.
		  void setAddress(dword dwAddrnr, dword dwValue); // EXPORT
	};

	template <int bits>
	class IatDirectoryT : public IatDirectory
	{
		public:
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader); // EXPORT
	};

	/**
	* Reads the Import Address table from a file.
	* @param inStream Input stream.
	* @param peHeader A valid PE header which is necessary because some RVA calculations need to be done.
	**/
	template <int bits>
	int IatDirectoryT<bits>::read(std::istream& inStream, const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		std::uint64_t dwOffset = peHeader.rvaToOffset(peHeader.getIddIatRva());
		std::uint64_t dwSize = peHeader.getIddIatSize();

		if (ulFileSize <= dwOffset)
		{
			return ERROR_INVALID_FILE;
		}

		dwSize = std::min(ulFileSize - dwOffset, dwSize);
		inStream_w.seekg(dwOffset, std::ios::beg);

		std::vector<byte> vBuffer(dwSize);
		inStream_w.read(reinterpret_cast<char*>(vBuffer.data()), dwSize);

		InputBuffer inpBuffer{vBuffer};
		return IatDirectory::read(inpBuffer, dwOffset, ulFileSize);
	}

}

#endif

