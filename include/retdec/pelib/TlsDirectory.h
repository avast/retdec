/*
* TlsDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef TLSDIRECTORY_H
#define TLSDIRECTORY_H

#include "pelib/PeHeader.h"

namespace PeLib
{
	/// Class that handles the TLS directory.
	/**
	* This class handles the TLS (Thread Local Storage) directory.
	**/
	template<int bits>
	class TlsDirectory
	{
		private:
		  PELIB_IMAGE_TLS_DIRECTORY<bits> m_tls; ///< Structure that holds all information about the directory.

		  void read(InputBuffer& inputbuffer);

		public:
		  /// Reads a file's TLS directory.
		  int read(std::istream& inStream, const PeHeaderT<bits> &peHeader); // EXPORT
		  int read(unsigned char* buffer, unsigned int buffersize); // EXPORT
		  /// Rebuilds the TLS directory.
		  void rebuild(std::vector<byte>& vBuffer) const; // EXPORT
		  /// Returns the size of the TLS Directory.
		  unsigned int size() const; // EXPORT
		  /// Writes the TLS directory to a file.
		  int write(const std::string& strFilename, unsigned int dwOffset) const; // EXPORT

		  /// Returns the StartAddressOfRawData value of the TLS header.
		  typename FieldSizes<bits>::VAR4_8 getStartAddressOfRawData() const; // EXPORT
		  /// Returns the EndAddressOfRawData value of the TLS header.
		  typename FieldSizes<bits>::VAR4_8 getEndAddressOfRawData() const; // EXPORT
		  /// Returns the AddressOfIndex value of the TLS header.
		  typename FieldSizes<bits>::VAR4_8 getAddressOfIndex() const; // EXPORT
		  /// Returns the AddressOfCallBacks value of the TLS header.
		  typename FieldSizes<bits>::VAR4_8 getAddressOfCallBacks() const; // EXPORT
		  /// Returns the SizeOfZeroFill value of the TLS header.
		  dword getSizeOfZeroFill() const; // EXPORT
		  /// Returns the Characteristics value of the TLS header.
		  dword getCharacteristics() const; // EXPORT

		  /// Sets the StartAddressOfRawData value of the TLS header.
		  void setStartAddressOfRawData(dword dwValue); // EXPORT
		  /// Sets the EndAddressOfRawData value of the TLS header.
		  void setEndAddressOfRawData(dword dwValue); // EXPORT
		  /// Sets the AddressOfIndex value of the TLS header.
		  void setAddressOfIndex(dword dwValue); // EXPORT
		  /// Sets the AddressOfCallBacks value of the TLS header.
		  void setAddressOfCallBacks(dword dwValue); // EXPORT
		  /// Sets the SizeOfZeroFill value of the TLS header.
		  void setSizeOfZeroFill(dword dwValue); // EXPORT
		  /// Sets the Characteristics value of the TLS header.
		  void setCharacteristics(dword dwValue); // EXPORT
	};

	template<int bits>
	void TlsDirectory<bits>::read(InputBuffer& inputBuffer)
	{
		PELIB_IMAGE_TLS_DIRECTORY<bits> itdCurr;

		inputBuffer >> itdCurr.StartAddressOfRawData;
		inputBuffer >> itdCurr.EndAddressOfRawData;
		inputBuffer >> itdCurr.AddressOfIndex;
		inputBuffer >> itdCurr.AddressOfCallBacks;
		inputBuffer >> itdCurr.SizeOfZeroFill;
		inputBuffer >> itdCurr.Characteristics;

		std::swap(itdCurr, m_tls);
	}

	template<int bits>
	int TlsDirectory<bits>::read(unsigned char* buffer, unsigned int buffersize)
	{
		if (buffersize < PELIB_IMAGE_TLS_DIRECTORY<bits>::size())
		{
			return ERROR_INVALID_FILE;
		}

		std::vector<byte> vTlsDirectory(buffer, buffer + buffersize);

		InputBuffer ibBuffer(vTlsDirectory);
		read(ibBuffer);
		return ERROR_NONE;
	}

	/**
	* Reads a file's TLS directory.
	* @param inStream Input stream.
	* @param peHeader A valid PE header.
	**/
	template<int bits>
	int TlsDirectory<bits>::read(std::istream& inStream, const PeHeaderT<bits> &peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);

		std::uint64_t uiOffset = peHeader.rvaToOffset(peHeader.getIddTlsRva());
		unsigned int uiSize = peHeader.getIddTlsSize();

		if (ulFileSize < uiOffset + uiSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<byte> vTlsDirectory(uiSize);
		inStream_w.read(reinterpret_cast<char*>(vTlsDirectory.data()), uiSize);

		InputBuffer ibBuffer{vTlsDirectory};
		read(ibBuffer);
		return ERROR_NONE;
	}

	/**
	* Rebuilds the current TLS Directory.
	* @param vBuffer Buffer where the TLS directory will be written to.
	**/
	template<int bits>
	void TlsDirectory<bits>::rebuild(std::vector<byte>& vBuffer) const
	{
		OutputBuffer obBuffer(vBuffer);

		obBuffer << m_tls.StartAddressOfRawData;
		obBuffer << m_tls.EndAddressOfRawData;
		obBuffer << m_tls.AddressOfIndex;
		obBuffer << m_tls.AddressOfCallBacks;
		obBuffer << m_tls.SizeOfZeroFill;
		obBuffer << m_tls.Characteristics;
	}

	/**
	* Returns the size of the TLS directory. Due to the static nature of this structure the return value
	* will always be 24.
	* @return Size in bytes.
	**/
	template<int bits>
	unsigned int TlsDirectory<bits>::size() const
	{
		return PELIB_IMAGE_TLS_DIRECTORY<bits>::size();
	}

	/**
	* @param strFilename Name of the file.
	* @param dwOffset File offset the TLS Directory will be written to.
	**/
	template<int bits>
	int TlsDirectory<bits>::write(const std::string& strFilename, unsigned int dwOffset) const
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

		ofFile.seekp(dwOffset, std::ios::beg);

		std::vector<unsigned char> vBuffer;
		rebuild(vBuffer);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), vBuffer.size());

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* @return The StartAddressOfRawData value of the TLS directory.
	**/
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 TlsDirectory<bits>::getStartAddressOfRawData() const
	{
		return m_tls.StartAddressOfRawData;
	}

	/**
	* @return The EndAddressOfRawData value of the TLS directory.
	**/
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 TlsDirectory<bits>::getEndAddressOfRawData() const
	{
		return m_tls.EndAddressOfRawData;
	}

	/**
	* @return The AddressOfIndex value of the TLS directory.
	**/
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 TlsDirectory<bits>::getAddressOfIndex() const
	{
		return m_tls.AddressOfIndex;
	}

	/**
	* @return The AddressOfCallBacks value of the TLS directory.
	**/
	template<int bits>
	typename FieldSizes<bits>::VAR4_8 TlsDirectory<bits>::getAddressOfCallBacks() const
	{
		return m_tls.AddressOfCallBacks;
	}

	/**
	* @return The SizeOfZeroFill value of the TLS directory.
	**/
	template<int bits>
	dword TlsDirectory<bits>::getSizeOfZeroFill() const
	{
		return m_tls.SizeOfZeroFill;
	}

	/**
	* @return The Characteristics value of the TLS directory.
	**/
	template<int bits>
	dword TlsDirectory<bits>::getCharacteristics() const
	{
		return m_tls.Characteristics;
	}

	/**
	* @param dwValue The new StartAddressOfRawData value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setStartAddressOfRawData(dword dwValue)
	{
		m_tls.StartAddressOfRawData = dwValue;
	}

	/**
	* @param dwValue The new EndAddressOfRawData value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setEndAddressOfRawData(dword dwValue)
	{
		m_tls.EndAddressOfRawData = dwValue;
	}

	/**
	* @param dwValue The new AddressOfIndex value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setAddressOfIndex(dword dwValue)
	{
		m_tls.AddressOfIndex = dwValue;
	}

	/**
	* @param dwValue The new AddressOfCallBacks value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setAddressOfCallBacks(dword dwValue)
	{
		m_tls.AddressOfCallBacks = dwValue;
	}

	/**
	* @param dwValue The new SizeOfZeroFill value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setSizeOfZeroFill(dword dwValue)
	{
		m_tls.SizeOfZeroFill = dwValue;
	}

	/**
	* @param dwValue The new Characteristics value of the TLS directory.
	**/
	template<int bits>
	void TlsDirectory<bits>::setCharacteristics(dword dwValue)
	{
		m_tls.Characteristics = dwValue;
	}

}
#endif
