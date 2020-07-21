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

#ifndef RETDEC_PELIB_TLSDIRECTORY_H
#define RETDEC_PELIB_TLSDIRECTORY_H

#include "retdec/pelib/ImageLoader.h"

namespace PeLib
{
	/// Class that handles the TLS directory.
	/**
	* This class handles the TLS (Thread Local Storage) directory.
	**/
	class TlsDirectory
	{
		private:
		  PELIB_IMAGE_TLS_DIRECTORY m_tls; ///< Structure that holds all information about the directory.
		  std::vector<uint64_t> m_Callbacks;
		  std::size_t pointerSize;

		public:
		  /// Reads a file's TLS directory.
		  int read(ImageLoader & imageLoader); // EXPORT
		  /// Rebuilds the TLS directory.
		  void rebuild(std::vector<std::uint8_t>& vBuffer) const; // EXPORT
		  /// Returns the size of the TLS Directory.
		  unsigned int size() const; // EXPORT
		  /// Writes the TLS directory to a file.
		  int write(const std::string& strFilename, unsigned int dwOffset) const; // EXPORT

		  /// Returns vector of TLS callbacks
		  const std::vector<std::uint64_t> & getCallbacks() const;
		  /// Returns the StartAddressOfRawData value of the TLS header.
		  std::uint64_t getStartAddressOfRawData() const; // EXPORT
		  /// Returns the EndAddressOfRawData value of the TLS header.
		  std::uint64_t getEndAddressOfRawData() const; // EXPORT
		  /// Returns the AddressOfIndex value of the TLS header.
		  std::uint64_t getAddressOfIndex() const; // EXPORT
		  /// Returns the AddressOfCallBacks value of the TLS header.
		  std::uint64_t getAddressOfCallBacks() const; // EXPORT
		  /// Returns the SizeOfZeroFill value of the TLS header.
		  std::uint32_t getSizeOfZeroFill() const; // EXPORT
		  /// Returns the Characteristics value of the TLS header.
		  std::uint32_t getCharacteristics() const; // EXPORT

		  /// Sets the StartAddressOfRawData value of the TLS header.
		  void setStartAddressOfRawData(std::uint64_t value); // EXPORT
		  /// Sets the EndAddressOfRawData value of the TLS header.
		  void setEndAddressOfRawData(std::uint64_t value); // EXPORT
		  /// Sets the AddressOfIndex value of the TLS header.
		  void setAddressOfIndex(std::uint64_t value); // EXPORT
		  /// Sets the AddressOfCallBacks value of the TLS header.
		  void setAddressOfCallBacks(std::uint64_t value); // EXPORT
		  /// Sets the SizeOfZeroFill value of the TLS header.
		  void setSizeOfZeroFill(std::uint32_t dwValue); // EXPORT
		  /// Sets the Characteristics value of the TLS header.
		  void setCharacteristics(std::uint32_t dwValue); // EXPORT
	};

	/**
	* Reads a file's TLS directory.
	* @param imageLoader Referenve to a valid PE image loader.
	**/
	inline
	int TlsDirectory::read(ImageLoader & imageLoader)
	{
		std::uint64_t imageBase = imageLoader.getImageBase();
		std::uint32_t rva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_TLS);
		std::uint32_t size = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_TLS);
		std::uint32_t sizeOfImage = imageLoader.getSizeOfImage();
		std::uint32_t bytesRead;

		if((rva + size) >= sizeOfImage)
			return ERROR_INVALID_FILE;

		// Remember the pointer size
		pointerSize = imageLoader.getPointerSize();

		// Read the TLS directory from the image. Differentiate between 32-bit and 64-bit
		if(imageLoader.getImageBitability() == 32)
		{
			PELIB_IMAGE_TLS_DIRECTORY32 TlsDirectory32;

			// Read the 32-bit TLS directory structure
			bytesRead = imageLoader.readImage(&TlsDirectory32, rva, sizeof(PELIB_IMAGE_TLS_DIRECTORY32));
			if(bytesRead != sizeof(PELIB_IMAGE_TLS_DIRECTORY32))
				return ERROR_INVALID_FILE;

			// Convert to 64-bit structure
			m_tls.StartAddressOfRawData = TlsDirectory32.StartAddressOfRawData;
			m_tls.EndAddressOfRawData = TlsDirectory32.EndAddressOfRawData;
			m_tls.AddressOfIndex = TlsDirectory32.AddressOfIndex;
			m_tls.AddressOfCallBacks = TlsDirectory32.AddressOfCallBacks;
			m_tls.SizeOfZeroFill = TlsDirectory32.SizeOfZeroFill;
			m_tls.Characteristics = TlsDirectory32.Characteristics;
		}
		else
		{
			// Read the 32-bit TLS directory structure
			bytesRead = imageLoader.readImage(&m_tls, rva, sizeof(PELIB_IMAGE_TLS_DIRECTORY));
			if(bytesRead != sizeof(PELIB_IMAGE_TLS_DIRECTORY))
				return ERROR_INVALID_FILE;
		}

		// If there is non-zero address of callbacks, we try to read at least one pointer to know
		// if there are TLS callbacks
		if(imageBase < m_tls.AddressOfCallBacks && m_tls.AddressOfCallBacks < (imageBase + sizeOfImage))
		{
			std::uint32_t rva = (std::uint32_t)(m_tls.AddressOfCallBacks - imageBase);

			for(std::uint32_t i = 0; i < PELIB_MAX_TLS_CALLBACKS; i++)
			{
				std::uint64_t AddressOfCallBack = 0;

				if(imageLoader.readPointer(rva, AddressOfCallBack) == 0)
					break;
				if(AddressOfCallBack == 0)
					break;

				m_Callbacks.push_back(AddressOfCallBack);
				rva += pointerSize;
			}
		}

		return ERROR_NONE;
	}

	/**
	* Rebuilds the current TLS Directory.
	* @param vBuffer Buffer where the TLS directory will be written to.
	**/
	inline
	void TlsDirectory::rebuild(std::vector<std::uint8_t>& vBuffer) const
	{
		if(pointerSize == 32)
		{
			PELIB_IMAGE_TLS_DIRECTORY32 TlsDirectory32;

			TlsDirectory32.StartAddressOfRawData = (std::uint32_t)m_tls.StartAddressOfRawData;
			TlsDirectory32.EndAddressOfRawData   = (std::uint32_t)m_tls.EndAddressOfRawData;
			TlsDirectory32.AddressOfIndex        = (std::uint32_t)m_tls.AddressOfIndex;
			TlsDirectory32.AddressOfCallBacks    = (std::uint32_t)m_tls.AddressOfCallBacks;
			TlsDirectory32.SizeOfZeroFill        = m_tls.SizeOfZeroFill;
			TlsDirectory32.Characteristics       = m_tls.Characteristics;

			vBuffer.resize(sizeof(PELIB_IMAGE_TLS_DIRECTORY32));
			memcpy(vBuffer.data(), &TlsDirectory32, sizeof(PELIB_IMAGE_TLS_DIRECTORY32));
		}
		else
		{
			vBuffer.resize(sizeof(PELIB_IMAGE_TLS_DIRECTORY));
			memcpy(vBuffer.data(), &m_tls, sizeof(PELIB_IMAGE_TLS_DIRECTORY));
		}
	}

	/**
	* Returns the size of the TLS directory. Due to the static nature of this structure the return value
	* will always be 24.
	* @return Size in bytes.
	**/
	inline
	unsigned int TlsDirectory::size() const
	{
		return (pointerSize == 32) ? sizeof(PELIB_IMAGE_TLS_DIRECTORY32) : sizeof(PELIB_IMAGE_TLS_DIRECTORY);
	}

	/**
	* @param strFilename Name of the file.
	* @param dwOffset File offset the TLS Directory will be written to.
	**/
	inline
	int TlsDirectory::write(const std::string& strFilename, unsigned int dwOffset) const
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
	* @return The vector of TLS callbacks
	**/
	inline
	const std::vector<std::uint64_t> & TlsDirectory::getCallbacks() const
	{
		return m_Callbacks;
	}

	/**
	* @return The StartAddressOfRawData value of the TLS directory.
	**/
	inline
	std::uint64_t TlsDirectory::getStartAddressOfRawData() const
	{
		return m_tls.StartAddressOfRawData;
	}

	/**
	* @return The EndAddressOfRawData value of the TLS directory.
	**/
	inline
	std::uint64_t TlsDirectory::getEndAddressOfRawData() const
	{
		return m_tls.EndAddressOfRawData;
	}

	/**
	* @return The AddressOfIndex value of the TLS directory.
	**/
	inline
	std::uint64_t TlsDirectory::getAddressOfIndex() const
	{
		return m_tls.AddressOfIndex;
	}

	/**
	* @return The AddressOfCallBacks value of the TLS directory.
	**/
	inline
	std::uint64_t TlsDirectory::getAddressOfCallBacks() const
	{
		return m_tls.AddressOfCallBacks;
	}

	/**
	* @return The SizeOfZeroFill value of the TLS directory.
	**/
	inline
	std::uint32_t TlsDirectory::getSizeOfZeroFill() const
	{
		return m_tls.SizeOfZeroFill;
	}

	/**
	* @return The Characteristics value of the TLS directory.
	**/
	inline
	std::uint32_t TlsDirectory::getCharacteristics() const
	{
		return m_tls.Characteristics;
	}

	/**
	* @param value The new StartAddressOfRawData value of the TLS directory.
	**/
	inline
	void TlsDirectory::setStartAddressOfRawData(std::uint64_t value)
	{
		m_tls.StartAddressOfRawData = value;
	}

	/**
	* @param value The new EndAddressOfRawData value of the TLS directory.
	**/
	inline
	void TlsDirectory::setEndAddressOfRawData(std::uint64_t value)
	{
		m_tls.EndAddressOfRawData = value;
	}

	/**
	* @param value The new AddressOfIndex value of the TLS directory.
	**/
	inline
	void TlsDirectory::setAddressOfIndex(std::uint64_t value)
	{
		m_tls.AddressOfIndex = value;
	}

	/**
	* @param value The new AddressOfCallBacks value of the TLS directory.
	**/
	inline
	void TlsDirectory::setAddressOfCallBacks(std::uint64_t value)
	{
		m_tls.AddressOfCallBacks = value;
	}

	/**
	* @param dwValue The new SizeOfZeroFill value of the TLS directory.
	**/
	inline
	void TlsDirectory::setSizeOfZeroFill(std::uint32_t dwValue)
	{
		m_tls.SizeOfZeroFill = dwValue;
	}

	/**
	* @param dwValue The new Characteristics value of the TLS directory.
	**/
	inline
	void TlsDirectory::setCharacteristics(std::uint32_t dwValue)
	{
		m_tls.Characteristics = dwValue;
	}

}
#endif
