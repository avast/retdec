/*
* ComHeaderDirectory.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "pelib/PeLibInc.h"
#include "pelib/ComHeaderDirectory.h"

namespace PeLib
{
	void ComHeaderDirectory::read(InputBuffer& inputbuffer)
	{
		PELIB_IMAGE_COR20_HEADER ichCurr;

		inputbuffer >> ichCurr.cb;
		inputbuffer >> ichCurr.MajorRuntimeVersion;
		inputbuffer >> ichCurr.MinorRuntimeVersion;
		inputbuffer >> ichCurr.MetaData.VirtualAddress;
		inputbuffer >> ichCurr.MetaData.Size;
		inputbuffer >> ichCurr.Flags;
		inputbuffer >> ichCurr.EntryPointToken;
		inputbuffer >> ichCurr.Resources.VirtualAddress;
		inputbuffer >> ichCurr.Resources.Size;
		inputbuffer >> ichCurr.StrongNameSignature.VirtualAddress;
		inputbuffer >> ichCurr.StrongNameSignature.Size;
		inputbuffer >> ichCurr.CodeManagerTable.VirtualAddress;
		inputbuffer >> ichCurr.CodeManagerTable.Size;
		inputbuffer >> ichCurr.VTableFixups.VirtualAddress;
		inputbuffer >> ichCurr.VTableFixups.Size;
		inputbuffer >> ichCurr.ExportAddressTableJumps.VirtualAddress;
		inputbuffer >> ichCurr.ExportAddressTableJumps.Size;
		inputbuffer >> ichCurr.ManagedNativeHeader.VirtualAddress;
		inputbuffer >> ichCurr.ManagedNativeHeader.Size;

		std::swap(ichCurr, m_ichComHeader);
	}

	int ComHeaderDirectory::read(unsigned char* buffer, unsigned int buffersize)
	{
		if (buffersize < PELIB_IMAGE_COR20_HEADER::size())
		{
			return ERROR_INVALID_FILE;
		}

		std::vector<byte> vComDescDirectory(buffer, buffer + buffersize);

		InputBuffer ibBuffer(vComDescDirectory);
		read(ibBuffer);
		return ERROR_NONE;
	}

	/**
	* Rebuilds the current COM+ descriptor.
	* @param vBuffer Buffer where the COM+ descriptor will be written to.
	**/
	void ComHeaderDirectory::rebuild(std::vector<byte>& vBuffer) const
	{
		OutputBuffer obBuffer(vBuffer);

		obBuffer << m_ichComHeader.cb;
		obBuffer << m_ichComHeader.MajorRuntimeVersion;
		obBuffer << m_ichComHeader.MinorRuntimeVersion;
		obBuffer << m_ichComHeader.MetaData.VirtualAddress;
		obBuffer << m_ichComHeader.MetaData.Size;
		obBuffer << m_ichComHeader.Flags;
		obBuffer << m_ichComHeader.EntryPointToken;
		obBuffer << m_ichComHeader.Resources.VirtualAddress;
		obBuffer << m_ichComHeader.Resources.Size;
		obBuffer << m_ichComHeader.StrongNameSignature.VirtualAddress;
		obBuffer << m_ichComHeader.StrongNameSignature.Size;
		obBuffer << m_ichComHeader.CodeManagerTable.VirtualAddress;
		obBuffer << m_ichComHeader.CodeManagerTable.Size;
		obBuffer << m_ichComHeader.VTableFixups.VirtualAddress;
		obBuffer << m_ichComHeader.VTableFixups.Size;
		obBuffer << m_ichComHeader.ExportAddressTableJumps.VirtualAddress;
		obBuffer << m_ichComHeader.ExportAddressTableJumps.Size;
		obBuffer << m_ichComHeader.ManagedNativeHeader.VirtualAddress;
		obBuffer << m_ichComHeader.ManagedNativeHeader.Size;
	}

	/**
	* @return Size in bytes.
	**/
	unsigned int ComHeaderDirectory::size() const
	{
		return PELIB_IMAGE_COR20_HEADER::size();
	}

	/**
	* @param strFilename Name of the file.
	* @param dwOffset File offset the COM+ descriptor will be written to.
	**/
	int ComHeaderDirectory::write(const std::string& strFilename, unsigned int dwOffset) const
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

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* @return SizeOfHeader value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getSizeOfHeader() const
	{
		return m_ichComHeader.cb;
	}

	/**
	* @return MajorRuntimeVersion value of the current COM+ descriptor.
	**/
	word ComHeaderDirectory::getMajorRuntimeVersion() const
	{
		return m_ichComHeader.MajorRuntimeVersion;
	}

	/**
	* @return MinorRuntimeVersion value of the current COM+ descriptor.
	**/
	word ComHeaderDirectory::getMinorRuntimeVersion() const
	{
		return m_ichComHeader.MinorRuntimeVersion;
	}

	/**
	* @return MetaData (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getMetaDataVa() const
	{
		return m_ichComHeader.MetaData.VirtualAddress;
	}

	/**
	* @return MetaData (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getMetaDataSize() const
	{
		return m_ichComHeader.MetaData.Size;
	}

	/**
	* @return Flags value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getFlags() const
	{
		return m_ichComHeader.Flags;
	}

	/**
	* @return EntryPointToken value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getEntryPointToken() const
	{
		return m_ichComHeader.EntryPointToken;
	}

	/**
	* @return Resources (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getResourcesVa() const
	{
		return m_ichComHeader.Resources.VirtualAddress;
	}

	/**
	* @return Resources (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getResourcesSize() const
	{
		return m_ichComHeader.Resources.Size;
	}

	/**
	* @return StrongNameSignature (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getStrongNameSignatureVa() const
	{
		return m_ichComHeader.StrongNameSignature.VirtualAddress;
	}

	/**
	* @return StrongNameSignature (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getStrongNameSignatureSize() const
	{
		return m_ichComHeader.StrongNameSignature.Size;
	}

	/**
	* @return CodeManagerTable (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getCodeManagerTableVa() const
	{
		return m_ichComHeader.CodeManagerTable.VirtualAddress;
	}

	/**
	* @return CodeManagerTable (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getCodeManagerTableSize() const
	{
		return m_ichComHeader.CodeManagerTable.Size;
	}

	/**
	* @return VTableFixups (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getVTableFixupsVa() const
	{
		return m_ichComHeader.VTableFixups.VirtualAddress;
	}

	/**
	* @return VTableFixups (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getVTableFixupsSize() const
	{
		return m_ichComHeader.VTableFixups.Size;
	}

	/**
	* @return ExportAddressTableJumps (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getExportAddressTableJumpsVa() const
	{
		return m_ichComHeader.ExportAddressTableJumps.VirtualAddress;
	}

	/**
	* @return ExportAddressTableJumps (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getExportAddressTableJumpsSize() const
	{
		return m_ichComHeader.ExportAddressTableJumps.Size;
	}

	/**
	* @return ManagedNativeHeader (Virtual Address) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getManagedNativeHeaderVa() const
	{
		return m_ichComHeader.ManagedNativeHeader.VirtualAddress;
	}

	/**
	* @return ManagedNativeHeader (Size) value of the current COM+ descriptor.
	**/
	dword ComHeaderDirectory::getManagedNativeHeaderSize() const
	{
		return m_ichComHeader.ManagedNativeHeader.Size;
	}

	/**
	* @param dwValue New value for the current SizeOfHeader (cb) value.
	**/
	void ComHeaderDirectory::setSizeOfHeader(dword dwValue)
	{
		m_ichComHeader.cb = dwValue;
	}

	/**
	* @param wValue New value for the current MajorRuntimeVersion value.
	**/
	void ComHeaderDirectory::setMajorRuntimeVersion(word wValue)
	{
		m_ichComHeader.MajorRuntimeVersion = wValue;
	}

	/**
	* @param wValue New value for the current MinorRuntimeVersion value.
	**/
	void ComHeaderDirectory::setMinorRuntimeVersion(word wValue)
	{
		m_ichComHeader.MinorRuntimeVersion = wValue;
	}

	/**
	* @param dwValue New value for the current MetaData (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setMetaDataVa(dword dwValue)
	{
		m_ichComHeader.MetaData.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current MetaData (Size) value.
	**/
	void ComHeaderDirectory::setMetaDataSize(dword dwValue)
	{
		m_ichComHeader.MetaData.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current Flags value.
	**/
	void ComHeaderDirectory::setFlags(dword dwValue)
	{
		m_ichComHeader.Flags = dwValue;
	}

	/**
	* @param dwValue New value for the current EntryPointToken value.
	**/
	void ComHeaderDirectory::setEntryPointToken(dword dwValue)
	{
		m_ichComHeader.EntryPointToken = dwValue;
	}

	/**
	* @param dwValue New value for the current Resources (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setResourcesVa(dword dwValue)
	{
		m_ichComHeader.Resources.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current Resources (Size) value.
	**/
	void ComHeaderDirectory::setResourcesSize(dword dwValue)
	{
		m_ichComHeader.Resources.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current StrongNameSignature (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setStrongNameSignatureVa(dword dwValue)
	{
		m_ichComHeader.StrongNameSignature.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current StrongNameSignature (Size) value.
	**/
	void ComHeaderDirectory::setStrongNameSignagureSize(dword dwValue)
	{
		m_ichComHeader.StrongNameSignature.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current CodeManagerTable (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setCodeManagerTableVa(dword dwValue)
	{
		m_ichComHeader.CodeManagerTable.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current CodeManagerTable (Size) value.
	**/
	void ComHeaderDirectory::setCodeManagerTableSize(dword dwValue)
	{
		m_ichComHeader.CodeManagerTable.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current VTableFixups (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setVTableFixupsVa(dword dwValue)
	{
		m_ichComHeader.VTableFixups.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current VTableFixups (Size) value.
	**/
	void ComHeaderDirectory::setVTableFixupsSize(dword dwValue)
	{
		m_ichComHeader.VTableFixups.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current ExportAddressTableJumps (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setExportAddressTableJumpsVa(dword dwValue)
	{
		m_ichComHeader.ExportAddressTableJumps.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current ExportAddressTableJumps (Size) value.
	**/
	void ComHeaderDirectory::setExportAddressTableJumpsSize(dword dwValue)
	{
		m_ichComHeader.ExportAddressTableJumps.Size = dwValue;
	}

	/**
	* @param dwValue New value for the current ManagedNativeHeader (VirtualAddress) value.
	**/
	void ComHeaderDirectory::setManagedNativeHeaderVa(dword dwValue)
	{
		m_ichComHeader.ManagedNativeHeader.VirtualAddress = dwValue;
	}

	/**
	* @param dwValue New value for the current ManagedNativeHeader (Size) value.
	**/
	void ComHeaderDirectory::setManagedNativeHeaderSize(dword dwValue)
	{
		m_ichComHeader.ManagedNativeHeader.Size = dwValue;
	}

}
