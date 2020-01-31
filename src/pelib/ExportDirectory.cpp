/*
* ExportDirectory.cpp - Part of the PeLib library.
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
#include "pelib/ExportDirectory.h"

namespace PeLib
{
	/**
	* @param strFuncname Name of the function.
	* @param dwFuncAddr RVA of the function.
	**/
	void ExportDirectory::addFunction(const std::string& strFuncname, dword dwFuncAddr)
	{
		PELIB_EXP_FUNC_INFORMATION efiCurr;
		efiCurr.funcname = strFuncname;
		efiCurr.addroffunc = dwFuncAddr;
		m_ied.functions.push_back(efiCurr);
	}

	void ExportDirectory::removeFunction(unsigned int index)
	{
		m_ied.functions.erase(m_ied.functions.begin() + index);
	}

	void ExportDirectory::clear()
	{
		m_ied.functions.clear();
	}

	unsigned int ExportDirectory::calcNumberOfFunctions() const
	{
		return static_cast<unsigned int>(m_ied.functions.size());
	}

	/**
	* Identifies an exported function through it's name.
	* @param strFunctionName Name of the function
	* @return Number which identifies the functions.
	**/
	int ExportDirectory::getFunctionIndex(const std::string& strFunctionName) const
	{
		auto Iter = std::find_if(
				m_ied.functions.begin(),
				m_ied.functions.end(),
				[&](const auto& i) { return i.equal(strFunctionName); }
		);

		if (Iter == m_ied.functions.end())
		{
//			throw Exceptions::InvalidName(ExportDirectoryId, __LINE__);
			return -1;
		}

		return static_cast<int>(std::distance(m_ied.functions.begin(), Iter));
	}

	/**
	* @param vBuffer Buffer where the rebuilt export directory is written to.
	* @param dwRva RVA of the export directory.
	* \todo fValid flag
	**/
	void ExportDirectory::rebuild(std::vector<byte>& vBuffer, dword dwRva) const
	{
		unsigned int uiSizeDirectory = sizeof(PELIB_IMAGE_EXPORT_DIRECTORY);

		unsigned int uiSizeNames = 0;
		unsigned int uiSizeAddrFuncs = 0;
		unsigned int uiSizeAddrNames = 0;
		unsigned int uiSizeOrdinals = 0;

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			uiSizeNames += (m_ied.functions[i].funcname.empty()) ? 0 : static_cast<unsigned int>(m_ied.functions[i].funcname.size()) + 1;
			uiSizeAddrFuncs += sizeof(m_ied.functions[i].addroffunc);
			uiSizeAddrNames += (m_ied.functions[i].funcname.empty()) ? 0 : sizeof(m_ied.functions[i].addrofname);
			uiSizeOrdinals += (m_ied.functions[i].funcname.empty()) ? 0 : sizeof(m_ied.functions[i].ordinal);
		}

		unsigned int uiFilenameSize = static_cast<unsigned int>(m_ied.name.size()) + 1;

		OutputBuffer obBuffer(vBuffer);

		obBuffer << m_ied.ied.Characteristics;
		obBuffer << m_ied.ied.TimeDateStamp;
		obBuffer << m_ied.ied.MajorVersion;
		obBuffer << m_ied.ied.MinorVersion;
		obBuffer << dwRva + uiSizeDirectory + uiSizeAddrFuncs + uiSizeAddrNames + uiSizeOrdinals;
		obBuffer << m_ied.ied.Base;
		obBuffer << static_cast<unsigned int>(m_ied.functions.size());

		// TODO: Not correct but sufficient for now. (Update: I forgot what this comment refers to, but I'll leave it in)
		obBuffer << static_cast<unsigned int>(m_ied.functions.size());
		obBuffer << dwRva + uiSizeDirectory;
		obBuffer << dwRva + uiSizeDirectory + uiSizeAddrFuncs;
		obBuffer << dwRva + uiSizeDirectory + uiSizeAddrFuncs + uiSizeAddrNames;

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			obBuffer << m_ied.functions[i].addroffunc;
		}

		unsigned int ulFuncCounter = dwRva + uiSizeDirectory + uiSizeAddrFuncs + uiSizeAddrNames + uiSizeOrdinals + uiFilenameSize;

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			if (!m_ied.functions[i].funcname.empty())
			{
				obBuffer << ulFuncCounter;
				ulFuncCounter += static_cast<unsigned int>(m_ied.functions[i].funcname.size()) + 1;
			}
		}

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			if (!m_ied.functions[i].funcname.empty())
			{
				obBuffer <<  m_ied.functions[i].ordinal;
			}
		}

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			if (m_ied.functions[i].funcname.empty() && m_ied.functions[i].addroffunc)
			{
				obBuffer <<  m_ied.functions[i].ordinal;
			}
		}

		obBuffer.add(m_ied.name.c_str(), static_cast<unsigned int>(m_ied.name.size())+1);

		for (unsigned int i=0;i<m_ied.functions.size();i++)
		{
			if (!m_ied.functions[i].funcname.empty())
			{
				obBuffer.add(m_ied.functions[i].funcname.c_str(), static_cast<unsigned int>(m_ied.functions[i].funcname.size()) + 1);
			}
		}
	}

	/**
	* @return Size of the current export directory.
	**/
	unsigned int ExportDirectory::size() const
	{
		return m_ied.size();
	}

	/**
	* @param strFilename Name of the file.
	* @param uiOffset File offset the export directory will be written to.
	* @param uiRva RVA of the export directory.
	* \todo Check if ofFile.write succeeded.
	**/
	int ExportDirectory::write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva) const
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

		ofFile.seekp(uiOffset, std::ios::beg);

		std::vector<unsigned char> vBuffer;
		rebuild(vBuffer, uiRva);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Changes the filename according to the export directory.
	* @param strFilename New filename.
	**/
	void ExportDirectory::setNameString(const std::string& strFilename)
	{
		m_ied.name = strFilename;
	}

	std::string ExportDirectory::getNameString() const
	{
		return m_ied.name;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @return The name of that function.
	**/
	std::string ExportDirectory::getFunctionName(std::size_t dwIndex) const
	{
		return m_ied.functions[dwIndex].funcname;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @return The ordinal of that function.
	**/
	word ExportDirectory::getFunctionOrdinal(std::size_t dwIndex) const
	{
		return m_ied.functions[dwIndex].ordinal;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @return The RVA of the name string of that function.
	**/
	dword ExportDirectory::getAddressOfName(std::size_t dwIndex) const
	{
		return m_ied.functions[dwIndex].addrofname;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @return The RVA of that function.
	**/
	dword ExportDirectory::getAddressOfFunction(std::size_t dwIndex) const
	{
		return m_ied.functions[dwIndex].addroffunc;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @param strName The name of that function.
	**/
	void ExportDirectory::setFunctionName(std::size_t dwIndex, const std::string& strName)
	{
		m_ied.functions[dwIndex].funcname = strName;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @param wValue The ordinal of that function.
	**/
	void ExportDirectory::setFunctionOrdinal(std::size_t dwIndex, word wValue)
	{
		m_ied.functions[dwIndex].ordinal = wValue;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @param dwValue The RVA of the name string of that function.
	**/
	void ExportDirectory::setAddressOfName(std::size_t dwIndex, dword dwValue)
	{
		m_ied.functions[dwIndex].addrofname = dwValue;
	}

	/**
	* @param dwIndex Number which identifies an exported function.
	* @param dwValue The RVA of that function.
	**/
	void ExportDirectory::setAddressOfFunction(std::size_t dwIndex, dword dwValue)
	{
		m_ied.functions[dwIndex].addroffunc = dwValue;
	}

	/**
	* @return The ordinal base of the export directory.
	**/
	dword ExportDirectory::getBase() const
	{
		return m_ied.ied.Base;
	}

	/**
	* @return The characteristics of the export directory.
	**/
	dword ExportDirectory::getCharacteristics() const
	{
		return m_ied.ied.Characteristics;
	}

	/**
	* @return The time/date stamp of the export directory.
	**/
	dword ExportDirectory::getTimeDateStamp() const
	{
		return m_ied.ied.TimeDateStamp;
	}

	/**
	* @return The MajorVersion of the export directory.
	**/
	word ExportDirectory::getMajorVersion() const
	{
		return m_ied.ied.MajorVersion;
	}

	/**
	* @return The MinorVersion of the export directory.
	**/
	word ExportDirectory::getMinorVersion() const
	{
		return m_ied.ied.MinorVersion;
	}

	/**
	* @return The RVA of the name of the file.
	**/
	dword ExportDirectory::getName() const
	{
		return m_ied.ied.Name;
	}

	/**
	* @return The NumberOfFunctions of the export directory.
	**/
	dword ExportDirectory::getNumberOfFunctions() const
	{
		return m_ied.ied.NumberOfFunctions;
	}

	/**
	* @return The NumberOfNames of the export directory.
	**/
	dword ExportDirectory::getNumberOfNames() const
	{
		return m_ied.ied.NumberOfNames;
	}

	/**
	* @return The AddressOfFunctions of the export directory.
	**/
	dword ExportDirectory::getAddressOfFunctions() const
	{
		return m_ied.ied.AddressOfFunctions;
	}

	/**
	* @return The AddressOfNames of the export directory.
	**/
	dword ExportDirectory::getAddressOfNames() const
	{
		return m_ied.ied.AddressOfNames;
	}

/*	dword ExportDirectory::getNumberOfNameOrdinals() const
	{
		return static_cast<dword>(m_ied.functions.size());
	}

	dword ExportDirectory::getNumberOfAddressOfFunctionNames() const
	{
		return static_cast<dword>(m_ied.functions.size());
	}

	dword ExportDirectory::getNumberOfAddressOfFunctions() const
	{
		return static_cast<dword>(m_ied.functions.size());
	}
*/
	/**
	* @return The AddressOfNameOrdinals of the export directory.
	**/
	dword ExportDirectory::getAddressOfNameOrdinals() const
	{
		return m_ied.ied.AddressOfNameOrdinals;
	}

	/**
	* @param dwValue The ordinal base of the export directory.
	**/
	void ExportDirectory::setBase(dword dwValue)
	{
		m_ied.ied.Base = dwValue;
	}

	/**
	* @param dwValue The Characteristics of the export directory.
	**/
	void ExportDirectory::setCharacteristics(dword dwValue)
	{
		m_ied.ied.Characteristics = dwValue;
	}

	/**
	* @param dwValue The TimeDateStamp of the export directory.
	**/
	void ExportDirectory::setTimeDateStamp(dword dwValue)
	{
		m_ied.ied.TimeDateStamp = dwValue;
	}

	/**
	* @param wValue The MajorVersion of the export directory.
	**/
	void ExportDirectory::setMajorVersion(word wValue)
	{
		m_ied.ied.MajorVersion = wValue;
	}

	/**
	* @param wValue The MinorVersion of the export directory.
	**/
	void ExportDirectory::setMinorVersion(word wValue)
	{
		m_ied.ied.MinorVersion = wValue;
	}

	/**
	* @param dwValue The Name of the export directory.
	**/
	void ExportDirectory::setName(dword dwValue)
	{
		m_ied.ied.Name = dwValue;
	}

	/**
	* @param dwValue The NumberOfFunctions of the export directory.
	**/
	void ExportDirectory::setNumberOfFunctions(dword dwValue)
	{
		m_ied.ied.NumberOfFunctions = dwValue;
	}

	/**
	* @param dwValue The NumberOfNames of the export directory.
	**/
	void ExportDirectory::setNumberOfNames(dword dwValue)
	{
		m_ied.ied.NumberOfNames = dwValue;
	}

	/**
	* @param dwValue The AddressOfFunctions of the export directory.
	**/
	void ExportDirectory::setAddressOfFunctions(dword dwValue)
	{
		m_ied.ied.AddressOfFunctions = dwValue;
	}

	/**
	* @param dwValue The AddressOfNames of the export directory.
	**/
	void ExportDirectory::setAddressOfNames(dword dwValue)
	{
		m_ied.ied.AddressOfNames = dwValue;
	}

	void ExportDirectory::setAddressOfNameOrdinals(dword value)
	{
		m_ied.ied.AddressOfNameOrdinals = value;
	}

	const std::vector<std::pair<unsigned int, unsigned int>>& ExportDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}
}
