/*
* BoundImportDirectory.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include <numeric>
#include <set>
#include <map>

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/BoundImportDirectory.h"

namespace PeLib
{
	/**
	* Adds another bound import to the BoundImport directory.
	* @param strModuleName Name of the PE file which will be imported.
	* @param dwTds Value of the TimeDateStamp of the bound import field.
	* @param wOmn Value of the OffsetModuleName of the bound import field.
	* @param wWfr Value of the NumberOfModuleForwarderRefs of the bound import field.
	**/
	int BoundImportDirectory::addBoundImport(const std::string& strModuleName, std::uint32_t dwTds, std::uint16_t wOmn, std::uint16_t wWfr)
	{
		for (unsigned int i=0;i<m_vIbd.size();i++)
		{
			if (isEqualNc(strModuleName, m_vIbd[i].strModuleName))
			{
				return ERROR_DUPLICATE_ENTRY;
			}
		}

		PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR ibidCurrent;
		ibidCurrent.TimeDateStamp = dwTds;
		ibidCurrent.OffsetModuleName = wOmn;
		ibidCurrent.NumberOfModuleForwarderRefs = wWfr;
		PELIB_IMAGE_BOUND_DIRECTORY ibdCurrent;
		ibdCurrent.ibdDescriptor = ibidCurrent;
		ibdCurrent.strModuleName = strModuleName;
		m_vIbd.push_back(ibdCurrent);

		return ERROR_NONE;
	}

	/**
	* Searches for the first instance of a module with the given modulename.
	* @param strModuleName The name of a module.
	* @return The id of the module.
	**/
	int BoundImportDirectory::getModuleIndex(const std::string& strModuleName) const
	{
		auto Iter = std::find_if(
				m_vIbd.begin(),
				m_vIbd.end(),
				[&](const auto& i) { return i.equal(strModuleName); }
		);

		if (Iter == m_vIbd.end())
		{
			return ERROR_ENTRY_NOT_FOUND;
		}

		return static_cast<int>(std::distance(m_vIbd.begin(), Iter));
	}

	/**
	* @return Number of files in the current BoundImport directory.
	**/
	unsigned int BoundImportDirectory::calcNumberOfModules() const
	{
		return static_cast<unsigned int>(m_vIbd.size());
	}

	/**
	* Searches for the first instance of a module with the given modulename.
	* @param inpBuffer Reference to the input buffer
	* @param data source data
	* @param dwSize length of the source data
	* @return ERROR_NONE if success, otherwise an error code.
	**/
	int BoundImportDirectory::read(InputBuffer& inpBuffer, unsigned char* data, unsigned int dwSize)
	{
		std::vector<PELIB_IMAGE_BOUND_DIRECTORY> currentDirectory;

		do
		{
			if (inpBuffer.get() + PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size() >= inpBuffer.size())
				return ERROR_INVALID_FILE;

			PELIB_IMAGE_BOUND_DIRECTORY ibdCurrent;

			inpBuffer >> ibdCurrent.ibdDescriptor.TimeDateStamp;
			inpBuffer >> ibdCurrent.ibdDescriptor.OffsetModuleName;
			inpBuffer >> ibdCurrent.ibdDescriptor.NumberOfModuleForwarderRefs;

			if (ibdCurrent.ibdDescriptor.TimeDateStamp == 0 && ibdCurrent.ibdDescriptor.OffsetModuleName == 0 && ibdCurrent.ibdDescriptor.NumberOfModuleForwarderRefs == 0) break;

			for (int i=0;i<ibdCurrent.ibdDescriptor.NumberOfModuleForwarderRefs;i++)
			{
				if (inpBuffer.get() + PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size() >= inpBuffer.size())
					return ERROR_INVALID_FILE;

				PELIB_IMAGE_BOUND_DIRECTORY currentForwarder;

				inpBuffer >> currentForwarder.ibdDescriptor.TimeDateStamp;
				inpBuffer >> currentForwarder.ibdDescriptor.OffsetModuleName;
				inpBuffer >> currentForwarder.ibdDescriptor.NumberOfModuleForwarderRefs;

				ibdCurrent.moduleForwarders.push_back(currentForwarder);
			}

			currentDirectory.push_back(ibdCurrent);
			ibdCurrent.moduleForwarders.clear();
		} while (true);

		for (unsigned int i=0;i<currentDirectory.size();i++)
		{
			std::uint32_t wOmn = currentDirectory[i].ibdDescriptor.OffsetModuleName;
			if (wOmn > dwSize)
			{
				return ERROR_INVALID_FILE;
			}

			currentDirectory[i].strModuleName = "";
			for (int k=0;k + wOmn < dwSize && data[wOmn + k] != 0;k++)
			{
				currentDirectory[i].strModuleName += data[wOmn + k];
			}

			for (unsigned int j=0;j<currentDirectory[i].moduleForwarders.size();j++)
			{
				std::uint32_t wOmn2 = currentDirectory[i].moduleForwarders[j].ibdDescriptor.OffsetModuleName;
				if (wOmn2 > dwSize)
				{
					return ERROR_INVALID_FILE;
				}

//				m_vIbd[i].moduleForwarders[j].strModuleName.assign((char*)(&vBimpDir[wOmn2]));
				currentDirectory[i].moduleForwarders[j].strModuleName = "";
				for (int k=0;k + wOmn2 < dwSize && data[wOmn2 + k] != 0;k++)
				{
					currentDirectory[i].moduleForwarders[j].strModuleName += data[wOmn2 + k];
				}
			}
		}

		std::swap(m_vIbd, currentDirectory);

		return ERROR_NONE;
	}

	int BoundImportDirectory::read(unsigned char* pcBuffer, unsigned int uiSize)
	{
		std::vector<unsigned char> vBimpDir(pcBuffer, pcBuffer + uiSize);
		InputBuffer inpBuffer(vBimpDir);

		return read(inpBuffer, vBimpDir.data(), uiSize);
	}

	/**
	* Reads the BoundImport directory from a PE file.
	* @param imageLoader Reference to the image loader
	**/
	int BoundImportDirectory::read(ImageLoader & imageLoader)
	{
		std::uint32_t importRva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
		std::uint32_t importSize = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
		std::uint32_t sizeOfImage = imageLoader.getSizeOfImage();

		// Refuse to load blatantly invalid bound import directory
		if(importSize & 0xFF000000)
			return ERROR_INVALID_FILE;

		// Refuse to load too large import directories
		if((importRva + importSize) < importRva || importRva >= sizeOfImage || (importRva + importSize) >= sizeOfImage)
			return ERROR_INVALID_FILE;

		std::vector<unsigned char> vBimpDir(importSize);
		imageLoader.readImage(reinterpret_cast<char*>(vBimpDir.data()), importRva, importSize);

		InputBuffer inpBuffer{vBimpDir};
		return BoundImportDirectory::read(inpBuffer, vBimpDir.data(), importSize);
	}

	unsigned int BoundImportDirectory::totalModules() const
	{
		unsigned int modules = static_cast<unsigned int>(m_vIbd.size());

		for (unsigned int i=0;i<m_vIbd.size();i++)
		{
			modules += static_cast<unsigned int>(m_vIbd[i].moduleForwarders.size());
		}

		return modules;
	}

	/**
	* Rebuilds the BoundImport directory. The rebuilded BoundImport directory can then be
	* written back to a PE file.
	* @param vBuffer Buffer where the rebuilt BoundImport directory will be stored.
	* @param fMakeValid If this flag is true a valid directory will be produced.
	**/
	void BoundImportDirectory::rebuild(std::vector<std::uint8_t>& vBuffer, bool fMakeValid) const
	{
		std::map<std::string, std::uint16_t> filename_offsets;

		OutputBuffer obBuffer(vBuffer);

		std::uint16_t ulNameOffset = static_cast<std::uint16_t>((totalModules() + 1) * PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size());

		for (unsigned int i=0;i<m_vIbd.size();i++)
		{
			obBuffer << m_vIbd[i].ibdDescriptor.TimeDateStamp;

			// Recalculate the offsets if a valid directory is wanted.
			if (fMakeValid)
			{
				if (filename_offsets.find(m_vIbd[i].strModuleName) == filename_offsets.end())
				{
					filename_offsets[m_vIbd[i].strModuleName] = ulNameOffset;
					obBuffer << ulNameOffset;
					ulNameOffset += static_cast<std::uint16_t>(m_vIbd[i].strModuleName.size() + 1);
				}
				else
				{
					obBuffer << filename_offsets[m_vIbd[i].strModuleName];
				}
			}
			else // Otherwise just copy the old values into the buffer.
			{
				obBuffer << m_vIbd[i].ibdDescriptor.OffsetModuleName;
			}

			obBuffer << m_vIbd[i].ibdDescriptor.NumberOfModuleForwarderRefs;

			for (int j=0;j<calcNumberOfModuleForwarderRefs(i);j++)
			{
				obBuffer << m_vIbd[i].moduleForwarders[j].ibdDescriptor.TimeDateStamp;

				if (fMakeValid)
				{
					if (filename_offsets.find(m_vIbd[i].strModuleName) == filename_offsets.end())
					{
						filename_offsets[m_vIbd[i].moduleForwarders[j].strModuleName] = ulNameOffset;
						obBuffer << ulNameOffset;
						ulNameOffset += static_cast<std::uint16_t>(m_vIbd[i].moduleForwarders[j].strModuleName.size() + 1);
					}
					else
					{
						obBuffer << filename_offsets[m_vIbd[i].moduleForwarders[j].strModuleName];
					}
				}
				else // Otherwise just copy the old values into the buffer.
				{
					obBuffer << m_vIbd[i].moduleForwarders[j].ibdDescriptor.OffsetModuleName;
				}

				obBuffer << m_vIbd[i].moduleForwarders[j].ibdDescriptor.NumberOfModuleForwarderRefs;
			}
		}

		obBuffer << static_cast<std::uint32_t>(0);
		obBuffer << static_cast<std::uint16_t>(0);
		obBuffer << static_cast<std::uint16_t>(0);

		for (unsigned int i=0;i<m_vIbd.size();i++)
		{
			if (filename_offsets.find(m_vIbd[i].strModuleName) != filename_offsets.end())
			{
				obBuffer.add(getModuleName(i).c_str(), static_cast<unsigned long>(getModuleName(i).size() + 1));
				filename_offsets.erase(m_vIbd[i].strModuleName);
			}

			for (int j=0;j<calcNumberOfModuleForwarderRefs(i);j++)
			{
				if (filename_offsets.find(getModuleName(i, j)) != filename_offsets.end())
				{
					obBuffer.add(getModuleName(i, j).c_str(), static_cast<unsigned long>(getModuleName(i, j).size() + 1));
					filename_offsets.erase(getModuleName(i, j));
				}
			}
		}
	}

	/**
	* Removes all bound import files.
	**/
	void BoundImportDirectory::clear()
	{
		m_vIbd.clear();
	}

	/**
	* Removes a field specified by the parameter filename from the BoundImport directory.
	* @param strModuleName Name of the file whose field will be removed from the BoundImport directory.
	**/
	void BoundImportDirectory::removeBoundImport(const std::string& strModuleName)
	{
		m_vIbd.erase(
			std::remove_if(
				m_vIbd.begin(),
				m_vIbd.end(),
				[&](const auto& i) { return i.equal(strModuleName); }
			),
			m_vIbd.end()
		);
	}

	/**
	* Returns the size of the rebuilt BoundImportDirectory.
	* @return Size of the rebuilt BoundImportDirectory.
	**/
	unsigned int BoundImportDirectory::size() const
	{
		unsigned int size2 = PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size();

		std::set<std::string> filenames;

		for (unsigned int i = 0; i < m_vIbd.size(); i++)
		{
			filenames.insert(m_vIbd[i].strModuleName);

			size2 += PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size();

			for (unsigned int j = 0; j < m_vIbd[i].moduleForwarders.size(); j++)
			{
				filenames.insert(m_vIbd[i].moduleForwarders[j].strModuleName);

				size2 += PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR::size();
			}
		}

		for (std::set<std::string>::iterator iter = filenames.begin(); iter != filenames.end(); ++iter)
		{
			size2 += static_cast<unsigned int>(iter->size()) + 1;
		}

		return size2;
	}

	/**
	* @param strFilename Name of the file.
	* @param dwOffset File offset the bound importdirectory will be written to.
	* @param fMakeValid If this flag is true a valid directory will be produced.
	**/
	int BoundImportDirectory::write(const std::string& strFilename, std::uint32_t dwOffset,  bool fMakeValid) const
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
		rebuild(vBuffer, fMakeValid);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<std::streamsize>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Retrieves the value of the TimeDateStamp value of a bound import field.
	* @param dwBidnr Number of the bound import field.
	* @return Value of the TimeDateStamp of the bound import field.
	**/
	std::uint32_t BoundImportDirectory::getTimeDateStamp(std::uint32_t dwBidnr) const
	{
		return m_vIbd[dwBidnr].ibdDescriptor.TimeDateStamp;
	}

	/**
	* Retrieves the value of the OffsetModuleName value of a bound import field.
	* @param dwBidnr Number of the bound import field.
	* @return Value of the OffsetModuleName of the bound import field.
	**/
	std::uint16_t BoundImportDirectory::getOffsetModuleName(std::uint32_t dwBidnr) const
	{
		return m_vIbd[dwBidnr].ibdDescriptor.OffsetModuleName;
	}

	/**
	* Retrieves the value of the NumberOfModuleForwarderRefs value of a bound import field.
	* @param dwBidnr Number of the bound import field.
	* @return Value of the NumberOfModuleForwarderRefs of the bound import field.
	**/
	std::uint16_t BoundImportDirectory::getNumberOfModuleForwarderRefs(std::uint32_t dwBidnr) const
	{
		return m_vIbd[dwBidnr].ibdDescriptor.NumberOfModuleForwarderRefs;
	}

	/**
	* Retrieves the value of the ModuleName value of a bound import field.
	* @param dwBidnr Number of the bound import field.
	* @return Value of the ModuleName of the bound import field.
	**/
	std::string BoundImportDirectory::getModuleName(std::uint32_t dwBidnr) const
	{
		return m_vIbd[dwBidnr].strModuleName;
	}

	/**
	* Changes the TimeDateStamp value of an existing bound import field.
	* @param dwBidnr Number of the bound import field which will be changed.
	* @param dwTds New value of the TimeDateStamp of the bound import field.
	**/
	void BoundImportDirectory::setTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t dwTds)
	{
		m_vIbd[dwBidnr].ibdDescriptor.TimeDateStamp = dwTds;
	}

	/**
	* Changes the OffsetModuleName value of an existing bound import field.
	* @param dwBidnr Number of the bound import field which will be changed.
	* @param wOmn New value of the OffsetModuleName of the bound import field.
	**/
	void BoundImportDirectory::setOffsetModuleName(std::uint32_t dwBidnr, std::uint16_t wOmn)
	{
		m_vIbd[dwBidnr].ibdDescriptor.OffsetModuleName = wOmn;
	}

	/**
	* Changes the NumberOfModuleForwarderRefs value of an existing bound import field.
	* @param dwBidnr Number of the bound import field which will be changed.
	* @param wMfr New value of the NumberOfModuleForwarderRefs of the bound import field.
	**/
	void BoundImportDirectory::setNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint16_t wMfr)
	{
		m_vIbd[dwBidnr].ibdDescriptor.NumberOfModuleForwarderRefs = wMfr;
	}

	/**
	* Changes the ModuleName value of an existing bound import field.
	* @param dwBidnr Number of the bound import field which will be changed.
	* @param strModuleName New value of the ModuleName of the bound import field.
	**/
	void BoundImportDirectory::setModuleName(std::uint32_t dwBidnr, const std::string& strModuleName)
	{
		m_vIbd[dwBidnr].strModuleName = strModuleName;
	}

	std::uint32_t BoundImportDirectory::getTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const
	{
		return m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.TimeDateStamp;
	}

	std::uint16_t BoundImportDirectory::getOffsetModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const
	{
		return m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.OffsetModuleName;
	}

	std::uint16_t BoundImportDirectory::getNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const
	{
		return m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.NumberOfModuleForwarderRefs;
	}

	std::string BoundImportDirectory::getModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const
	{
		return m_vIbd[dwBidnr].moduleForwarders[forwardedModule].strModuleName;
	}

	void BoundImportDirectory::setTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint32_t dwTds)
	{
		m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.TimeDateStamp = dwTds;
	}

	void BoundImportDirectory::setOffsetModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint16_t wOmn)
	{
		m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.OffsetModuleName = wOmn;
	}

	void BoundImportDirectory::setNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint16_t wMfr)
	{
		m_vIbd[dwBidnr].moduleForwarders[forwardedModule].ibdDescriptor.NumberOfModuleForwarderRefs = wMfr;
	}

	void BoundImportDirectory::setModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule, const std::string& strModuleName)
	{
		m_vIbd[dwBidnr].moduleForwarders[forwardedModule].strModuleName = strModuleName;
	}

	std::uint16_t BoundImportDirectory::calcNumberOfModuleForwarderRefs(std::uint32_t dwBidnr) const
	{
		return static_cast<std::uint16_t>(m_vIbd[dwBidnr].moduleForwarders.size());
	}

	void BoundImportDirectory::addForwardedModule(std::uint32_t dwBidnr, const std::string& name, std::uint32_t timeStamp, std::uint16_t offsetModuleName, std::uint16_t forwardedModules)
	{
		// XXX: Maybe test if there are already 0xFFFF forwarded modules.
		// XXX: Check for duplicate entries. Is it also necessary to check
		//      non-forwarded entries and forwarded entries in other non-forwarded
		//      entries?
		// XXX: Can forwarders forward recursively?

		PELIB_IMAGE_BOUND_DIRECTORY ibdCurrent;
		ibdCurrent.strModuleName = name;
		ibdCurrent.ibdDescriptor.TimeDateStamp = timeStamp;
		ibdCurrent.ibdDescriptor.OffsetModuleName = offsetModuleName;
		ibdCurrent.ibdDescriptor.NumberOfModuleForwarderRefs = forwardedModules;

		m_vIbd[dwBidnr].moduleForwarders.push_back(ibdCurrent);
	}

	void BoundImportDirectory::removeForwardedModule(std::uint32_t dwBidnr, std::uint16_t forwardedModule)
	{
		m_vIbd[dwBidnr].moduleForwarders.erase(m_vIbd[dwBidnr].moduleForwarders.begin() + forwardedModule);
	}
}
