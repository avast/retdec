/*
* PeLib.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "retdec/pelib/PeFile.h"

namespace PeLib
{
	PeFileT::PeFileT(const std::string& strFileName) : m_iStream(m_ifStream)
	{
		setFileName(strFileName);
	}

	PeFileT::PeFileT(std::istream& stream) : m_iStream(stream)
	{}

	PeFileT::PeFileT() : m_iStream(m_ifStream)
	{}

	PeFile::~PeFile()
	{}

	int PeFileT::loadPeHeaders(bool loadHeadersOnly)
	{
		return m_imageLoader.Load(m_iStream, loadHeadersOnly);
	}

	int PeFileT::loadPeHeaders(ByteBuffer & fileData, bool loadHeadersOnly)
	{
		return m_imageLoader.Load(fileData, loadHeadersOnly);
	}

	/// returns PEFILE64 or PEFILE32
	int PeFileT::getFileType() const
	{
		std::uint16_t machine = m_imageLoader.getMachine();
		std::uint16_t magic = m_imageLoader.getMagic();

		if((machine == PELIB_IMAGE_FILE_MACHINE_AMD64 || machine == PELIB_IMAGE_FILE_MACHINE_IA64) && magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return PEFILE64;
		}

		if(machine == PELIB_IMAGE_FILE_MACHINE_I386 && magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			return PEFILE32;
		}

		return PEFILE_UNKNOWN;
	}

	/**
	* @return A reference to the file's image loader.
	**/

	const ImageLoader & PeFile::imageLoader() const
	{
		return m_imageLoader;
	}

	/**
	* @return A reference to the file's image loader.
	**/

	ImageLoader & PeFile::imageLoader()
	{
		return m_imageLoader;
	}

	const RichHeader& PeFile::richHeader() const
	{
		return m_richheader;
	}

	RichHeader& PeFile::richHeader()
	{
		return m_richheader;
	}

	const CoffSymbolTable& PeFile::coffSymTab() const
	{
		return m_coffsymtab;
	}

	CoffSymbolTable& PeFile::coffSymTab()
	{
		return m_coffsymtab;
	}

	const SecurityDirectory& PeFile::securityDir() const
	{
		return m_secdir;
	}

	SecurityDirectory& PeFile::securityDir()
	{
		return m_secdir;
	}

	/**
	* @return A reference to the file's import directory.
	**/
	const ImportDirectory & PeFileT::impDir() const
	{
		return m_impdir;
	}

	/**
	* @return A reference to the file's import directory.
	**/
	ImportDirectory & PeFileT::impDir()
	{
		return m_impdir;
	}

	const TlsDirectory & PeFileT::tlsDir() const
	{
		return m_tlsdir;
	}

	TlsDirectory & PeFileT::tlsDir()
	{
		return m_tlsdir;
	}

	/**
	* @return A reference to the file's delay import directory.
	**/
	const DelayImportDirectory & PeFileT::delayImports() const
	{
		return m_delayimpdir;
	}

	/**
	* @return A reference to the file's delay import directory.
	**/
	DelayImportDirectory & PeFileT::delayImports()
	{
		return m_delayimpdir;
	}

	/**
	* @return A reference to the file's export directory.
	**/
	const ExportDirectory & PeFileT::expDir() const
	{
		return m_expdir;
	}

	/**
	* @return A reference to the file's export directory.
	**/
	ExportDirectory & PeFileT::expDir()
	{
		return m_expdir;
	}

	/**
	* @return A reference to the file's bound import directory.
	**/
	const BoundImportDirectory & PeFileT::boundImpDir() const
	{
		return m_boundimpdir;
	}

	/**
	* @return A reference to the file's bound import directory.
	**/
	BoundImportDirectory & PeFileT::boundImpDir()
	{
		return m_boundimpdir;
	}

	/**
	* @return A reference to the file's resource directory.
	**/
	const ResourceDirectory & PeFileT::resDir() const
	{
		return m_resdir;
	}

	/**
	* @return A reference to the file's resource directory.
	**/
	ResourceDirectory & PeFileT::resDir()
	{
		return m_resdir;
	}

	/**
	* @return A reference to the file's relocations directory.
	**/
	const RelocationsDirectory & PeFileT::relocDir() const
	{
		return m_relocs;
	}

	/**
	* @return A reference to the file's relocations directory.
	**/
	RelocationsDirectory & PeFileT::relocDir()
	{
		return m_relocs;
	}

	/**
	* @return A reference to the file's COM+ descriptor directory.
	**/
	const ComHeaderDirectory & PeFileT::comDir() const
	{
		return m_comdesc;
	}

	/**
	* @return A reference to the file's COM+ descriptor directory.
	**/
	ComHeaderDirectory & PeFileT::comDir()
	{
		return m_comdesc;
	}

	const IatDirectory & PeFileT::iatDir() const
	{
		return m_iat;
	}

	IatDirectory & PeFileT::iatDir()
	{
		return m_iat;
	}

	const DebugDirectory & PeFileT::debugDir() const
	{
		return m_debugdir;
	}

	DebugDirectory & PeFileT::debugDir()
	{
		return m_debugdir;
	}

	/**
	* @return Filename of the current file.
	**/
	std::string PeFileT::getFileName() const
	{
		return m_filename;
	}

	/**
	* @param strFilename New filename.
	**/
	void PeFileT::setFileName(const std::string & strFilename)
	{
		m_filename = strFilename;
		if (m_ifStream.is_open())
		{
			m_ifStream.close();
		}
		m_ifStream.open(m_filename, std::ifstream::binary);
	}

	int PeFileT::readRichHeader(std::size_t offset, std::size_t size, bool ignoreInvalidKey)
	{
		return richHeader().read(m_iStream, offset, size, ignoreInvalidKey);
	}

	int PeFileT::readCoffSymbolTable(ByteBuffer & fileData)
	{
		if(m_imageLoader.getPointerToSymbolTable() && m_imageLoader.getNumberOfSymbols())
		{
			return coffSymTab().read(
				fileData,
				m_imageLoader.getPointerToSymbolTable(),
				m_imageLoader.getNumberOfSymbols() * PELIB_IMAGE_SIZEOF_COFF_SYMBOL);
		}
		return ERROR_COFF_SYMBOL_TABLE_DOES_NOT_EXIST;
	}

	int PeFileT::readExportDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT))
		{
			return expDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readImportDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT))
		{
			return impDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readResourceDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE))
		{
			return resDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readSecurityDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY))
		{
			return securityDir().read(m_iStream,
									  m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY),
									  m_imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY));
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readRelocationsDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC))
		{
			return relocDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readDebugDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG))
		{
			return debugDir().read(m_iStream, m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readTlsDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_TLS))
		{
			return tlsDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readBoundImportDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT))
		{
			return boundImpDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readIatDirectory()
	{
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IAT))
		{
			return iatDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readDelayImportDirectory()
	{
		// Note: Delay imports can have arbitrary size and Windows loader will still load them
		if(m_imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT))
		{
			return delayImports().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	int PeFileT::readComHeaderDirectory()
	{
		// Need to do this regardless of NumberOf
		if(m_imageLoader.getComDirRva() && m_imageLoader.getComDirSize())
		{
			return comDir().read(m_imageLoader);
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	LoaderError PeFileT::checkEntryPointErrors() const
	{
		ImageLoader & imgLoader = const_cast<ImageLoader &>(m_imageLoader);
		std::uint32_t addressOfEntryPoint = m_imageLoader.getAddressOfEntryPoint();
		std::uint32_t sizeOfImage = m_imageLoader.getSizeOfImageAligned();

		if(addressOfEntryPoint >= sizeOfImage)
		{
			return LDR_ERROR_ENTRY_POINT_OUT_OF_IMAGE;
		}

		// Only check PE files compiled for i386 or x64 processors.
		if (m_imageLoader.getMachine() == PELIB_IMAGE_FILE_MACHINE_I386 || m_imageLoader.getMachine() == PELIB_IMAGE_FILE_MACHINE_AMD64)
		{
			// Only if there are no TLS callbacks
			if(m_tlsdir.getCallbacks().size() == 0)
			{
				std::uint64_t entryPointCode[2] = {0, 0};

				// Check if 16 bytes of code are available in the file
				if ((addressOfEntryPoint + sizeof(entryPointCode)) < sizeOfImage)
				{
					// Read the entry point code
					imgLoader.readImage(entryPointCode, addressOfEntryPoint, sizeof(entryPointCode));

					// Zeroed instructions at entry point map either to "add [eax], al" (i386) or "add [rax], al" (AMD64).
					// Neither of these instructions makes sense on the entry point. We check 16 bytes of the entry point,
					// in order to make sure it's really a corruption.
					if ((entryPointCode[0] | entryPointCode[1]) == 0)
					{
						return LDR_ERROR_ENTRY_POINT_ZEROED;
					}
				}
			}
		}

		return LDR_ERROR_NONE;
	}

	LoaderError PeFileT::checkForInMemoryLayout(LoaderError ldrError) const
	{
		std::uint64_t ulFileSize = fileSize(m_iStream);
		std::uint64_t sizeOfImage = m_imageLoader.getSizeOfImage();

		// The file size must be greater or equal to SizeOfImage
		if(ulFileSize >= sizeOfImage && m_imageLoader.getNumberOfSections() != 0)
		{
			std::uint32_t sectionAlignment = m_imageLoader.getSectionAlignment();
			std::uint32_t fileAlignment = m_imageLoader.getFileAlignment();
			std::uint32_t sizeOfHeaders = m_imageLoader.getSizeOfHeaders();

			// SectionAlignment must be greater than file alignment
			if(sectionAlignment >= PELIB_PAGE_SIZE && sectionAlignment > fileAlignment)
			{
				// SizeOfHeaders must be smaller than SectionAlignment
				if(sizeOfHeaders < sectionAlignment)
				{
					std::size_t headerDataSize = sectionAlignment - sizeOfHeaders;

					// Read the entire after-header-data
					ByteBuffer headerData(headerDataSize);
					m_iStream.seekg(sizeOfHeaders, std::ios::beg);
					m_iStream.read(reinterpret_cast<char *>(headerData.data()), headerDataSize);

					// Check whether there are zeros only. If yes, we consider
					// the file to be an in-memory image
					if(std::all_of(headerData.begin(), headerData.end(), [](char item) { return item == 0; }))
						ldrError = LDR_ERROR_INMEMORY_IMAGE;
				}
			}
		}

		return ldrError;
	}

	// Returns an error code indicating loader problem. We check every part of the PE file
	// for possible loader problem. If anything wrong was found, we report it
	LoaderError PeFileT::loaderError() const
	{
		// Check for problems in image loader
		LoaderError ldrError = imageLoader().loaderError();

		// Check the loader error
		if (ldrError == LDR_ERROR_NONE)
			ldrError = coffSymTab().loaderError();

		// Check errors in import directory
		if (ldrError == LDR_ERROR_NONE)
			ldrError = impDir().loaderError();

		// Check errors in resource directory
		if (ldrError == LDR_ERROR_NONE)
			ldrError = resDir().loaderError();

		// Check errors in relocations directory
		if (ldrError == LDR_ERROR_NONE)
			ldrError = relocDir().loaderError();

		// Check errors in security directory
		if (ldrError == LDR_ERROR_NONE)
			ldrError = securityDir().loaderError();

		// Check errors in entry point
		if (ldrError == LDR_ERROR_NONE)
			ldrError = checkEntryPointErrors();

		// If there was a loaded error, we'll check whether
		// the file can't actually be an in-memory version
		if(ldrError != LDR_ERROR_NONE)
			ldrError = checkForInMemoryLayout(ldrError);

		// Nothing wrond found
		return ldrError;
	}
}
