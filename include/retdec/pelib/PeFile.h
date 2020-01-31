/*
* PeFile.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef PEFILE_H
#define PEFILE_H

#include "pelib/PeLibInc.h"
#include "pelib/MzHeader.h"
#include "pelib/PeHeader.h"
#include "pelib/ImportDirectory.h"
#include "pelib/ExportDirectory.h"
#include "pelib/BoundImportDirectory.h"
#include "pelib/ResourceDirectory.h"
#include "pelib/RelocationsDirectory.h"
#include "pelib/ComHeaderDirectory.h"
#include "pelib/IatDirectory.h"
#include "pelib/DebugDirectory.h"
#include "pelib/TlsDirectory.h"
#include "pelib/RichHeader.h"
#include "pelib/CoffSymbolTable.h"
#include "pelib/DelayImportDirectory.h"
#include "pelib/SecurityDirectory.h"

namespace PeLib
{
	class PeFile32;
	class PeFile64;

	/**
	* Visitor base class for PeFiles.
	**/
	class PeFileVisitor
	{
		public:
		  virtual void callback(PeFile32 &file){(void) file; /* avoid warning about unused parameter */}
		  virtual void callback(PeFile64 &file){(void) file; /* avoid warning about unused parameter */}
		  virtual ~PeFileVisitor(){}
	};

	/**
	* Traits class that's used to decide of what type the PeHeader in a PeFile is.
	**/
	template<int>
	struct PeFile_Traits;

	template<>
	struct PeFile_Traits<32>
	{
		typedef PeHeader32 PeHeader32_64;
	};

	template<>
	struct PeFile_Traits<64>
	{
		typedef PeHeader64 PeHeader32_64;
	};

	/**
	* This class represents the common structures of PE and PE+ files.
	**/
	class PeFile
	{
		protected:
		  std::string m_filename; ///< Name of the current file.
		  MzHeader m_mzh; ///< MZ header of the current file.
		  RichHeader m_richheader; ///< Rich header of the current file.
		  CoffSymbolTable m_coffsymtab; ///< Symbol table of the current file.
		  SecurityDirectory m_secdir; ///< Security directory of the current file.
		public:
		  virtual ~PeFile();

		  /// Returns the name of the current file.
		  virtual std::string getFileName() const = 0; // EXPORT
		  /// Changes the name of the current file.
		  virtual void setFileName(std::string strFilename) = 0; // EXPORT

		  virtual void visit(PeFileVisitor &v) = 0;

		  /// Reads the MZ header of the current file from disc.
		  virtual int readMzHeader() = 0; // EXPORT
		  /// Reads the export directory of the current file from disc.
		  virtual int readExportDirectory() = 0; // EXPORT
		  /// Reads the PE header of the current file from disc.
		  virtual int readPeHeader()  = 0; // EXPORT
		  /// Reads the import directory of the current file from disc.
		  virtual int readImportDirectory() = 0; // EXPORT
		  /// Reads the bound import directory of the current file from disc.
		  virtual int readBoundImportDirectory() = 0; // EXPORT
		  /// Reads the resource directory of the current file from disc.
		  virtual int readResourceDirectory() = 0; // EXPORT
		  /// Reads the relocations directory of the current file from disc.
		  virtual int readRelocationsDirectory() = 0; // EXPORT
		  /// Reads the COM+ descriptor directory of the current file from disc.
		  virtual int readComHeaderDirectory() = 0; // EXPORT
		  /// Reads the IAT directory of the current file from disc.
		  virtual int readIatDirectory() = 0; // EXPORT
		  /// Reads the Debug directory of the current file.
		  virtual int readDebugDirectory() = 0; // EXPORT
		  /// Reads the TLS directory of the current file.
		  virtual int readTlsDirectory() = 0; // EXPORT
		  /// Reads rich header of the current file.
		  virtual int readRichHeader(std::size_t offset, std::size_t size, bool ignoreInvalidKey = false)  = 0; // EXPORT
		  /// Reads the COFF symbol table of the current file.
		  virtual int readCoffSymbolTable() = 0; // EXPORT
		  /// Reads delay import directory of the current file.
		  virtual int readDelayImportDirectory() = 0; // EXPORT
		  /// Reads security directory of the current file.
		  virtual int readSecurityDirectory() = 0; // EXPORT
		  /// Returns a loader error, if there was any
		  virtual LoaderError loaderError() const = 0;

		  virtual unsigned int getBits() const = 0;

		  /// Accessor function for the MZ header.
		  const MzHeader& mzHeader() const;
		  /// Accessor function for the MZ header.
		  MzHeader& mzHeader(); // EXPORT

		  /// Accessor function for the Rich header.
		  const RichHeader& richHeader() const;
		  /// Accessor function for the Rich header.
		  RichHeader& richHeader(); // EXPORT

		  /// Accessor function for the COFF symbol table.
		  const CoffSymbolTable& coffSymTab() const;
		  /// Accessor function for the COFF symbol table.
		  CoffSymbolTable& coffSymTab(); // EXPORT

		  /// Accessor function for the security directory.
		  const SecurityDirectory& securityDir() const;
		  /// Accessor function for the security directory.
		  SecurityDirectory& securityDir();
	};

	/**
	* This class implements the common structures of PE and PE+ files.
	**/
	template<int bits>
	class PeFileT : public PeFile
	{
		typedef typename PeFile_Traits<bits>::PeHeader32_64 PeHeader32_64;

		private:
	      std::ifstream m_ifStream;
	      std::istream& m_iStream;

		  PeHeader32_64 m_peh; ///< PE header of the current file.
		  ExportDirectoryT<bits> m_expdir; ///< Export directory of the current file.
		  ImportDirectory<bits> m_impdir; ///< Import directory of the current file.
		  BoundImportDirectoryT<bits> m_boundimpdir; ///< BoundImportDirectory of the current file.
		  ResourceDirectoryT<bits> m_resdir; ///< ResourceDirectory of the current file.
		  RelocationsDirectoryT<bits> m_relocs; ///< Relocations directory of the current file.
		  ComHeaderDirectoryT<bits> m_comdesc; ///< COM+ descriptor directory of the current file.
		  IatDirectoryT<bits> m_iat; ///< Import address table of the current file.
		  DebugDirectoryT<bits> m_debugdir; ///< Debug directory of the current file.
		  DelayImportDirectory<bits> m_delayimpdir; ///< Delay import directory of the current file.
		  TlsDirectory<bits> m_tlsdir; ///< TLS directory of the current file.

		public:
		  /// Default constructor which exists only for the sake of allowing to construct files without filenames.
		  PeFileT();

		  virtual ~PeFileT() {}

		  /// Initializes a PeFile with a filename
		  explicit PeFileT(const std::string& strFilename);
		  PeFileT(std::istream& stream);

		  /// Returns the name of the current file.
		  std::string getFileName() const;
		  /// Changes the name of the current file.
		  void setFileName(std::string strFilename);

		  /// Reads the MZ header of the current file from disc.
		  int readMzHeader() ;
		  /// Reads the export directory of the current file from disc.
		  int readExportDirectory() ;
		  /// Reads the PE header of the current file from disc.
		  int readPeHeader() ;
		  /// Reads the import directory of the current file from disc.
		  int readImportDirectory() ;
		  /// Reads the bound import directory of the current file from disc.
		  int readBoundImportDirectory() ;
		  /// Reads the resource directory of the current file from disc.
		  int readResourceDirectory() ;
		  /// Reads the relocations directory of the current file from disc.
		  int readRelocationsDirectory() ;
		  /// Reads the COM+ descriptor directory of the current file from disc.
		  int readComHeaderDirectory() ;
		  /// Reads the IAT directory of the current file from disc.
		  int readIatDirectory() ;
		  /// Reads the Debug directory of the current file.
		  int readDebugDirectory() ;
		  /// Reads the TLS directory of the current file.
		  int readTlsDirectory() ;
		  /// Reads rich header of the current file.
		  int readRichHeader(std::size_t offset, std::size_t size, bool ignoreInvalidKey = false) ;
		  /// Reads the COFF symbol table of the current file.
		  int readCoffSymbolTable() ;
		  /// Reads delay import directory of the current file.
		  int readDelayImportDirectory() ;
		  /// Reads the security directory of the current file.
		  int readSecurityDirectory() ;

		  /// Checks the entry point code
		  LoaderError checkEntryPointErrors() const;

		  /// Returns a loader error, if there was any
		  LoaderError loaderError() const;

		  unsigned int getBits() const
		  {
			  return bits;
		  }

		  /// Accessor function for the PE header.
		  const PeHeader32_64& peHeader() const;
		  /// Accessor function for the PE header.
		  PeHeader32_64& peHeader();

		  /// Accessor function for the export directory.
		  const ExportDirectoryT<bits>& expDir() const;
		  /// Accessor function for the export directory.
		  ExportDirectoryT<bits>& expDir(); // EXPORT

		  /// Accessor function for the import directory.
		  const ImportDirectory<bits>& impDir() const;
		  /// Accessor function for the import directory.
		  ImportDirectory<bits>& impDir();

		  /// Accessor function for the bound import directory.
		  const BoundImportDirectoryT<bits>& boundImpDir() const;
		  /// Accessor function for the bound import directory.
		  BoundImportDirectoryT<bits>& boundImpDir(); // EXPORT

		  /// Accessor function for the resource directory.
		  const ResourceDirectoryT<bits>& resDir() const;
		  /// Accessor function for the resource directory.
		  ResourceDirectoryT<bits>& resDir(); // EXPORT

		  /// Accessor function for the relocations directory.
		  const RelocationsDirectoryT<bits>& relocDir() const;
		  /// Accessor function for the relocations directory.
		  RelocationsDirectoryT<bits>& relocDir(); // EXPORT

		  /// Accessor function for the COM+ descriptor directory.
		  const ComHeaderDirectoryT<bits>& comDir() const;
		  /// Accessor function for the COM+ descriptor directory.
		  ComHeaderDirectoryT<bits>& comDir(); // EXPORT

		  /// Accessor function for the IAT directory.
		  const IatDirectoryT<bits>& iatDir() const;
		  /// Accessor function for the IAT directory.
		  IatDirectoryT<bits>& iatDir(); // EXPORT

		  /// Accessor function for the debug directory.
		  const DebugDirectoryT<bits>& debugDir() const;
		  /// Accessor function for the debug directory.
		  DebugDirectoryT<bits>& debugDir(); // EXPORT

		  /// Accessor function for the delay import directory.
		  const DelayImportDirectory<bits>& delayImports() const;
		  /// Accessor function for the delay import directory.
		  DelayImportDirectory<bits>& delayImports(); // EXPORT

		  /// Accessor function for the TLS directory.
		  const TlsDirectory<bits>& tlsDir() const;
		  /// Accessor function for the TLS directory.
		  TlsDirectory<bits>& tlsDir();
	};

	/**
	* This class is the main class for handling PE files.
	**/
	class PeFile32 : public PeFileT<32>
	{
		public:
		  /// Default constructor which exists only for the sake of allowing to construct files without filenames.
		  PeFile32();

		  /// Initializes a PeFile with a filename
		  explicit PeFile32(const std::string& strFlename);
		  PeFile32(std::istream& stream);
		  virtual void visit(PeFileVisitor &v) { v.callback( *this ); }
	};

	/**
	* This class is the main class for handling PE+ files.
	**/
	class PeFile64 : public PeFileT<64>
	{
		public:
		  /// Default constructor which exists only for the sake of allowing to construct files without filenames.
		  PeFile64();

		  /// Initializes a PeFile with a filename
		  explicit PeFile64(const std::string& strFlename);
		  PeFile64(std::istream& stream);
		  virtual void visit(PeFileVisitor &v) { v.callback( *this ); }
	};

	//typedef PeFileT<32> PeFile32;
	//typedef PeFileT<64> PeFile64;

	/**
	* @param strFilename Name of the current file.
	**/
	template<int bits>
	PeFileT<bits>::PeFileT(const std::string& strFilename) :
			m_iStream(m_ifStream)
	{
		m_filename = strFilename;
		m_ifStream.open(m_filename, std::ifstream::binary);
	}

	/**
	* @param stream Input stream.
	**/
	template<int bits>
	PeFileT<bits>::PeFileT(std::istream& stream) :
			m_iStream(stream)
	{
 	}

	template<int bits>
	PeFileT<bits>::PeFileT() :
			m_iStream(m_ifStream)
	{
	}

	template<int bits>
	int PeFileT<bits>::readPeHeader()
	{
		return peHeader().read(m_iStream, mzHeader().getAddressOfPeHeader(), mzHeader());
	}

	/**
	* @return A reference to the file's PE header.
	**/
	template<int bits>
	const typename PeFile_Traits<bits>::PeHeader32_64& PeFileT<bits>::peHeader() const
	{
		return m_peh;
	}

	/**
	* @return A reference to the file's PE header.
	**/
	template<int bits>
	typename PeFile_Traits<bits>::PeHeader32_64& PeFileT<bits>::peHeader()
	{
		return m_peh;
	}

	/**
	* @return A reference to the file's import directory.
	**/
	template<int bits>
	const ImportDirectory<bits>& PeFileT<bits>::impDir() const
	{
		return m_impdir;
	}

	/**
	* @return A reference to the file's import directory.
	**/
	template<int bits>
	ImportDirectory<bits>& PeFileT<bits>::impDir()
	{
		return m_impdir;
	}

	template<int bits>
	const TlsDirectory<bits>& PeFileT<bits>::tlsDir() const
	{
		return m_tlsdir;
	}

	template<int bits>
	TlsDirectory<bits>& PeFileT<bits>::tlsDir()
	{
		return m_tlsdir;
	}

	/**
	* @return A reference to the file's delay import directory.
	**/
	template<int bits>
	const DelayImportDirectory<bits>& PeFileT<bits>::delayImports() const
	{
		return m_delayimpdir;
	}

	/**
	* @return A reference to the file's delay import directory.
	**/
	template<int bits>
	DelayImportDirectory<bits>& PeFileT<bits>::delayImports()
	{
		return m_delayimpdir;
	}

	/**
	* @return A reference to the file's export directory.
	**/
	template <int bits>
	const ExportDirectoryT<bits>& PeFileT<bits>::expDir() const
	{
		return m_expdir;
	}

	/**
	* @return A reference to the file's export directory.
	**/
	template <int bits>
	ExportDirectoryT<bits>& PeFileT<bits>::expDir()
	{
		return m_expdir;
	}

	/**
	* @return A reference to the file's bound import directory.
	**/
	template <int bits>
	const BoundImportDirectoryT<bits>& PeFileT<bits>::boundImpDir() const
	{
		return m_boundimpdir;
	}

	/**
	* @return A reference to the file's bound import directory.
	**/
	template <int bits>
	BoundImportDirectoryT<bits>& PeFileT<bits>::boundImpDir()
	{
		return m_boundimpdir;
	}

	/**
	* @return A reference to the file's resource directory.
	**/
	template <int bits>
	const ResourceDirectoryT<bits>& PeFileT<bits>::resDir() const
	{
		return m_resdir;
	}

	/**
	* @return A reference to the file's resource directory.
	**/
	template <int bits>
	ResourceDirectoryT<bits>& PeFileT<bits>::resDir()
	{
		return m_resdir;
	}

	/**
	* @return A reference to the file's relocations directory.
	**/
	template <int bits>
	const RelocationsDirectoryT<bits>& PeFileT<bits>::relocDir() const
	{
		return m_relocs;
	}

	/**
	* @return A reference to the file's relocations directory.
	**/
	template <int bits>
	RelocationsDirectoryT<bits>& PeFileT<bits>::relocDir()
	{
		return m_relocs;
	}

	/**
	* @return A reference to the file's COM+ descriptor directory.
	**/
	template <int bits>
	const ComHeaderDirectoryT<bits>& PeFileT<bits>::comDir() const
	{
		return m_comdesc;
	}

	/**
	* @return A reference to the file's COM+ descriptor directory.
	**/
	template <int bits>
	ComHeaderDirectoryT<bits>& PeFileT<bits>::comDir()
	{
		return m_comdesc;
	}

	template <int bits>
	const IatDirectoryT<bits>& PeFileT<bits>::iatDir() const
	{
		return m_iat;
	}

	template <int bits>
	IatDirectoryT<bits>& PeFileT<bits>::iatDir()
	{
		return m_iat;
	}

	template <int bits>
	const DebugDirectoryT<bits>& PeFileT<bits>::debugDir() const
	{
		return m_debugdir;
	}

	template <int bits>
	DebugDirectoryT<bits>& PeFileT<bits>::debugDir()
	{
		return m_debugdir;
	}

	/**
	* @return Filename of the current file.
	**/
	template<int bits>
	std::string PeFileT<bits>::getFileName() const
	{
		return m_filename;
	}

	/**
	* @param strFilename New filename.
	**/
	template<int bits>
	void PeFileT<bits>::setFileName(std::string strFilename)
	{
		m_filename = strFilename;
		if (m_ifStream.is_open())
		{
			m_ifStream.close();
		}
		m_ifStream.open(m_filename, std::ifstream::binary);
	}

	template<int bits>
	int PeFileT<bits>::readMzHeader()
	{
		return mzHeader().read(m_iStream);
	}

	template<int bits>
	int PeFileT<bits>::readRichHeader(
			std::size_t offset,
			std::size_t size,
			bool ignoreInvalidKey)
	{
		return richHeader().read(m_iStream, offset, size, ignoreInvalidKey);
	}

	template<int bits>
	int PeFileT<bits>::readCoffSymbolTable()
	{
		if (peHeader().getPointerToSymbolTable()
				&& peHeader().getNumberOfSymbols())
		{
			return coffSymTab().read(
					m_iStream,
					static_cast<unsigned int>(peHeader().getPointerToSymbolTable()),
					peHeader().getNumberOfSymbols() * PELIB_IMAGE_SIZEOF_COFF_SYMBOL);
		}
		return ERROR_COFF_SYMBOL_TABLE_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readExportDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 1
			&& peHeader().getIddExportRva())
		{
			return expDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readImportDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 2
			&& peHeader().getIddImportRva())
		{
			return impDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readResourceDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 3
			&& peHeader().getIddResourceRva())
		{
			return resDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readSecurityDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 5
			&& peHeader().getIddSecurityRva()
			&& peHeader().getIddSecuritySize())
		{
			return securityDir().read(
					m_iStream,
					peHeader().getIddSecurityRva(),
					peHeader().getIddSecuritySize());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readRelocationsDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 6
			&& peHeader().getIddBaseRelocRva() && peHeader().getIddBaseRelocSize())
		{
			return relocDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readDebugDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 7
			&& peHeader().getIddDebugRva() && peHeader().getIddDebugSize())
		{
			return debugDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readTlsDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 10
			&& peHeader().getIddTlsRva() && peHeader().getIddTlsSize())
		{
			return tlsDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readBoundImportDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 12
			&& peHeader().getIddBoundImportRva() && peHeader().getIddBoundImportSize())
		{
			return boundImpDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readIatDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 13
			&& peHeader().getIddIatRva() && peHeader().getIddIatSize())
		{
			return iatDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readDelayImportDirectory()
	{
		// Note: Delay imports can have arbitrary size and Windows loader will still load them
		if (peHeader().calcNumberOfRvaAndSizes() >= 14 && peHeader().getIddDelayImportRva() /* && peHeader().getIddDelayImportSize() */)
		{
			return delayImports().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	int PeFileT<bits>::readComHeaderDirectory()
	{
		if (peHeader().calcNumberOfRvaAndSizes() >= 15
			&& peHeader().getIddComHeaderRva() && peHeader().getIddComHeaderSize())
		{
			return comDir().read(m_iStream, peHeader());
		}
		return ERROR_DIRECTORY_DOES_NOT_EXIST;
	}

	template<int bits>
	LoaderError PeFileT<bits>::checkEntryPointErrors() const
	{
		unsigned int uiEntryPointRva = peHeader().getAddressOfEntryPoint();
		std::uint64_t uiOffset = peHeader().rvaToOffset(uiEntryPointRva);
		std::uint64_t entryPointCode[2];

		// No point of reading entry point that is beyond the file size
		std::uint64_t ulFileSize = fileSize(m_iStream);
		if (uiOffset > ulFileSize)
		{
			return LDR_ERROR_ENTRY_POINT_OUT_OF_IMAGE;
		}

		// Only check PE files compiled for i386 or x64 processors.
		if (peHeader().getMachine() == PELIB_IMAGE_FILE_MACHINE_I386 || peHeader().getMachine() == PELIB_IMAGE_FILE_MACHINE_AMD64)
		{
			// Check if 16 bytes of code are available in the file
			if ((uiOffset + sizeof(entryPointCode)) < ulFileSize)
			{
				// Read the entry point code
				m_iStream.seekg(uiOffset, std::ios::beg);
				m_iStream.read((char *)entryPointCode, sizeof(entryPointCode));

				// Zeroed instructions at entry point map either to "add [eax], al" (i386) or "add [rax], al" (AMD64).
				// Neither of these instructions makes sense on the entry point. We check 16 bytes of the entry point,
				// in order to make sure it's really a corruption.
				if ((entryPointCode[0] | entryPointCode[1]) == 0)
				{
					return LDR_ERROR_ENTRY_POINT_ZEROED;
				}
			}
		}

		return LDR_ERROR_NONE;
	}

	// Returns an error code indicating loader problem. We check every part of the PE file
	// for possible loader problem. If anything wrong was found, we report it
	template<int bits>
	LoaderError PeFileT<bits>::loaderError() const
	{
		LoaderError ldrError;

		// Was there a problem in the DOS header?
		ldrError = mzHeader().loaderError();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Was there a problem in the NT headers?
		ldrError = peHeader().loaderError();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Check the loader error
		ldrError = coffSymTab().loaderError();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Check errors in import directory
		ldrError = impDir().loaderError();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Check errors in resource directory
		ldrError = resDir().loaderError();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Check errors in entry point
		ldrError = checkEntryPointErrors();
		if (ldrError != LDR_ERROR_NONE)
			return ldrError;

		// Nothing wrond found
		return LDR_ERROR_NONE;
	}
}

#endif
