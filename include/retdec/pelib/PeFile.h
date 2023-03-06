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

#ifndef RETDEC_PELIB_PEFILE_H
#define RETDEC_PELIB_PEFILE_H

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/ImageLoader.h"
#include "retdec/pelib/ImportDirectory.h"
#include "retdec/pelib/ExportDirectory.h"
#include "retdec/pelib/BoundImportDirectory.h"
#include "retdec/pelib/ResourceDirectory.h"
#include "retdec/pelib/RelocationsDirectory.h"
#include "retdec/pelib/ComHeaderDirectory.h"
#include "retdec/pelib/IatDirectory.h"
#include "retdec/pelib/DebugDirectory.h"
#include "retdec/pelib/TlsDirectory.h"
#include "retdec/pelib/RichHeader.h"
#include "retdec/pelib/CoffSymbolTable.h"
#include "retdec/pelib/DelayImportDirectory.h"
#include "retdec/pelib/SecurityDirectory.h"
#include "retdec/pelib/ConfigDirectory.h"

namespace PeLib
{
	/**
	* This class represents the common structures of PE and PE+ files.
	**/
	class PeFile
	{
		protected:
		  std::string m_filename; ///< Name of the current file.
		  ImageLoader m_imageLoader;
		  RichHeader m_richheader; ///< Rich header of the current file.
		  CoffSymbolTable m_coffsymtab; ///< Symbol table of the current file.
		  SecurityDirectory m_secdir; ///< Security directory of the current file.
		public:
		  virtual ~PeFile();

		  /// Returns the name of the current file.
		  virtual std::string getFileName() const = 0; // EXPORT
		  /// Changes the name of the current file.
		  virtual void setFileName(const std::string & strFilename) = 0; // EXPORT

		  /// Reads the export directory of the current file from disc.
		  virtual int readExportDirectory() = 0; // EXPORT
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
		  virtual int readCoffSymbolTable(ByteBuffer & fileData) = 0; // EXPORT
		  /// Reads delay import directory of the current file.
		  virtual int readDelayImportDirectory() = 0; // EXPORT
		  /// Reads security directory of the current file.
		  virtual int readSecurityDirectory() = 0; // EXPORT
		  /// Returns a loader error, if there was any
		  virtual LoaderError loaderError() const = 0;

		  virtual unsigned int getBits() const = 0;

		  /// Accessor function for the image loader
		  const ImageLoader & imageLoader() const;
		  /// Accessor function for the MZ header.
		  ImageLoader & imageLoader(); // EXPORT

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
	class PeFileT : public PeFile
	{
		private:

		std::ifstream m_ifStream;                         ///< Valid if we opened the file stream ourself
		std::istream& m_iStream;                          ///< Can also reference m_ifStream

		ExportDirectory m_expdir;                         ///< Export directory of the current file.
		ImportDirectory m_impdir;                         ///< Import directory of the current file.
		BoundImportDirectory m_boundimpdir;               ///< BoundImportDirectory of the current file.
		ResourceDirectory m_resdir;                       ///< ResourceDirectory of the current file.
		RelocationsDirectory m_relocs;                    ///< Relocations directory of the current file.
		ComHeaderDirectory m_comdesc;                     ///< COM+ descriptor directory of the current file.
		IatDirectory m_iat;                               ///< Import address table of the current file.
		DebugDirectory m_debugdir;                        ///< Debug directory of the current file.
		DelayImportDirectory m_delayimpdir;               ///< Delay import directory of the current file.
		TlsDirectory m_tlsdir;                            ///< TLS directory of the current file.
		ConfigDirectory m_configdir;                      ///< Load Config directory

		public:

		PeFileT(const std::string& strFileName);
		PeFileT(std::istream& stream);
		PeFileT();                                        /// Default constructor which exists only for the sake of allowing to construct files without filenames.
		virtual ~PeFileT() {}

		/// Load the PE file using the already-open stream
		int loadPeHeaders(bool loadHeadersOnly = false);

		/// Alternate load - can be used when the data are already loaded to memory to prevent duplicating large buffers
		int loadPeHeaders(ByteBuffer & fileData, bool loadHeadersOnly = false);

		/// returns PEFILE64 or PEFILE32
		int getFileType() const;

		/// Returns the name of the current file.
		std::string getFileName() const;
		/// Changes the name of the current file.
		void setFileName(const std::string & strFilename);

		/// Reads the export directory of the current file from disc.
		int readExportDirectory() ;
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
		int readCoffSymbolTable(ByteBuffer & fileData);
		/// Reads delay import directory of the current file.
		int readDelayImportDirectory() ;
		/// Reads the security directory of the current file.
		int readSecurityDirectory() ;
		int readLoadConfigDirectory();

		/// Checks the entry point code
		LoaderError checkEntryPointErrors() const;
		LoaderError checkForInMemoryLayout(LoaderError ldrError) const;
		bool isFirstSectionZeroed() const;

		/// Returns a loader error, if there was any
		LoaderError loaderError() const;

		unsigned int getBits() const
		{
			return m_imageLoader.getImageBitability();
		}

		/// Accessor function for the export directory.
		const ExportDirectory & expDir() const;
		/// Accessor function for the export directory.
		ExportDirectory & expDir(); // EXPORT

		/// Accessor function for the import directory.
		const ImportDirectory & impDir() const;
		/// Accessor function for the import directory.
		ImportDirectory & impDir();

		/// Accessor function for the bound import directory.
		const BoundImportDirectory & boundImpDir() const;
		/// Accessor function for the bound import directory.
		BoundImportDirectory & boundImpDir(); // EXPORT

		/// Accessor function for the resource directory.
		const ResourceDirectory & resDir() const;
		/// Accessor function for the resource directory.
		ResourceDirectory & resDir(); // EXPORT

		/// Accessor function for the relocations directory.
		const RelocationsDirectory & relocDir() const;
		/// Accessor function for the relocations directory.
		RelocationsDirectory & relocDir(); // EXPORT

		/// Accessor function for the COM+ descriptor directory.
		const ComHeaderDirectory & comDir() const;
		/// Accessor function for the COM+ descriptor directory.
		ComHeaderDirectory & comDir(); // EXPORT

		/// Accessor function for the IAT directory.
		const IatDirectory & iatDir() const;
		/// Accessor function for the IAT directory.
		IatDirectory & iatDir(); // EXPORT

		/// Accessor function for the debug directory.
		const DebugDirectory & debugDir() const;
		/// Accessor function for the debug directory.
		DebugDirectory & debugDir(); // EXPORT

		/// Accessor function for the delay import directory.
		const DelayImportDirectory & delayImports() const;
		/// Accessor function for the delay import directory.
		DelayImportDirectory & delayImports(); // EXPORT

		/// Accessor function for the TLS directory.
		const TlsDirectory & tlsDir() const;
		/// Accessor function for the TLS directory.
		TlsDirectory & tlsDir();

		const ConfigDirectory& configDir() const;
		ConfigDirectory& configDir();
	};
}

#endif
