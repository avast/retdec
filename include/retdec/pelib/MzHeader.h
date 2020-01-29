/*
* MzHeader.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef MZHEADER_H
#define MZHEADER_H

#include "pelib/PeLibInc.h"

namespace PeLib
{
	/// Class that handles the MZ header of files.
	/**
	* This class can read and modify MZ headers. It provides set- and get functions to access
	* all individual members of a MZ header. Furthermore it's possible to validate and rebuild
	* MZ headers.
	**/
	class MzHeader
	{
		private:
		  PELIB_IMAGE_DOS_HEADER m_idhHeader;       ///< Stores all MZ header information.
		  std::string m_headerString;               ///< MZ header in string representation.
		  LoaderError m_ldrError;

		  /// Reads data from an InputBuffer into a MZ header struct.
		  void read(InputBuffer& ibBuffer);

		  /// Offset of the MZ header in the original file.
		  unsigned int originalOffset;

		  void setLoaderError(LoaderError ldrError);

		public:

		  enum Field {e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
						e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid,
						e_oeminfo, e_res2, e_lfanew};

		  MzHeader();

		  /// Checks if the current MZ header is valid.
		  bool isValid() const; // EXPORT

		  bool isValid(Field field) const; // EXPORT _field

		  /// Returns loader error for the header
		  LoaderError loaderError() const;

		  /// Corrects the current MZ header.
		  void makeValid(); // EXPORT

		  void makeValid(Field field); // EXPORT _field

		  /// Reads the MZ header of a file.
		  int read(std::istream& inStream); // EXPORT

		  /// Reads the MZ header from a memory location.
		  int read(unsigned char* pcBuffer, unsigned int uiSize, unsigned int originalOffs = 0); // EXPORT _fromMemory

		  /// Rebuild the MZ header.
		  void rebuild(std::vector<byte>& vBuffer) const; // EXPORT

		  /// Returns the size of the current MZ header.
		  unsigned int size() const; // EXPORT

		  /// Writes the current MZ header to offset 0 of a file.
		  int write(const std::string& strFilename, dword dwOffset) const; // EXPORT

		  /// Gets MZ header.
		  const PELIB_IMAGE_DOS_HEADER& getHeader() const; // EXPORT
		  /// Gets MZ header in string representation.
		  const std::string& getString() const; // EXPORT

		  /// Gets the e_magic value of the MZ header.
		  word getMagicNumber() const; // EXPORT
		  /// Gets the e_cblp value of the MZ header.
		  word getBytesOnLastPage() const; // EXPORT
		  /// Gets the e_cp value of the MZ header.
		  word getPagesInFile() const; // EXPORT
		  /// Gets the e_crlc value of the MZ header.
		  word getRelocations() const; // EXPORT
		  /// Gets the e_cparhdr value of the MZ header.
		  word getSizeOfHeader() const; // EXPORT
		  /// Gets the e_minalloc value of the MZ header.
		  word getMinExtraParagraphs() const; // EXPORT
		  /// Gets the e_maxalloc value of the MZ header.
		  word getMaxExtraParagraphs() const; // EXPORT
		  /// Gets the e_ss value of the MZ header.
		  word getSsValue() const; // EXPORT
		  /// Gets the e_sp value of the MZ header.
		  word getSpValue() const; // EXPORT
		  /// Gets the e_csum value of the MZ header.
		  word getChecksum() const; // EXPORT
		  /// Gets the e_ip value of the MZ header.
		  word getIpValue() const; // EXPORT
		  /// Gets the e_cs value of the MZ header.
		  word getCsValue() const; // EXPORT
		  /// Gets the e_lfarlc value of the MZ header.
		  word getAddrOfRelocationTable() const; // EXPORT
		  /// Gets the e_ovnovalue of the MZ header.
		  word getOverlayNumber() const; // EXPORT
		  /// Gets the e_oemid value of the MZ header.
		  word getOemIdentifier() const; // EXPORT
		  /// Gets the e_oeminfo value of the MZ header.
		  word getOemInformation() const; // EXPORT
		  /// Gets the e_lfanew value of the MZ header.
		  dword getAddressOfPeHeader() const; // EXPORT
		  /// Gets the e_res of the MZ header.
		  word getReservedWords1(unsigned int uiNr) const; // EXPORT
		  /// Gets the e_res2 of the MZ header.
		  word getReservedWords2(unsigned int uiNr) const; // EXPORT

		  /// Sets the e_magic value of the MZ header.
		  void setMagicNumber(word wValue); // EXPORT
		  /// Sets the e_cblp value of the MZ header.
		  void setBytesOnLastPage(word wValue); // EXPORT
		  /// Sets the e_cp value of the MZ header.
		  void setPagesInFile(word wValue); // EXPORT
		  /// Sets the e_crlc value of the MZ header.
		  void setRelocations(word wValue); // EXPORT
		  /// Sets the e_cparhdr value of the MZ header.
		  void setSizeOfHeader(word wValue); // EXPORT
		  /// Sets the e_minalloc value of the MZ header.
		  void setMinExtraParagraphs(word wValue); // EXPORT
		  /// Sets the e_maxalloc value of the MZ header.
		  void setMaxExtraParagraphs(word wValue); // EXPORT
		  /// Sets the e_ss value of the MZ header.
		  void setSsValue(word wValue); // EXPORT
		  /// Sets the e_sp value of the MZ header.
		  void setSpValue(word wValue); // EXPORT
		  /// Sets the e_csum value of the MZ header.
		  void setChecksum(word wValue); // EXPORT
		  /// Sets the e_ip value of the MZ header.
		  void setIpValue(word wValue); // EXPORT
		  /// Sets the e_cs value of the MZ header.
		  void setCsValue(word wValue); // EXPORT
		  /// Sets the e_lfarlc value of the MZ header.
		  void setAddrOfRelocationTable(word wValue); // EXPORT
		  /// Sets the e_ovno value of the MZ header.
		  void setOverlayNumber(word wValue); // EXPORT
		  /// Sets the e_oemid value of the MZ header.
		  void setOemIdentifier(word wValue); // EXPORT
		  /// Sets the e_oeminfo value of the MZ header.
		  void setOemInformation(word wValue); // EXPORT
		  /// Sets the e_lfanew value of the MZ header.
		  void setAddressOfPeHeader(dword dwValue); // EXPORT
		  /// Sets the e_res value of the MZ header.
		  void setReservedWords1(unsigned int uiNr, word wValue); // EXPORT
		  /// Sets the e_res2 value of the MZ header.
		  void setReservedWords2(unsigned int uiNr, word wValue); // EXPORT
	};
}

#endif
