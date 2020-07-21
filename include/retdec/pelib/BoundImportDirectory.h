/*
* BoundImportDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_BOUNDIMPORTDIRECTORY_H
#define RETDEC_PELIB_BOUNDIMPORTDIRECTORY_H

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/PeLibAux.h"
#include "retdec/pelib/ImageLoader.h"

namespace PeLib
{
	/// Class that handles the BoundImport directory.
	/**
	* This class can read and modify the BoundImport directory table of a PE file.
	**/
	class BoundImportDirectory
	{
		protected:
		  std::vector<PELIB_IMAGE_BOUND_DIRECTORY> m_vIbd; ///< Stores the individual BoundImport fields.

		  int read(InputBuffer& inpBuffer, unsigned char* data, unsigned int dwSize);
		  unsigned int totalModules() const;
		public:
		  virtual ~BoundImportDirectory() = default;

		  /// Reads the BoundImport directory table from a PE file.
		  int read(ImageLoader & imageLoader); // EXPORT
		  /// Adds another bound import.
		  int addBoundImport(const std::string& strModuleName, std::uint32_t dwTds, std::uint16_t dwOmn, std::uint16_t wWfr); // EXPORT
		  /// Identifies a module through it's name.
		  int getModuleIndex(const std::string& strModuleName) const; // EXPORT
		  /// Returns the number of files in the BoundImport directory.
		  unsigned int calcNumberOfModules() const; // EXPORT
		  /// Reads the BoundImport directory table from a PE file.
		  int read(unsigned char* pcBuffer, unsigned int uiSize); // EXPORT
		  /// Rebuilds the BoundImport directory.
		  void rebuild(std::vector<std::uint8_t>& vBuffer, bool fMakeValid = true) const; // EXPORT
		  /// Empties the BoundImport directory.
		  void clear(); // EXPORT
		  /// Removes a bound import.
		  void removeBoundImport(const std::string& strModuleName); // EXPORT
		  /// Returns the size of the BoundImport directory.
		  unsigned int size() const; // EXPORT
		  /// Writes the current bound import directory to a file.
		  int write(const std::string& strFilename, std::uint32_t dwOffset, bool fMakeValid = true) const; // EXPORT

		  /// Retrieves the TimeDateStamp value of a bound import.
		  std::uint32_t getTimeDateStamp(std::uint32_t dwBidnr) const; // EXPORT
		  /// Retrieves the OffsetModuleName value of a bound import.
		  std::uint16_t getOffsetModuleName(std::uint32_t dwBidnr) const; // EXPORT
		  /// Retrieves the NumberOfModuleForwarderRefs value of a bound import.
		  std::uint16_t getNumberOfModuleForwarderRefs(std::uint32_t dwBidnr) const; // EXPORT
		  /// Retrieves the ModuleName value of a bound import.
		  std::string getModuleName(std::uint32_t dwBidnr) const; // EXPORT

		  /// Updates the TimeDateStamp value of a bound import.
		  void setTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t dwTds); // EXPORT
		  /// Updates the OffsetModuleName value of a bound import.
		  void setOffsetModuleName(std::uint32_t dwBidnr, std::uint16_t wOmn); // EXPORT
		  /// Updates the NumberOfModuleForwarderRefs value of a bound import.
		  void setNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint16_t wMfr); // EXPORT
		  /// Updates the ModuleName value of a bound import.
		  void setModuleName(std::uint32_t dwBidnr, const std::string& strModuleName); // EXPORT

		  std::uint32_t getTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const; // EXPORT _module
		  std::uint16_t getOffsetModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const; // EXPORT _module
		  std::uint16_t getNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const; // EXPORT _module
		  std::string getModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule) const; // EXPORT _module

		  void setTimeDateStamp(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint32_t dwTds); // EXPORT _module
		  void setOffsetModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint16_t wOmn); // EXPORT _module
		  void setNumberOfModuleForwarderRefs(std::uint32_t dwBidnr, std::uint32_t forwardedModule, std::uint16_t wMfr); // EXPORT _module
		  void setModuleName(std::uint32_t dwBidnr, std::uint32_t forwardedModule, const std::string& strModuleName); // EXPORT _module

		  std::uint16_t calcNumberOfModuleForwarderRefs(std::uint32_t dwBidnr) const; // EXPORT
		  void addForwardedModule(std::uint32_t dwBidnr, const std::string& name, std::uint32_t timeStamp = 0, std::uint16_t offsetModuleName = 0, std::uint16_t forwardedModules = 0); // EXPORT
		  void removeForwardedModule(std::uint32_t dwBidnr, std::uint16_t forwardedModule); // EXPORT
	};
}

#endif
