/**
 * @file SecurityDirectory.h
 * @brief Class for certificate directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef SECURITYDIRECTORY_H
#define SECURITYDIRECTORY_H

#include "pelib/PeHeader.h"

namespace PeLib
{
	class SecurityDirectory
	{
		private:
		  std::vector<PELIB_IMAGE_CERTIFICATE_ENTRY> m_certs;
		public:
		  /// Number of certificates in the directory.
		  unsigned int calcNumberOfCertificates() const; // EXPORT
		  /// Returns certificate at specified index.
		  const std::vector<unsigned char>& getCertificate(std::size_t index) const; // EXPORT
		  /// Read a file's certificate directory.
		  int read(
				  std::istream& inStream,
				  unsigned int uiOffset,
				  unsigned int uiSize); // EXPORT
	};
}

#endif
