/**
 * @file SecurityDirectory.h
 * @brief Class for certificate directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PELIB_SECURITYDIRECTORY_H
#define RETDEC_PELIB_SECURITYDIRECTORY_H

#include <cstdint>

namespace PeLib
{
	class SecurityDirectory
	{
		private:
		  LoaderError m_ldrError;
		  std::vector<PELIB_IMAGE_CERTIFICATE_ENTRY> m_certs;
		  std::uint64_t offset = 0;
		  std::uint64_t size = 0;
		public:
		  /// Constructor
		  SecurityDirectory();
		  std::uint64_t getOffset() const;
		  std::uint64_t getSize() const;
		  /// Number of certificates in the directory.
		  unsigned int calcNumberOfCertificates() const; // EXPORT
		  /// Returns certificate at specified index.
		  const std::vector<unsigned char>& getCertificate(std::size_t index) const; // EXPORT
		  /// Return the loader error
		  LoaderError loaderError() const;
		  /// Read a file's certificate directory.
		  int read(
				  std::istream& inStream,
				  unsigned int uiOffset,
				  unsigned int uiSize); // EXPORT
	};
}

#endif
