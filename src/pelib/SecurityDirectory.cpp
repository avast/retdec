/**
 * @file SecurityDirectory.cpp
 * @brief Class for security directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/SecurityDirectory.h"

namespace PeLib
{
	SecurityDirectory::SecurityDirectory() : m_ldrError(LDR_ERROR_NONE)
	{}

	unsigned int SecurityDirectory::calcNumberOfCertificates() const
	{
		return (unsigned int)m_certs.size();
	}

	const std::vector<unsigned char>& SecurityDirectory::getCertificate(std::size_t index) const
	{
		return m_certs[index].Certificate;
	}

	LoaderError SecurityDirectory::loaderError() const
	{
		return m_ldrError;
	}

	int SecurityDirectory::read(
			std::istream& inStream,
			unsigned int uiOffset,
			unsigned int uiSize)
	{
		IStreamWrapper inStream_w(inStream);

		m_ldrError = LDR_ERROR_NONE;

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		if (ulFileSize < uiOffset + uiSize)
		{
			m_ldrError = LDR_ERROR_DIGITAL_SIGNATURE_CUT;
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<unsigned char> vCertDirectory(uiSize);
		inStream_w.read(reinterpret_cast<char*>(vCertDirectory.data()), uiSize); // reads the whole directory

		// Verify zeroed certificates (00002edec5247488029b2cc69568dda90714eeed8de0d84f1488635196b7e708)
		if (std::all_of(vCertDirectory.begin(), vCertDirectory.end(), [](unsigned char item) { return item == 0; }))
		{
			m_ldrError = LDR_ERROR_DIGITAL_SIGNATURE_ZEROED;
			return ERROR_INVALID_FILE;
		}

		InputBuffer inpBuffer(vCertDirectory);

		unsigned bytesRead = 0;
		while (bytesRead < uiSize)
		{
			PELIB_IMAGE_CERTIFICATE_ENTRY cert;
			inpBuffer >> cert.Length;
			inpBuffer >> cert.Revision;
			inpBuffer >> cert.CertificateType;

			if ((cert.Length <= PELIB_IMAGE_CERTIFICATE_ENTRY::size() ||
				((cert.Revision != PELIB_WIN_CERT_REVISION_1_0) && (cert.Revision != PELIB_WIN_CERT_REVISION_2_0)) ||
				(cert.CertificateType != PELIB_WIN_CERT_TYPE_PKCS_SIGNED_DATA)))
			{
				return ERROR_INVALID_FILE;
			}

			cert.Certificate.resize(cert.Length - PELIB_IMAGE_CERTIFICATE_ENTRY::size());
			inpBuffer.read(reinterpret_cast<char*>(cert.Certificate.data()), cert.Certificate.size());

			bytesRead += cert.Length;
			m_certs.push_back(cert);
		}

		// save the offset and size for future checks
		this->offset = uiOffset;
		this->size = size;

		return ERROR_NONE;
	}

	std::uint64_t SecurityDirectory::getOffset() const
	{
		return offset;
	}

	std::uint64_t SecurityDirectory::getSize() const
	{
		return size;
	}
}
