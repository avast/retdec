/**
 * @file RichHeader.cpp
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <sstream>
#include <iomanip>

#include "pelib/PeLibInc.h"
#include "pelib/RichHeader.h"

namespace PeLib
{

namespace
{
	std::string makeSignature(dword value)
	{
		std::stringstream signature;
		signature << std::hex << std::setfill('0') << std::setw(2 * sizeof(dword)) << std::uppercase << value;
		return signature.str();
	}

	std::string makeSignature(dword first, dword second)
	{
		return makeSignature(first) + makeSignature(second);
	}
}

	RichHeader::RichHeader()
	{
		init();
	}

	RichHeader::~RichHeader()
	{

	}

	void RichHeader::init()
	{
		headerIsValid = false;
		validStructure = false;
		key = 0;
		noOfIters = 0;
		decryptedHeader.clear();
		records.clear();
	}

	void RichHeader::setValidStructure()
	{
		validStructure = (decryptedHeader.size() >= 4);
	}

	bool RichHeader::analyze(bool ignoreInvalidKey)
	{
		bool hValid = true;
		size_t decSize = decryptedHeader.size();
		if (decSize < 4)
		{
			return false;
		}
		else if (decryptedHeader[0] != 0x536e6144 || decryptedHeader[1] != 0 ||
			decryptedHeader[2] != 0 || decryptedHeader[3] != 0)
		{
			if (ignoreInvalidKey)
			{
				hValid = false;
			}
			else
			{
				return false;
			}
		}

		const word mask1 = (1 << (8 * sizeof(word))) - 1;
		const word mask2 = (1 << (8 * sizeof(byte))) - 1;
		PELIB_IMAGE_RICH_HEADER_RECORD record;

		for (size_t i = 4; i + 1 < decSize; i += 2)
		{
			headerIsValid = hValid;
			const word id = decryptedHeader[i] >> (8 * sizeof(word));
			record.MajorVersion = id & mask2;
			record.MinorVersion = id >> (8 * sizeof(byte));
			record.Build = decryptedHeader[i] & mask1;
			record.Count = decryptedHeader[i + 1];
			record.Signature = makeSignature(decryptedHeader[i], decryptedHeader[i + 1]);
			records.push_back(record);
		}

		return true;
	}

	void RichHeader::read(InputBuffer& inputbuffer, std::size_t uiSize, bool ignoreInvalidKey)
	{
		init();
		std::vector<dword> rich;

		for (std::size_t i = 0, e = uiSize / sizeof(dword); i < e; ++i)
		{
			dword actInput;
			inputbuffer >> actInput;
			rich.push_back(actInput);
		}

		dword sign[] = {0x68636952};
		auto lastPos = rich.end();

		// try to find signature of rich header and key for decryption
		do
		{
			auto richSignature = find_end(rich.begin(), lastPos, sign, sign + 1);
			if (richSignature == lastPos || richSignature + 1 == rich.end())
			{
				break;
			}

			lastPos = richSignature;
			key = *(richSignature + 1);
			decryptedHeader.clear();
			++noOfIters;

			for (auto i = rich.begin(); i != richSignature; ++i)
			{
				decryptedHeader.push_back(*i ^ key);
			}

			setValidStructure();
		} while (!analyze());

		if (ignoreInvalidKey && noOfIters)
		{
			analyze(true);
		}
	}

	int RichHeader::read(
			std::istream& inStream,
			std::size_t uiOffset,
			std::size_t uiSize,
			bool ignoreInvalidKey)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		const auto ulFileSize = fileSize(inStream_w);
		if (ulFileSize < uiOffset + uiSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);
		std::vector<unsigned char> tableDump;
		tableDump.resize(uiSize);
		inStream_w.read(reinterpret_cast<char*>(tableDump.data()), uiSize);
		InputBuffer ibBuffer(tableDump);
		read(ibBuffer, uiSize, ignoreInvalidKey);

		return ERROR_NONE;
	}

	bool RichHeader::isHeaderValid() const
	{
		return headerIsValid;
	}

	bool RichHeader::isStructureValid() const
	{
		return validStructure;
	}

	std::size_t RichHeader::getNumberOfIterations() const
	{
		return noOfIters;
	}

	dword RichHeader::getKey() const
	{
		return key;
	}

	const dword* RichHeader::getDecryptedHeaderItem(std::size_t index) const
	{
		return (index < decryptedHeader.size()) ? &decryptedHeader[index] : nullptr;
	}

	std::string RichHeader::getDecryptedHeaderItemSignature(std::size_t index) const
	{
		const auto *dhI = getDecryptedHeaderItem(index);
		return dhI ? makeSignature(*dhI) : "";
	}

	std::string RichHeader::getDecryptedHeaderItemsSignature(std::initializer_list<std::size_t> indexes) const
	{
		std::string result;

		for (const auto index : indexes)
		{
			result += getDecryptedHeaderItemSignature(index);
		}

		return result;
	}

	std::vector<std::uint8_t> RichHeader::getDecryptedHeaderBytes() const
	{
		std::vector<std::uint8_t> result(decryptedHeader.size() * sizeof(dword));
		std::memcpy(result.data(), reinterpret_cast<const std::uint8_t*>(decryptedHeader.data()), result.size());
		return result;
	}

	RichHeader::richHeaderIterator RichHeader::begin() const
	{
		return records.begin();
	}

	RichHeader::richHeaderIterator RichHeader::end() const
	{
		return records.end();
	}
}
