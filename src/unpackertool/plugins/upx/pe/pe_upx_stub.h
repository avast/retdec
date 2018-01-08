/**
 * @file src/unpackertool/plugins/upx/pe/pe_upx_stub.h
 * @brief Declaration of UPX unpacking stub in PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_PE_PE_UPX_STUB_H
#define UNPACKERTOOL_PLUGINS_UPX_PE_PE_UPX_STUB_H

#include <unordered_set>

#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/dynamic_buffer.h"
#include "retdec/unpacker/signature.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * UPX unpacking stub consists of main stub (decompression) and then
 * many more smaller stubs which perform various tasks like fixing imports,
 * fixing relocations etc.
 *
 * This data structure represents information about these auxiliary unpacking stubs
 */
struct UnfilterSignatureData
{
	retdec::unpacker::Signature* signature; ///< Signature associated with the stub.
	std::uint32_t filterId; ///< Used to store data specific for each type of stub.
};

class UpxExtraData
{
public:
	UpxExtraData() : _importsOffset(0), _relocsOffset(0), _originalHeaderOffset(0), _relocsBigEndian(false) {}
	UpxExtraData(const UpxExtraData& extraData)
		: _importsOffset(extraData._importsOffset), _relocsOffset(extraData._relocsOffset), _relocsBigEndian(extraData._relocsBigEndian) {}

	std::uint32_t getImportsOffset() const { return _importsOffset; }
	void setImportsOffset(std::uint32_t importsOffset) { _importsOffset = importsOffset; }

	std::uint32_t getRelocationsOffset() const { return _relocsOffset; }
	void setRelocationsOffset(std::uint32_t relocsOffset) { _relocsOffset = relocsOffset; }
	bool areRelocationsBigEndian() const { return _relocsBigEndian; }
	void setRelocationsBigEndian(bool set) { _relocsBigEndian = true; }

	std::uint32_t getOriginalHeaderOffset() const { return _originalHeaderOffset; }
	void setOriginalHeaderOffset(std::uint32_t originalHeaderOffset) { _originalHeaderOffset = originalHeaderOffset; }

private:
	std::uint32_t _importsOffset;
	std::uint32_t _relocsOffset;
	std::uint32_t _originalHeaderOffset;
	bool _relocsBigEndian;
};

/**
 * Base PE UPX traits structure.
 */
template <int /*bits*/> struct PeUpxStubTraits {};

/**
 * Specialized traits for PE32.
 */
template <> struct PeUpxStubTraits<32>
{
	using AddressType = std::uint32_t; ///< Type with default word size.
	using PeLibFileType = PeLib::PeFile32;

	static const std::uint16_t HeaderMagic = PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC; ///< PE magic header.
	static const std::uint32_t NumberOfRvaAndSizesOffset = 0x74; ///< Offset in PE header to directories count.
	static const std::uint32_t TlsDirectoryRvaOffset = 0xC0; ///< Offset to TLS RVA.
	static const std::uint32_t TlsDirectorySizeOffset = 0xC4; ///< Offset to TLS size.
	static const std::uint32_t ExportsDirectoryRvaOffset = 0x78; ///< Offset to exports RVA.
	static const std::uint32_t ExportsDirectorySizeOffset = 0x7C; ///< Offset to exports size.
	static const std::uint32_t LoadConfigDirectoryRvaOffset = 0xC8; ///< Offset to load configuration RVA.
	static const std::uint32_t LoadConfigDirectorySizeOffset = 0xCC; ///< Offset to load configuration size.
	static const std::uint32_t RsrcsDirectoryRvaOffset = 0x88; ///< Offset to resources RVA.
	static const std::uint32_t RsrcsDirectorySizeOffset = 0x8C; ///< Offset to resources size.
};

/**
 * Specialized traits for PE32+.
 */
template <> struct PeUpxStubTraits<64>
{
	using AddressType = std::uint32_t; ///< Type with default word size.
	using PeLibFileType = PeLib::PeFile64; ///< Type of PE file.

	static const std::uint16_t HeaderMagic = PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC; ///< PE magic header.
	static const std::uint32_t NumberOfRvaAndSizesOffset = 0x84; ///< Offset in PE header to directories count.
	static const std::uint32_t TlsDirectoryRvaOffset = 0xD0; ///< Offset to TLS RVA.
	static const std::uint32_t TlsDirectorySizeOffset = 0xD4; ///< Offset to TLS size.
	static const std::uint32_t ExportsDirectoryRvaOffset = 0x88; ///< Offset to exports RVA.
	static const std::uint32_t ExportsDirectorySizeOffset = 0x8C; ///< Offset to exports size.
	static const std::uint32_t LoadConfigDirectoryRvaOffset = 0xD8; ///< Offset to load configuration RVA.
	static const std::uint32_t LoadConfigDirectorySizeOffset = 0xDC; ///< Offset to load configuration size.
	static const std::uint32_t RsrcsDirectoryRvaOffset = 0x98; ///< Offset to resources RVA.
	static const std::uint32_t RsrcsDirectorySizeOffset = 0x9C; ///< Offset to resources size.
};

/**
 * Basic unpacking stub class for unpacking files in PE format.
 */
template <int bits> class PeUpxStub : public UpxStub
{
	using AddressType = typename PeUpxStubTraits<bits>::AddressType;
	using PeLibFileType = typename PeUpxStubTraits<bits>::PeLibFileType;

public:
	PeUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const retdec::unpacker::DynamicBuffer& stubCapturedData,
			std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata);

	virtual ~PeUpxStub() override;

	virtual void unpack(const std::string& ouputFile) override;
	virtual void setupPackingMethod(std::uint8_t packingMethod);
	virtual void readUnpackingStub(retdec::unpacker::DynamicBuffer& unpackingStub);
	virtual void readPackedData(retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata);
	virtual void decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata);
	virtual void cleanup() override;

	virtual std::uint32_t getRealEpAddress() const override;
	void setRealEpAddress(std::uint32_t realEpAddress);

protected:
	const retdec::loader::Segment* _upx0Sect;      ///< Pointer to section UPX0.
	std::uint32_t _realEpAddress;                ///< The real entry point address.

private:
	void prepare();
	void detectUnfilter(const retdec::unpacker::DynamicBuffer& unpackingStub);
	void unpackData(retdec::unpacker::DynamicBuffer& unpackedData);
	void readPackedFileILT(retdec::unpacker::DynamicBuffer& ilt);
	void fixSizeOfSections(const retdec::unpacker::DynamicBuffer& unpackedData);
	UpxExtraData parseExtraData(retdec::unpacker::DynamicBuffer& unpackedData, retdec::unpacker::DynamicBuffer& originalHeader);
	void fixPeHeader(const retdec::unpacker::DynamicBuffer& originalHeader);
	void unfilterData(retdec::unpacker::DynamicBuffer& unpackedData);
	void fixImports(const retdec::unpacker::DynamicBuffer& unpackedData, const UpxExtraData& extraData, const retdec::unpacker::DynamicBuffer& ilt);
	void fixRelocations(retdec::unpacker::DynamicBuffer& unpackedData, const UpxExtraData& extraData);
	void fixTls(const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixOep(const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixExports(const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixLoadConfiguration(const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixResources(const retdec::unpacker::DynamicBuffer& unpackedData, const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixSectionHeaders(const retdec::unpacker::DynamicBuffer& originalHeader);
	void fixCoffSymbolTable();
	void fixCertificates();
	void cutHintsData(retdec::unpacker::DynamicBuffer& unpackedData, const UpxExtraData& extraData);
	void saveFile(const std::string& outputFile, retdec::unpacker::DynamicBuffer& unpackedData);

	void loadResources(PeLib::ResourceNode* rootNode, std::uint32_t offset, std::uint32_t uncompressedRsrcRva, std::uint32_t compressedRsrcRva,
			const retdec::unpacker::DynamicBuffer& uncompressedRsrcs, const retdec::unpacker::DynamicBuffer& unpackedData, std::unordered_set<std::uint32_t>& visitedNodes);
	std::uint8_t getPackingMethod(bool trustMetadata) const;

	PeLibFileType* _newPeFile;      ///< Unpacked output file.
	std::uint32_t _rvaShift;        ///< Size of sections UPX1 and UPX2 which are deleted and virtual addresses are shifted.
	bool _exportsCompressed;        ///< True if the exports are compressed in the packed file, otherwise false
	std::vector<std::uint8_t> _coffSymbolTable; ///< COFF symbol table data if any exists.

	/// @name Data read from signatures.
	/// @{
	std::uint32_t _filterId;     ///< ID of the used filter.
	std::uint32_t _filterCount;  ///< Number of jumps that are filtered.
	std::uint32_t _filterParam;  ///< Parameter of the filter.
	/// @}
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
