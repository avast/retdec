/**
 * @file src/unpackertool/plugins/upx/pe/pe_upx_stub.h
 * @brief Declaration of UPX unpacking stub in PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_PE_PE_UPX_STUB_H
#define UNPACKERTOOL_PLUGINS_UPX_PE_PE_UPX_STUB_H

#include <unordered_set>

#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/pelib/PeFile.h"
#include "retdec/utils/dynamic_buffer.h"
#include "retdec/unpacker/signature.h"

using namespace retdec::utils;

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
		: _importsOffset(extraData._importsOffset), _relocsOffset(extraData._relocsOffset), _originalHeaderOffset(extraData._originalHeaderOffset), _relocsBigEndian(extraData._relocsBigEndian) {}

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
 * Basic unpacking stub class for unpacking files in PE format.
 */
template <int bits> class PeUpxStub : public UpxStub
{
	public:

	PeUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const DynamicBuffer& stubCapturedData,
			std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata);

	virtual void unpack(const std::string& ouputFile) override;
	virtual void setupPackingMethod(std::uint8_t packingMethod);
	virtual void readUnpackingStub(DynamicBuffer& unpackingStub);
	virtual void readPackedData(DynamicBuffer& packedData, bool trustMetadata);
	virtual void decompress(DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata);
	virtual void cleanup() override;

	virtual std::uint32_t getRealEpAddress() const override;
	void setRealEpAddress(std::uint32_t realEpAddress);

protected:
	const retdec::loader::Segment* _upx0Sect;      ///< Pointer to section UPX0.
	std::uint32_t _realEpAddress;                ///< The real entry point address.

private:
	void prepare();
	void detectUnfilter(const DynamicBuffer& unpackingStub);
	void unpackData(DynamicBuffer& unpackedData);
	void readPackedFileILT(DynamicBuffer& ilt);
	void fixSizeOfSections(const DynamicBuffer& unpackedData);
	UpxExtraData parseExtraData(DynamicBuffer& unpackedData, DynamicBuffer& originalHeader);
	void fixPeHeader(const DynamicBuffer& originalHeader);
	void unfilterData(DynamicBuffer& unpackedData);
	void fixImports(const DynamicBuffer& unpackedData, const UpxExtraData& extraData, const DynamicBuffer& ilt);
	void fixRelocations(DynamicBuffer& unpackedData, const UpxExtraData& extraData);
	void fixTls(const DynamicBuffer& originalHeader);
	void fixOep(const DynamicBuffer& originalHeader);
	void fixExports(const DynamicBuffer& originalHeader);
	void fixLoadConfiguration(const DynamicBuffer& originalHeader);
	void fixResources(const DynamicBuffer& unpackedData, const DynamicBuffer& originalHeader);
	void fixSectionHeaders(const DynamicBuffer& originalHeader);
	void fixCoffSymbolTable();
	void fixCertificates();
	void cutHintsData(DynamicBuffer& unpackedData, const UpxExtraData& extraData);
	void saveFile(const std::string& outputFile, DynamicBuffer& unpackedData);

	void loadResources(PeLib::ResourceNode* rootNode, std::uint32_t offset, std::uint32_t uncompressedRsrcRva, std::uint32_t compressedRsrcRva,
			const DynamicBuffer& uncompressedRsrcs, const DynamicBuffer& unpackedData, std::unordered_set<std::uint32_t>& visitedNodes);
	std::uint8_t getPackingMethod(bool trustMetadata) const;

	PeLib::PeFileT * _newPeFile;    ///< Unpacked output file.
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
