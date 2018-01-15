/**
 * @file src/unpackertool/plugins/upx/upx_stub.h
 * @brief Declaration of abstract UPX stub class that represents the unpacking procedure itself.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_UPX_STUB_H
#define UNPACKERTOOL_PLUGINS_UPX_UPX_STUB_H

#include <memory>

#include "retdec/loader/loader.h"
#include "retdec/unpacker/plugin.h"
#include "retdec/unpacker/dynamic_buffer.h"
#include "retdec/unpacker/unpacking_stub.h"

namespace retdec {

// Forward declaration
namespace unpacker { class CompressedData; }

namespace unpackertool {
namespace upx {

class Decompressor;

/**
 * Version of the UPX unpacking stub.
 */
enum class UpxStubVersion
{
	LZMA,
	NRV2B,
	NRV2D,
	NRV2E,
	UPXSHIT,
	DIRECT_JUMP,
	UNIVERSAL,
	UNKNOWN
};

/**
 * UPX packing method. Distinguishes between used bit parsers. This field
 * is written in the packed block header for ELF file format. PE always uses
 * 32-bit parsers.
 */
enum UpxPackingMethod
{
	UPX_PACKING_METHOD_NRV2B_LE32   = 0x2, // NRV2B Little Endian 32-bit parser.
	UPX_PACKING_METHOD_NRV2B_8      = 0x3, // NRV2B 8-bit parser.
	UPX_PACKING_METHOD_NRV2D_LE32   = 0x5, // NRV2D Little Endian 32-bit parser.
	UPX_PACKING_METHOD_NRV2D_8      = 0x6, // NRV2D 8-bit parser.
	UPX_PACKING_METHOD_NRV2E_LE32   = 0x8, // NRV2E Little Endian 32-bit parser.
	UPX_PACKING_METHOD_NRV2E_8      = 0x9, // NRV2E 8-bit parser
	UPX_PACKING_METHOD_LZMA         = 0xE  // LZMA - no bit parser used but has it's own value
};

struct UpxStubData;

class UpxMetadata
{
public:
	UpxMetadata();
	UpxMetadata(const UpxMetadata& metadata);

	static UpxMetadata read(retdec::loader::Image* file);
	static std::uint8_t calcChecksum(const retdec::unpacker::DynamicBuffer& data);
	static std::uint32_t getSizeOfVersion(std::uint8_t version);

	UpxStubVersion getStubVersion() const;

	bool isDefined() const { return _defined; }
	bool usesPackingMethod() const { return _usesPackingMethod; }
	std::uint32_t getFileOffset() const { return _fileOffset; }
	std::uint32_t getFileSize() const { return _fileSize; }
	UpxPackingMethod getPackingMethod() const { return static_cast<UpxPackingMethod>(_packingMethod); }
	std::uint32_t getPackedDataSize() const { return _packedDataSize; }
	std::uint32_t getUnpackedDataSize() const { return _unpackedDataSize; }
	std::uint8_t getFilterId() const { return _filterId; }
	std::uint8_t getFilterParameter() const { return _filterParam; }

private:
	void setDefined(bool set) { _defined = set; }
	void setUsesPackingMethod(bool set) { _usesPackingMethod = set; }
	void setFileOffset(std::uint32_t fileOffset) { _fileOffset = fileOffset; }
	void setFileSize(std::uint32_t fileSize) { _fileSize = fileSize; }
	void setPackingMethod(std::uint8_t packingMethod) { _packingMethod = packingMethod; }
	void setPackedDataSize(std::uint32_t packedDataSize) { _packedDataSize = packedDataSize; }
	void setUnpackedDataSize(std::uint32_t unpackedDataSize) { _unpackedDataSize = unpackedDataSize; }
	void setFilterId(std::uint8_t filterId) { _filterId = filterId; }
	void setFilterParameter(std::uint8_t filterParam) { _filterParam = filterParam; }

	bool _defined;
	bool _usesPackingMethod;
	std::uint32_t _fileOffset;
	std::uint32_t _fileSize;
	std::uint8_t _packingMethod;
	std::uint32_t _packedDataSize;
	std::uint32_t _unpackedDataSize;
	std::uint8_t _filterId;
	std::uint8_t _filterParam;
};

/**
 * Base class that represents UPX unpacking stub and its functionality. Every different type
 * of unpacking stub should subclass this class and implement its unpacker, decompress and cleanup method.
 */
class UpxStub : public retdec::unpacker::UnpackingStub
{
public:
	UpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const retdec::unpacker::DynamicBuffer& stubCapturedData,
			std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata);

	virtual ~UpxStub() override;

	static std::shared_ptr<UpxStub> createStub(retdec::loader::Image* file);
	static std::shared_ptr<UpxStub> createStub(retdec::loader::Image* file, const retdec::unpacker::DynamicBuffer& stubBytes);

	UpxStubVersion getVersion() const;
	const UpxStubData* getStubData() const;
	const retdec::unpacker::DynamicBuffer* getStubCapturedData() const;
	Decompressor* getDecompressor() const;
	const UpxMetadata* getUpxMetadata() const;
	virtual std::uint32_t getRealEpAddress() const;

	void setStubData(const UpxStubData* stubData);
	void setStubCapturedData(const retdec::unpacker::DynamicBuffer& stubCapturedData);

protected:
	std::unique_ptr<Decompressor> decodePackingMethod(std::uint8_t packingMethod) const;

	const UpxStubData* _stubData;                ///< Additional stub information.
	retdec::unpacker::DynamicBuffer _stubCapturedData;  ///< Data captured while matching signature of this stub.
	std::unique_ptr<Decompressor> _decompressor; ///< Decompressor associated with stub.
	UpxMetadata _metadata;                       ///< UPX metadata aka packheader.

private:
	static std::shared_ptr<UpxStub> _createStubImpl(retdec::loader::Image* file, const retdec::unpacker::DynamicBuffer* stubBytes);
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
