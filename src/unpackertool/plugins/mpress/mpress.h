/**
 * @file src/unpackertool/plugins/mpress/mpress.h
 * @brief Unpacker plugin for MPRESS packer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_MPRESS_MPRESS_H
#define UNPACKERTOOL_PLUGINS_MPRESS_MPRESS_H

#include "retdec/loader/loader.h"
#include "retdec/unpacker/dynamic_buffer.h"
#include "retdec/unpacker/plugin.h"

#define mpress_plugin plugin(retdec::unpackertool::mpress::MpressPlugin)

namespace retdec {
namespace unpackertool {
namespace mpress {

enum Compression
{
	COMPRESSION_LZMA,
	COMPRESSION_LZMAT,
	COMPRESSION_UNKNOWN
};

enum MpressUnpackerStub
{
	MPRESS_UNPACKER_STUB_101_105,
	MPRESS_UNPACKER_STUB_107_127,
	MPRESS_UNPACKER_STUB_201,
	MPRESS_UNPACKER_STUB_205_LZMA,
	MPRESS_UNPACKER_STUB_205_LZMAT,
	MPRESS_UNPACKER_STUB_212_219_LZMA,
	MPRESS_UNPACKER_STUB_212_219_LZMAT,
	MPRESS_UNPACKER_STUB_UNKNOWN
};

enum MpressFixStub
{
	MPRESS_FIX_STUB_10x,
	MPRESS_FIX_STUB_127_20x,
	MPRESS_FIX_STUB_21x,
	MPRESS_FIX_STUB_UNKNOWN
};

struct MpressUnpackerStubData
{
	std::uint32_t signature; // Offset written near the EP which tells where is the offset to the fix imports stub
	std::uint32_t packedContentOffset; // Offset of the section with the packed content
	std::uint32_t fixStubOffset; // Offset from the EP where the offset of Fix Imports Stub is written
	std::uint32_t relocOffset; // Offset from Fix Imports Stub where relocations are written
	std::uint32_t relocSizeOffset; // Offset from the EP where size of relocations is written
	Compression compression; // Compression method used while packing
};

struct MpressFixStubData
{
	std::uint32_t signature; // Byte at the beginning of fix imports stub
	std::uint32_t importHintsOffset; // Offset from Fix Imports Stub where Import Hints are stored
	std::uint32_t oepOffset; // Offset from Fix Imports Stub where the offset of OEP is written
};

class MpressPlugin : public Plugin
{
public:
	MpressPlugin();
	virtual ~MpressPlugin() override;

	virtual void prepare() override;
	virtual void unpack() override;
	virtual void cleanup() override;

private:
	bool decompressData(unpacker::DynamicBuffer& compressedContent, unpacker::DynamicBuffer& decompressedContent);
	void decodeLzmaProperties(unpacker::DynamicBuffer& compressedContent, std::uint8_t& pb, std::uint8_t& lp, std::uint8_t& lc);
	std::uint32_t getFixStub();
	void fixJumpsAndCalls(unpacker::DynamicBuffer& buffer);
	void fixImportsAndEp(unpacker::DynamicBuffer& buffer);
	void offsetAnalysis(const unpacker::DynamicBuffer& buffer);
	void trailingBytesAnalysis(const unpacker::DynamicBuffer& buffer);
	void fixRelocations();
	MpressUnpackerStub detectUnpackerStubVersion();
	MpressFixStub detectFixStubVersion(unpacker::DynamicBuffer& unpackedContent);
	void saveFile(const std::string& fileName, unpacker::DynamicBuffer& content);
	void copySectionFromOriginalFile(std::uint32_t origSectIndex, const std::string& newFileName, std::uint32_t newSectIndex);

	std::unique_ptr<retdec::loader::Image> _file;
	PeLib::PeFile32* _peFile;
	MpressUnpackerStub _unpackerStub;
	MpressFixStub _fixStub;
	const retdec::loader::Segment* _packedContentSect;
	std::uint32_t _addedSectionCount;

	std::uint32_t _iatVa, _iatSize;
	std::uint32_t _oepVa;
	std::uint32_t _importHintsOffset;
};

} // namespace mpress
} // namespace unpackertool
} // namespace retdec

#endif
