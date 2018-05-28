/**
 * @file src/unpackertool/plugins/upx/upx_stub_signatures.h
 * @brief UPX stub signatures declarations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_UPX_STUB_SIGNATURES_H
#define UNPACKERTOOL_PLUGINS_UPX_UPX_STUB_SIGNATURES_H

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/signature.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Data of the UPX unpacking stub used to match the right version.
 */
struct UpxStubData
{
	retdec::fileformat::Architecture architecture; ///< Architecture this unpacking stub occures on.
	retdec::fileformat::Format format; ///< File format this unpacking stub occures in.
	retdec::unpacker::Signature* signature; ///< Signature of this unpacking stub.
	UpxStubVersion version; ///< Version this unpacking stub associates with.
	std::uint32_t size; ///< Size of the whole unpacking stub. Not used on ELF, only on PE.
	std::uint32_t searchDistance; ///< In case of non-fixed position of the signature, this field is used for searching around EP offset with this distance.
};

/**
 * Static class that is used to match the all supported unpacking stub signatures against the input packed file.
 *
 * To add new UPX signature follow these steps:
 * 1. Create signature in upx_stub_signature.cpp in the right section according to comments or create your own section if it is not present.
 *    @code
 *    Signature archFormatVersionSignature =
 *    {
 *        0x00, 0x01, 0x02, ANY, CAP
 *    };
 *    @endcode
 * 2. Add signature into @ref allStubs. Provide right retdec::fileformat::Architecture, retdec::fileformat::FileFormat and retdec::unpacker::upx::UpxStubVersion.
 *    PE signature also require their whole size to be provided. ELF does not require this. If you signature is located at the variable offset from
 *    entry point, you also need to provide maximum search distance. See @ref UpxStubData for further details.
 *
 * Make sure your signature provide all required data according to implementation of UpxStub::detectVersion for specific file format.
 * Check these methods first to see what kind of data your signature need to capture.
 */
class UpxStubSignatures
{
public:
	UpxStubSignatures() = delete;
	UpxStubSignatures(const UpxStubSignatures&) = delete;
	~UpxStubSignatures();

	static const UpxStubData* matchSignatures(retdec::loader::Image* file, retdec::unpacker::DynamicBuffer& captureData);
	static const UpxStubData* matchSignatures(const retdec::unpacker::DynamicBuffer& data, retdec::unpacker::DynamicBuffer& captureData,
			retdec::fileformat::Architecture architecture = retdec::fileformat::Architecture::UNKNOWN, retdec::fileformat::Format format = retdec::fileformat::Format::UNKNOWN);

private:
	UpxStubSignatures& operator =(const UpxStubSignatures&);

	static std::vector<UpxStubData> allStubs; ///< All supported unpacking stubs.
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
