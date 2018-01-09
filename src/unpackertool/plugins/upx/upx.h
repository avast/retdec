/**
 * @file src/unpackertool/plugins/upx/upx.h
 * @brief Unpacker plugin for UPX packer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_UPX_H
#define UNPACKERTOOL_PLUGINS_UPX_UPX_H

#include <memory>

#include "retdec/loader/loader.h"
#include "retdec/unpacker/plugin.h"
#include "unpackertool/plugins/upx/upx_stub.h"

#define upx_plugin plugin(retdec::unpackertool::upx::UpxPlugin)

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * UPX unpacking plugin.
 *
 * This plugins starts in UpxPlugin::unpack method as every other unpacking plugin.
 * It creates right version of UpxStub object (PeUpxStub or ElfUpxStub) Depending on the input file format.
 * Virtual method UpxStub::detectVersion is called to check what version of unpacking stub is present in the file.
 * In the end, UpxStub::run is called to perform unpacking.
 *
 * If you want to add support for new versions of UPX, check file @ref UpxStubSignatures.
 */
class UpxPlugin : public Plugin
{
public:
	UpxPlugin();
	virtual ~UpxPlugin();

	virtual void prepare() override;
	virtual void unpack() override;
	virtual void cleanup() override;

private:
	std::unique_ptr<retdec::loader::Image> _file; ///< Packed input file.
	std::shared_ptr<UpxStub> _stub; ///< Correct version of unpacking stub.
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
