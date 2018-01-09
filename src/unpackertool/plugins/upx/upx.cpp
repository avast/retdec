/**
 * @file src/unpackertool/plugins/upx/upx.cpp
 * @brief Unpacker plugin for UPX packer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>

#include <elfio/elfio.hpp>
#include <pelib/PeLib.h>

#include "retdec/loader/loader.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"
#include "retdec/unpacker/unpacker_exception.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
UpxPlugin::UpxPlugin() : _file(), _stub()
{
	info.name          = "UPX";
	info.pluginVersion = "1.0";
	info.packerVersion = R"/(.*)/";
	info.author        = "Marek Milkovic";
}

/**
 * Destructor.
 */
UpxPlugin::~UpxPlugin()
{
	cleanup();
}

/**
 * Performs preparation of unpacking.
 */
void UpxPlugin::prepare()
{
	_file = retdec::loader::createImage(getStartupArguments()->inputFile);
	if (!_file)
		throw UnsupportedFileException();

	// We need to do these kind of checks here because createStub may fail and it always throws UnsupportedStubException.
	// However, we want more specific errors if we can say for sure without creating the stub first.
	switch (_file->getFileFormat()->getFileFormat())
	{
		case retdec::fileformat::Format::PE:
		{
			// We do not support files that doesn't have EP section set
			if (!_file->getEpSegment())
				throw NoEntryPointException();

			// If we got here and EP section is seciont with index 0, this file was with high probability memory dumped and should not be unpacked at all.
			if (_file->getEpSegment()->getSecSeg()->getIndex() == 0)
				throw FileMemoryDumpedException();

			// Check whether the EP section is section with index 1
			if (_file->getEpSegment()->getSecSeg()->getIndex() != 1)
				throw NotPackedWithUpxException();

			break;
		}
		case retdec::fileformat::Format::ELF:
		{
			// We need to have EP segment for unpacking
			if (!_file->getEpSegment())
				throw NoEntryPointException();

			break;
		}
		case retdec::fileformat::Format::MACHO:
			break;
		default:
			throw UnsupportedFileException();
	}

	_stub = UpxStub::createStub(_file.get());
}

/**
 * Starts unpacking in the current plugin.
 */
void UpxPlugin::unpack()
{
	log("Started unpacking of file '", _file->getFileFormat()->getPathToFile(), "'.");
	_stub->unpack(getStartupArguments()->outputFile);
}

/**
 * Performs freeing of all owned resources.
 */
void UpxPlugin::cleanup()
{
	if (_stub.get() != nullptr)
		_stub->cleanup();
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
