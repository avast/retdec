/**
 * @file src/unpackertool/plugins/example/example.cpp
 * @brief Example of an unpacker plugin.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/unpacker/plugin.h"
#include "retdec/unpacker/unpacker_exception.h"

#include "unpackertool/plugins/example/example.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace example {

ExamplePlugin::ExamplePlugin()
{
	info.name = "Example Unpacker";
	info.pluginVersion = "1.0";
	info.packerVersion = "Example Version";
	info.author = "Example Author";
}

ExamplePlugin::~ExamplePlugin()
{
	cleanup();
}

/**
 * Performs preparation of unpacking.
 */
void ExamplePlugin::prepare()
{
	throw UnsupportedInputException("This is just an example plugin.");
}

/**
 * Performs unpacking of inputFile into outputFile.
 */
void ExamplePlugin::unpack()
{
	throw UnsupportedInputException("This is just an example plugin.");
}

/**
 * Performs freeing of all owned resources.
 */
void ExamplePlugin::cleanup()
{
}

} // namespace example
} // namespace unpackertool
} // namespace retdec
