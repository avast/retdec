/**
 * @file src/unpackertool/plugins/example/example.cpp
 * @brief Example of an unpacker plugin.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "unpacker/plugin.h"
#include "unpacker/unpacker_exception.h"

using namespace unpacker;

namespace unpackertool {
namespace example {

class ExamplePlugin : public Plugin
{
public:
	ExamplePlugin() {}

	virtual ~ExamplePlugin() override {}

	/**
	 * Initialization of plugin providing @ref Plugin::Info data.
	 */
	virtual void init() override
	{
		info.name = "Example Unpacker";
		info.pluginVersion = "1.0";
		info.packerVersion = "Example Version";
		info.author = "Example Author";
	}

	/**
	 * Performs preparation of unpacking.
	 */
	virtual void prepare() override
	{
		throw UnsupportedInputException("This is just an example plugin.");
	}

	/**
	 * Performs unpacking of inputFile into outputFile.
	 */
	virtual void unpack() override
	{
		throw UnsupportedInputException("This is just an example plugin.");
	}

	/**
	 * Performs freeing of all owned resources.
	 */
	virtual void cleanup() override
	{
	}
};

REGISTER_PLUGIN(ExamplePlugin)

} // namespace example
} // namespace unpackertool
