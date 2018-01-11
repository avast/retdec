/**
 * @file src/unpackertool/plugins/example/example.h
 * @brief Example of an unpacker plugin.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_EXAMPLE_EXAMPLE_H
#define UNPACKERTOOL_PLUGINS_EXAMPLE_EXAMPLE_H

#include "retdec/unpacker/plugin.h"
#include "retdec/unpacker/unpacker_exception.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace example {

class ExamplePlugin : public Plugin
{
public:
	ExamplePlugin();
	virtual ~ExamplePlugin() override;

	virtual void prepare() override;
	virtual void unpack() override;
	virtual void cleanup() override;
};

} // namespace example
} // namespace unpackertool
} // namespace retdec

#endif
