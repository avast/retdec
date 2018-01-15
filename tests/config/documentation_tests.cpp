/**
 * @file tests/config/documentation_tests.cpp
 * @brief Tests for code used in documentation.
 *        This just test the code can be compiled.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <gtest/gtest.h>

#include "retdec/config/config.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

class DocTests : public Test
{

};

std::string createJson()
{
	// Create an empty config file.
	// All config entries are initialized to their default values.
	retdec::config::Config config;

	// Fill some basic information in to the file.
	// Nothing complicated yet, a lot of stuff can be set only by using
	// simple set*() methods.
	config.architecture.setIsMips();
	config.architecture.setIsEndianLittle();
	config.fileType.setIsExecutable();
	config.fileFormat.setIsElf32();

	// Some set*() methods need a value to set.
	config.setImageBase(0x1000);
	config.parameters.setOutputFile("/decompilation/output/file.c");

	// Other members are containers in which we can insert values.
	config.parameters.abiPaths.insert("/path/to/abi");
	config.parameters.selectedRanges.insert( retdec::config::AddressRangeJson(0x1000, 0x2000) );

	// Some containers need a little bit more work to properly fill up.
	// Here we create a function name 'my_function', set its calling convention
	// and add parameter and local variable into it.
	// Do not forget to add the function into config function container.
	retdec::config::Function fnc("my_function");
	fnc.callingConvention.setIsStdcall();

	retdec::config::Object param("param", retdec::config::Storage::undefined());
	param.type.setLlvmIr("i32");

	retdec::config::Object local("local", retdec::config::Storage::onStack(-20));
	param.type.setLlvmIr("i8*");

	fnc.parameters.insert(param);
	fnc.locals.insert(local);

	config.functions.insert(fnc);

	// Finally, we can serialize the config instance into a JSON string.
	std::string json = config.generateJsonString();

	// We return this JSON string, so that others can use it.
	return json;
}

void parseJson(const std::string& json)
{
	std::stringstream out;

	// We again create an empty config file.
	// We can initialize it manually like in the createJson() function,
	// or by JSON string or JSON file like in this function.
	retdec::config::Config config;

	// String used in initialization must contain a valid JSON string.
	// Empty JSON string is valid.
	// It does not have to contain any obligatory values.
	// Any missing values are set to default.
	config.readJsonString("{}");

	// Therefore, it might contain very little (or none) information.
	config.readJsonString("{ \"inputPath\" : \"/input/path\" }");

	// We can parse any JSON string.
	// Any successful parsing by readJsonString() or readJsonFile() resets
	// all existing values to their defaults before setting them again.
	// Therefore, no previously set data survive these methods.
	// For example, this call will reset "inputPath" property set in the
	// previous line.
	config.readJsonString(json);

	// Now we can access all information from the file.
	out << config.architecture.getName() << "\n";
	out << config.architecture.isMips() << "\n";
	out << config.parameters.getOutputFile() << "\n";

	retdec::config::Function* fnc = config.functions.getFunctionByName("my_function");
	if (fnc)
	{
		out << fnc->getName() << "\n";
	}
}

/**
 * Does not test anything, just make sure it can compile.
 */
TEST_F(DocTests, TestDocumentationsCompleteExample)
{
	std::string json = createJson();
	parseJson(json);
}

} // namespace tests
} // namespace config
} // namespace retdec
