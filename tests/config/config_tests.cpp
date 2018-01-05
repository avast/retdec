/**
 * @file tests/config/config_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/config.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

class ConfigTests : public Test
{
	protected:
		Config config;
};

TEST_F(ConfigTests, ReadNonexistentFileThrowsAnException)
{
	ASSERT_THROW(config.readJsonFile("/non/existing/file"), FileNotFoundException);
}

TEST_F(ConfigTests, ParsingBadInputThrowsAnException)
{
	ASSERT_THROW(config.readJsonString("{ bad content }"), ParseException);
}

TEST_F(ConfigTests, FailedReadJsonFileClearsConfigFileName)
{
	std::string name = "/some/file/name";

	ASSERT_THROW(config.readJsonFile(name), FileNotFoundException);

	EXPECT_TRUE(config.getConfigFileName().empty());
}

TEST_F(ConfigTests, ReadJsonStringCanReadEmptyJson)
{
	ASSERT_NO_THROW(config.readJsonString("{}"));
}

TEST_F(ConfigTests, FailedReadJsonStringKeepsAllConfigData)
{
	std::string in1 = "/input/1";
	std::string abi = "/abi/path";
	std::string jsonContent = "{ bad content }";
	config.setInputFile(in1);
	config.parameters.abiPaths.insert(abi);

	ASSERT_THROW(config.readJsonString(jsonContent), ParseException);

	EXPECT_EQ(in1, config.getInputFile());
	std::set<std::string> expectedAbiPaths{abi};
	EXPECT_EQ(expectedAbiPaths, config.parameters.abiPaths);
}

TEST_F(ConfigTests, SuccessfulReadJsonStringResetsAllConfigData)
{
	std::string in1 = "/input/1";
	std::string in2 = "/input/2";
	std::string jsonContent = "{ \"inputFile\" : \"" + in2 + "\" }";
	config.setInputFile(in1);
	config.setUnpackedInputFile("unpacked");
	config.parameters.abiPaths.insert("/abi/path");

	ASSERT_NO_THROW(config.readJsonString(jsonContent));

	EXPECT_EQ(in2, config.getInputFile());
	EXPECT_EQ("", config.getUnpackedInputFile());
	EXPECT_TRUE(config.parameters.abiPaths.empty());
}

TEST_F(ConfigTests, ClassesGetElementByIdReturnsNullPointerWhenThereIsNoSuchClass)
{
	ASSERT_EQ(nullptr, config.classes.getElementById("ClassName"));
}

} // namespace tests
} // namespace config
} // namespace retdec
