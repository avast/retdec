/**
 * @file tests/serdes/classe_tests.cpp
 * @brief Tests for the class module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <json/json.h>

#include "retdec/common/class.h"
#include "retdec/serdes/class.h"

using namespace ::testing;

namespace retdec {
namespace serdes {
namespace tests {

class ClassTests : public Test
{
	protected:
		common::Class cl;
};

TEST_F(ClassTests, ClassIsParsedCorrectlyFromJSONWhenClassIsFullySpecified)
{
	std::istringstream input(R"({
			"name" : "A",
			"constructors" : [ "Actor" ],
			"destructors" : [ "Adtor" ],
			"methods" : [ "Amethod" ],
			"superClasses" : [ "Asuper" ],
			"virtualMethods" : [ "Avirtual" ],
			"virtualTables" : [ "Avtable" ]
	})");
	Json::Value val;
	std::string errs;
	Json::CharReaderBuilder rbuilder;
	bool success = Json::parseFromStream(rbuilder, input, &val, &errs);
	ASSERT_TRUE(success);

	deserialize(val, cl);

	EXPECT_EQ("A", cl.getName());
	EXPECT_EQ(std::set<std::string>({"Actor"}), cl.constructors);
	EXPECT_EQ(std::set<std::string>({"Adtor"}), cl.destructors);
	EXPECT_EQ(std::set<std::string>({"Amethod"}), cl.methods);
	EXPECT_EQ(std::vector<std::string>({"Asuper"}), cl.getSuperClasses());
	EXPECT_EQ(std::set<std::string>({"Avirtual"}), cl.virtualMethods);
	EXPECT_EQ(std::set<std::string>({"Avtable"}), cl.virtualTables);
}

TEST_F(ClassTests, ClassIsParsedCorrectlyFromJSONWhenClassHasOnlyNameSpecified)
{
	std::istringstream input(R"({
			"name" : "A"
	})");
	Json::Value val;
	std::string errs;
	Json::CharReaderBuilder rbuilder;
	bool success = Json::parseFromStream(rbuilder, input, &val, &errs);
	ASSERT_TRUE(success);

	deserialize(val, cl);

	EXPECT_EQ("A", cl.getName());
	EXPECT_TRUE(cl.constructors.empty());
	EXPECT_TRUE(cl.destructors.empty());
	EXPECT_TRUE(cl.methods.empty());
	EXPECT_TRUE(cl.getSuperClasses().empty());
	EXPECT_TRUE(cl.virtualMethods.empty());
	EXPECT_TRUE(cl.virtualTables.empty());
}

} // namespace tests
} // namespace serdes
} // namespace retdec
