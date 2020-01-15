/**
 * @file tests/serdes/classe_tests.cpp
 * @brief Tests for the class module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include <rapidjson/error/en.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

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
	std::string input(R"({
			"name" : "A",
			"constructors" : [ "Actor" ],
			"destructors" : [ "Adtor" ],
			"methods" : [ "Amethod" ],
			"superClasses" : [ "Asuper" ],
			"virtualMethods" : [ "Avirtual" ],
			"virtualTables" : [ "Avtable" ]
	})");
	rapidjson::Document root;
	rapidjson::ParseResult ok = root.Parse(input);
	ASSERT_TRUE(ok);

	deserialize(root, cl);

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
	std::string input(R"({
			"name" : "A"
	})");
	rapidjson::Document root;
	rapidjson::ParseResult ok = root.Parse(input);
	ASSERT_TRUE(ok);

	deserialize(root, cl);

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
