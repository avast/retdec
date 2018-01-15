/**
 * @file tests/config/classes_tests.cpp
 * @brief Tests for the @c classes module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/classes.h"
#include "retdec/config/config.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace config {
namespace tests {

class ClassesTests: public Test {};

//
// Parsing
//

TEST_F(ClassesTests,
ClassesAreEmptyWhenConfigIsCreated) {
	Config config;
	ASSERT_TRUE(config.classes.empty());
}

TEST_F(ClassesTests,
NoClassesAreParsedCorrectly) {
	Config config;

	config.readJsonString(R"({
		"classes" : []
	})");

	ASSERT_TRUE(config.classes.empty());
}

TEST_F(ClassesTests,
ClassIsParsedCorrectlyFromJSONWhenClassIsFullySpecified) {
	Config config;

	config.readJsonString(R"({
		"classes" : [
			{
				"name" : "A",
				"constructors" : [ "Actor" ],
				"destructors" : [ "Adtor" ],
				"methods" : [ "Amethod" ],
				"superClasses" : [ "Asuper" ],
				"virtualMethods" : [ "Avirtual" ],
				"virtualTables" : [ "Avtable" ]
			}
		]
	})");

	ASSERT_EQ(1, config.classes.size());
	auto cl = *config.classes.begin();
	EXPECT_EQ("A", cl.getName());
	EXPECT_EQ(std::set<std::string>({"Actor"}), cl.constructors);
	EXPECT_EQ(std::set<std::string>({"Adtor"}), cl.destructors);
	EXPECT_EQ(std::set<std::string>({"Amethod"}), cl.methods);
	EXPECT_EQ(std::vector<std::string>({"Asuper"}), cl.getSuperClasses());
	EXPECT_EQ(std::set<std::string>({"Avirtual"}), cl.virtualMethods);
	EXPECT_EQ(std::set<std::string>({"Avtable"}), cl.virtualTables);
}

TEST_F(ClassesTests,
ClassIsParsedCorrectlyFromJSONWhenClassHasOnlyNameSpecified) {
	Config config;

	config.readJsonString(R"({
		"classes" : [
			{
				"name" : "A"
			}
		]
	})");

	ASSERT_EQ(1, config.classes.size());
	auto cl = *config.classes.begin();
	EXPECT_EQ("A", cl.getName());
	EXPECT_TRUE(cl.constructors.empty());
	EXPECT_TRUE(cl.destructors.empty());
	EXPECT_TRUE(cl.methods.empty());
	EXPECT_TRUE(cl.getSuperClasses().empty());
	EXPECT_TRUE(cl.virtualMethods.empty());
	EXPECT_TRUE(cl.virtualTables.empty());
}

//
// hasConstructor()
//

TEST_F(ClassesTests,
HasConstructorReturnsFalseWhenClassDoesNotHaveConstructorWithGivenName) {
	Class cl("A"s);
	cl.constructors = {};

	ASSERT_FALSE(cl.hasConstructor("func"));
}

TEST_F(ClassesTests,
HasConstructorReturnsTrueWhenClassHasConstructorWithGivenName) {
	Class cl("A"s);
	cl.constructors = {"func"};

	ASSERT_TRUE(cl.hasConstructor("func"));
}

//
// hasDestructor()
//

TEST_F(ClassesTests,
HasDestructorReturnsFalseWhenClassDoesNotHaveDestructorWithGivenName) {
	Class cl("A"s);
	cl.destructors = {};

	ASSERT_FALSE(cl.hasDestructor("func"));
}

TEST_F(ClassesTests,
HasDestructorReturnsTrueWhenClassHasDestructorWithGivenName) {
	Class cl("A"s);
	cl.destructors = {"func"};

	ASSERT_TRUE(cl.hasDestructor("func"));
}

//
// hasMethod()
//

TEST_F(ClassesTests,
HasMethodReturnsFalseWhenClassDoesNotHaveMethodWithGivenName) {
	Class cl("A"s);
	cl.methods = {};

	ASSERT_FALSE(cl.hasMethod("func"));
}

TEST_F(ClassesTests,
HasMethodReturnsTrueWhenClassHasMethodWithGivenName) {
	Class cl("A"s);
	cl.methods = {"func"};

	ASSERT_TRUE(cl.hasMethod("func"));
}

TEST_F(ClassesTests,
HasMethodDoesNotConsiderVirtualMethods) {
	Class cl("A"s);
	cl.methods = {};
	cl.virtualMethods = {"func"};

	ASSERT_FALSE(cl.hasMethod("func"));
}

//
// hasVirtualMethod()
//

TEST_F(ClassesTests,
HasVirtualMethodReturnsFalseWhenClassDoesNotHaveVirtualMethodWithGivenName) {
	Class cl("A"s);
	cl.virtualMethods = {};

	ASSERT_FALSE(cl.hasVirtualMethod("func"));
}

TEST_F(ClassesTests,
HasVirtualMethodReturnsTrueWhenClassHasVirtualMethodWithGivenName) {
	Class cl("A"s);
	cl.virtualMethods = {"func"};

	ASSERT_TRUE(cl.hasVirtualMethod("func"));
}

//
// hasFunction()
//

TEST_F(ClassesTests,
HasFunctionReturnsFalseWhenClassDoesNotHaveFunction) {
	Class cl("A"s);

	ASSERT_FALSE(cl.hasFunction("func"));
}

TEST_F(ClassesTests,
HasFunctionReturnsTrueWhenClassHasConstructorWithGivenName) {
	Class cl("A"s);
	cl.constructors.insert("func");

	ASSERT_TRUE(cl.hasFunction("func"));
}

TEST_F(ClassesTests,
HasFunctionReturnsTrueWhenClassHasDestructorWithGivenName) {
	Class cl("A"s);
	cl.destructors.insert("func");

	ASSERT_TRUE(cl.hasFunction("func"));
}

TEST_F(ClassesTests,
HasFunctionReturnsTrueWhenClassHasMethodWithGivenName) {
	Class cl("A"s);
	cl.methods.insert("func");

	ASSERT_TRUE(cl.hasFunction("func"));
}

TEST_F(ClassesTests,
HasFunctionReturnsTrueWhenClassHasVirtualMethodWithGivenName) {
	Class cl("A"s);
	cl.virtualMethods.insert("func");

	ASSERT_TRUE(cl.hasFunction("func"));
}

//
// operator==()
//

TEST_F(ClassesTests,
OperatorEqualComparesClassNames) {
	EXPECT_TRUE(Class("A"s) == Class("A"s));
	EXPECT_FALSE(Class("A"s) == Class("B"s));
}

//
// operator<()
//

TEST_F(ClassesTests,
OperatorLessComparesClassNames) {
	EXPECT_TRUE(Class("A"s) < Class("B"s));
	EXPECT_FALSE(Class("B"s) < Class("A"s));
}

//
// addSuperClass()
//

TEST_F(ClassesTests,
AddSuperClassAddsClassesInOrder) {
	Class cl("A"s);
	cl.addSuperClass("B"s);
	cl.addSuperClass("C"s);
	cl.addSuperClass("D"s);

	EXPECT_EQ(std::vector<std::string>({"B", "C", "D"}), cl.getSuperClasses());
}

TEST_F(ClassesTests,
AddSuperClassDoesNotAddSameSuperclassTwice) {
	Class cl("A"s);
	cl.addSuperClass("B"s);
	cl.addSuperClass("B"s);

	EXPECT_EQ(std::vector<std::string>({"B"}), cl.getSuperClasses());
}

} // namespace tests
} // namespace config
} // namespace retdec
