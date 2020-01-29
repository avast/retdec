/**
 * @file tests/config/classes_tests.cpp
 * @brief Tests for the @c classes module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/class.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace common {
namespace tests {

class ClassesTests: public Test {};

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
} // namespace common
} // namespace retdec
