/**
* @file tests/bin2llvmir/providers/tests/demangler_tests.cpp
* @brief Tests for the @c DemanglerProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/common/tool_info.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/module.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  DemanglerFacotryTests
//=============================================================================
//

/**
 * @brief Tests for the @c DemanglerFactory.
 */
class DemanglerFactoryTests: public LlvmIrTests
{

};

TEST_F(DemanglerFactoryTests, GetItanumDemangler)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto dem = DemanglerFactory::getItaniumDemangler(module.get(), &config, std::move(typeConfig));
	EXPECT_FALSE(dem->demangleToString("_Z1fi").empty());		// itanium
	EXPECT_TRUE(dem->demangleToString("?f@@YAXH@Z").empty());	// microsoft
	EXPECT_TRUE(dem->demangleToString("@f$qi").empty());		// borland
}

TEST_F(DemanglerFactoryTests, GetMicrosoftDemangler)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto dem = DemanglerFactory::getMicrosoftDemangler(module.get(), &config, std::move(typeConfig));
	EXPECT_TRUE(dem->demangleToString("_Z1fi").empty());		// itanium
	EXPECT_FALSE(dem->demangleToString("?f@@YAXH@Z").empty());	// microsoft
	EXPECT_TRUE(dem->demangleToString("@f$qi").empty());		// borland
}

TEST_F(DemanglerFactoryTests, GetBorlandDemangler)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto dem = DemanglerFactory::getBorlandDemangler(module.get(), &config, std::move(typeConfig));
	EXPECT_TRUE(dem->demangleToString("_Z1fi").empty());		// itanium
	EXPECT_TRUE(dem->demangleToString("?f@@YAXH@Z").empty());	// microsoft
	EXPECT_FALSE(dem->demangleToString("@f$qi").empty());		// borland
}

//
//=============================================================================
//  DemanglerProviderTests
//=============================================================================
//

/**
 * @brief Tests for the @c DemanglerProvider.
 */
class DemanglerProviderTests: public LlvmIrTests
{

};

TEST_F(DemanglerProviderTests, addDemanglerAddsDemanglerForModule)
{

	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto *r1 = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	auto* r2 = DemanglerProvider::getDemangler(module.get());
	Demangler* r3 = nullptr;
	bool b = DemanglerProvider::getDemangler(module.get(), r3);

	EXPECT_NE(nullptr, r1);
	EXPECT_EQ(r1, r2);
	EXPECT_EQ(r1, r3);
	EXPECT_TRUE(b);
}

TEST_F(DemanglerProviderTests, getDemanglerReturnsNullptrForUnknownModule)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	parseInput(""); // creates a different module
	auto* r1 = DemanglerProvider::getDemangler(module.get());
	Demangler* r2 = nullptr;
	bool b = DemanglerProvider::getDemangler(module.get(), r2);

	EXPECT_EQ(nullptr, r1);
	EXPECT_EQ(nullptr, r2);
	EXPECT_FALSE(b);
}

TEST_F(DemanglerProviderTests, addedDemanglerWorks)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	parseInput(R"(
		define void @_ZN9wikipedia7article8print_toERSo() {
			ret void
		}
	)");
	Value* f = getValueByName("_ZN9wikipedia7article8print_toERSo");
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto *d = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	std::string name = d->demangleToString(f->getName());
	auto func_pair = d->getPairFunction(f->getName());

	EXPECT_EQ("wikipedia::article::print_to(std::ostream&)", name);
}

TEST_F(DemanglerProviderTests, clearRemovesAllData)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	auto* r1 = DemanglerProvider::getDemangler(module.get());
	EXPECT_NE(nullptr, r1);

	DemanglerProvider::clear();
	auto* r2 = DemanglerProvider::getDemangler(module.get());
	EXPECT_EQ(nullptr, r2);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
