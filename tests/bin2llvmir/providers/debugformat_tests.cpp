/**
* @file tests/bin2llvmir/providers/tests/debugformat_tests.cpp
* @brief Tests for the @c DebugFormatProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/providers/debugformat.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/loader/image_factory.h"
#include "retdec/loader/loader/raw_data/raw_data_image.h"

using namespace ::testing;
using namespace llvm;
using namespace retdec::debugformat;
using namespace retdec::fileformat;
using namespace retdec::loader;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c DebugFormatProvider pass.
 */
class DebugFormatProviderTests: public LlvmIrTests
{

};

TEST_F(DebugFormatProviderTests, addDebugFormatAddsDebugFormatForModule)
{
	std::stringstream emptySs;
	auto format = std::make_unique<RawDataFormat>(emptySs);
	if (format == nullptr)
	{
		throw std::runtime_error("failed to create RawDataFormat");
	}
	std::shared_ptr<RawDataFormat> formatShared(std::move(format));
	auto image = createImage(formatShared);
	if (image == nullptr)
	{
		throw std::runtime_error("failed to load RawDataImage");
	}
	auto* r1 = DebugFormatProvider::addDebugFormat(
			module.get(),
			image.get(),
			"",
			0x0,
			nullptr);
	auto* r2 = DebugFormatProvider::getDebugFormat(module.get());
	DebugFormat* r3 = nullptr;
	bool b = DebugFormatProvider::getDebugFormat(module.get(), r3);

	EXPECT_NE(nullptr, r1);
	EXPECT_EQ(r1, r2);
	EXPECT_EQ(r1, r3);
	EXPECT_TRUE(b);
}

TEST_F(DebugFormatProviderTests, addDebugFormatReturnNullptrIfFileImageNotProvided)
{
	auto* r1 = DebugFormatProvider::addDebugFormat(
			module.get(),
			nullptr,
			"",
			0x0,
			nullptr);

	EXPECT_EQ(nullptr, r1);
}

TEST_F(DebugFormatProviderTests, clearRemovesAllData)
{
	std::stringstream emptySs;
	auto format = std::make_unique<RawDataFormat>(emptySs);
	if (format == nullptr)
	{
		throw std::runtime_error("failed to create RawDataFormat");
	}
	std::shared_ptr<RawDataFormat> formatShared(std::move(format));
	auto image = createImage(formatShared);
	if (image == nullptr)
	{
		throw std::runtime_error("failed to load RawDataImage");
	}
	DebugFormatProvider::addDebugFormat(
			module.get(),
			image.get(),
			"",
			0x0,
			nullptr);
	auto* r1 = DebugFormatProvider::getDebugFormat(module.get());
	EXPECT_NE(nullptr, r1);

	DebugFormatProvider::clear();
	auto* r2 = DebugFormatProvider::getDebugFormat(module.get());
	EXPECT_EQ(nullptr, r2);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
