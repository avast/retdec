/**
* @file tests/bin2llvmir/providers/tests/fileimage_tests.cpp
* @brief Tests for the @c FileImageProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/config/tool_info.h"
#include "retdec/utils/system.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/loader/image_factory.h"
#include "retdec/loader/loader/raw_data/raw_data_image.h"

using namespace ::testing;
using namespace llvm;
using namespace retdec::fileformat;
using namespace retdec::loader;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  FileImage
//=============================================================================
//

/**
 * @brief Tests for the @c FileImage pass.
 */
class FileImageTests: public LlvmIrTests
{

};

//
//llvm::Constant* getConstant(
//		llvm::Type* type,
//		retdec::utils::Address addr)
//

TEST_F(FileImageTests, getConstantReadsCorrectValuesForI1)
{
	auto format = createFormat();
	int8_t i1 = 1;
	auto i1Pos = format->appendData(i1); // alignment

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i1Type = Type::getInt1Ty(module->getContext());
	ConstantInt* i1Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i1Type, i1Pos));
	ASSERT_NE(nullptr, i1Const);
	EXPECT_EQ(i1Type, i1Const->getType());
	EXPECT_EQ(i1, i1Const->getZExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForI8)
{
	auto format = createFormat();
	int8_t i8 = 123;
	auto i8Pos = format->appendData(i8);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i8Type = Type::getInt8Ty(module->getContext());
	ConstantInt* i8Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i8Type, i8Pos));
	ASSERT_NE(nullptr, i8Const);
	EXPECT_EQ(i8Type, i8Const->getType());
	EXPECT_EQ(i8, i8Const->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForI16)
{
	auto format = createFormat();
	int16_t i16 = 456;
	auto i16Pos = format->appendData(i16);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i16Type = Type::getInt16Ty(module->getContext());
	ConstantInt* i16Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i16Type, i16Pos));

	ASSERT_NE(nullptr, i16Const);
	EXPECT_EQ(i16Type, i16Const->getType());
	EXPECT_EQ(i16, i16Const->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForPositiveI32)
{
	auto format = createFormat();
	int32_t i32 = 789;
	auto i32Pos = format->appendData(i32);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i32Type = Type::getInt32Ty(module->getContext());
	ConstantInt* i32Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i32Type, i32Pos));

	ASSERT_NE(nullptr, i32Const);
	EXPECT_EQ(i32Type, i32Const->getType());
	EXPECT_EQ(i32, i32Const->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForNegativeI32)
{
	auto format = createFormat();
	int32_t i32 = -789;
	auto i32Pos = format->appendData(i32);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i32Type = Type::getInt32Ty(module->getContext());
	ConstantInt* i32Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i32Type, i32Pos));

	ASSERT_NE(nullptr, i32Const);
	EXPECT_EQ(i32Type, i32Const->getType());
	EXPECT_EQ(i32, i32Const->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForI64)
{
	auto format = createFormat();
	int64_t i64 = 987;
	auto i64Pos = format->appendData(i64);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* i64Type = Type::getInt64Ty(module->getContext());
	ConstantInt* i64Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			i64Type, i64Pos));

	ASSERT_NE(nullptr, i64Const);
	EXPECT_EQ(i64Type, i64Const->getType());
	EXPECT_EQ(i64, i64Const->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForHalf)
{
	auto format = createFormat();
	float f = 2.0;
	auto fPos = format->appendData(f);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* fType = Type::getHalfTy(module->getContext());
	ConstantFP* fConst = dyn_cast_or_null<ConstantFP>(image.getConstant(
			fType, fPos));

	ASSERT_NE(nullptr, fConst);
	EXPECT_EQ(fType, fConst->getType());
	EXPECT_TRUE(fConst->isExactlyValue(f));
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForFloat)
{
	auto format = createFormat();
	float f = 2.0;
	auto fPos = format->appendData(f);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* fType = Type::getFloatTy(module->getContext());
	ConstantFP* fConst = dyn_cast_or_null<ConstantFP>(image.getConstant(
			fType, fPos));

	ASSERT_NE(nullptr, fConst);
	EXPECT_EQ(fType, fConst->getType());
	EXPECT_TRUE(fConst->isExactlyValue(f));
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForDouble)
{
	auto format = createFormat();
	double d = 4.0;
	auto dPos = format->appendData(d);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* dType = Type::getDoubleTy(module->getContext());
	ConstantFP* dConst = dyn_cast_or_null<ConstantFP>(image.getConstant(
			dType, dPos));

	ASSERT_NE(nullptr, dConst);
	EXPECT_EQ(dType, dConst->getType());
	EXPECT_TRUE(dConst->isExactlyValue(d));
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForFp128)
{
	auto format = createFormat();
	double d = 4.0;
	auto dPos = format->appendData(d);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* fp128Type = Type::getFP128Ty(module->getContext());
	ConstantFP* dConst = dyn_cast_or_null<ConstantFP>(image.getConstant(
			fp128Type, dPos));

	ASSERT_NE(nullptr, dConst);
	EXPECT_EQ(fp128Type, dConst->getType());
	EXPECT_TRUE(dConst->isExactlyValue(d));
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForLongDouble)
{
	auto format = createFormat();
	if (retdec::utils::systemHasLongDouble())
	{
		long double ld = 10.0;
		auto ldPos = format->appendData(ld);

		auto c = Config::empty(module.get());
		auto image = FileImage(module.get(), format, &c);
		Type* ldType = Type::getX86_FP80Ty(module->getContext());
		ConstantFP* ldConst = dyn_cast_or_null<ConstantFP>(image.getConstant(
				ldType, ldPos));
		ASSERT_NE(nullptr, ldConst);
		EXPECT_EQ(ldType, ldConst->getType());
		EXPECT_TRUE(ldConst->isExactlyValue(ld));
	}
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForPointerType)
{
	auto format = createFormat();
	int32_t i32 = 789;
	auto i32Pos = format->appendData(i32);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* ptrType = Type::getInt32PtrTy(module->getContext());
	ConstantExpr* ptrConst = dyn_cast_or_null<ConstantExpr>(image.getConstant(
			ptrType, i32Pos));
	ASSERT_NE(nullptr, ptrConst);

	ConstantInt* intConst = dyn_cast<ConstantInt>(ptrConst->getOperand(0));
	ASSERT_NE(nullptr, intConst);

	EXPECT_EQ(i32, intConst->getSExtValue());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForStringType)
{
	auto format = createFormat();
	char str[] = "hello, how are you today?";
	auto strPos = format->appendData(str);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	Type* strType = Type::getInt8PtrTy(module->getContext());

	ConstantExpr* i8Const = dyn_cast_or_null<ConstantExpr>(
			image.getConstant(strType, strPos));
	ASSERT_NE(nullptr, i8Const);

	GlobalVariable* strGv = dyn_cast<GlobalVariable>(
			i8Const->getOperand(0));
	ASSERT_NE(nullptr, strGv);

	ConstantDataArray* strConst = dyn_cast_or_null<ConstantDataArray>(
			strGv->getInitializer());
	ASSERT_NE(nullptr, strConst);

	EXPECT_EQ(std::string(str), strConst->getAsCString().str());
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForArrayType)
{
	auto format = createFormat();
	auto pos = format->appendData(int32_t(1));
	format->appendData(int32_t(2));
	format->appendData(int32_t(3));
	format->appendData(int32_t(4));
	format->appendData(int32_t(5));
	format->appendData(int32_t(6));
	Type* i32Type = Type::getInt32Ty(module->getContext());
	Type* arrayType = ArrayType::get(i32Type, 6);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	ConstantDataArray* arrayConst = dyn_cast_or_null<ConstantDataArray>(
			image.getConstant(arrayType, pos));

	ASSERT_NE(nullptr, arrayConst);
	EXPECT_EQ(arrayType, arrayConst->getType());
	EXPECT_EQ(6, arrayConst->getNumElements());

	EXPECT_EQ(1, arrayConst->getElementAsInteger(0));
	EXPECT_EQ(2, arrayConst->getElementAsInteger(1));
	EXPECT_EQ(3, arrayConst->getElementAsInteger(2));
	EXPECT_EQ(4, arrayConst->getElementAsInteger(3));
	EXPECT_EQ(5, arrayConst->getElementAsInteger(4));
	EXPECT_EQ(6, arrayConst->getElementAsInteger(5));
}

TEST_F(FileImageTests, getConstantReadsCorrectValuesForStructureType)
{
	auto format = createFormat();
	struct s
	{
		int32_t i32;
		float f;
		double d;
	} x = {123, 3.14f, 2.71};
	auto pos = format->appendData(x);
	std::vector<Type*> vc;
	vc.push_back(Type::getInt32Ty(module->getContext()));
	vc.push_back(Type::getFloatTy(module->getContext()));
	vc.push_back(Type::getDoubleTy(module->getContext()));
	Type* type = StructType::create(vc);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	ConstantStruct* structConst = dyn_cast_or_null<ConstantStruct>(
			image.getConstant(type, pos));

	ASSERT_NE(nullptr, structConst);
	EXPECT_EQ(3, structConst->getNumOperands());
	EXPECT_EQ(123, dyn_cast<ConstantInt>(structConst->getOperand(0))->getSExtValue());
	EXPECT_TRUE(dyn_cast<ConstantFP>(structConst->getOperand(1))->isExactlyValue(3.14));
	EXPECT_TRUE(dyn_cast<ConstantFP>(structConst->getOperand(2))->isExactlyValue(2.71));
}

//
//llvm::Constant* getConstant(
//		llvm::Module* module,
//		retdec::loader::Image* objf,
//		DebugFormat* dbgf,
//		retdec::utils::Address addr)
//

TEST_F(FileImageTests, getConstantReadsDetectsAndReads32BitInteger)
{
	auto format = createFormat();
	int32_t i32 = 456;
	format->appendData(123);
	auto i32Pos = format->appendData(i32);
	format->appendData(789);

	auto c = Config::empty(module.get());
	auto image = FileImage(module.get(), format, &c);
	ConstantInt* i32Const = dyn_cast_or_null<ConstantInt>(image.getConstant(
			nullptr, nullptr, i32Pos));

	ASSERT_NE(nullptr, i32Const);
	EXPECT_EQ(i32, i32Const->getSExtValue());
}

//
//=============================================================================
//  FileImageProviderTests
//=============================================================================
//

/**
 * @brief Tests for the @c FileFileProvider pass.
 */
class FileImageProviderTests: public LlvmIrTests
{

};

TEST_F(FileImageProviderTests, addFileImageAddsFileImageForModule)
{
	std::stringstream emptySs;
	auto format = std::make_unique<RawDataFormat>(emptySs);
	if (format == nullptr)
	{
		throw std::runtime_error("failed to create RawDataFormat");
	}
	std::shared_ptr<RawDataFormat> formatShared(std::move(format));
	auto c = Config::empty(module.get());
	auto* r1 = FileImageProvider::addFileImage(module.get(), formatShared, &c);
	auto* r2 = FileImageProvider::getFileImage(module.get());
	FileImage* r3 = nullptr;
	bool b = FileImageProvider::getFileImage(module.get(), r3);

	EXPECT_NE(nullptr, r1);
	EXPECT_EQ(r1, r2);
	EXPECT_EQ(r1, r3);
	EXPECT_TRUE(b);
}

// TODO: If we checked throw message here, we could replace regression tests
// service.decompiler.errors.NoSectionsOrSegmentsErrorTest
// with this unit test.
//
TEST_F(FileImageProviderTests, addFileImageThrowsForModuleWhenBadPathProvided)
{
	std::string path = "/this/is/a/bad/path";
	auto c = Config::empty(module.get());
	ASSERT_ANY_THROW(FileImageProvider::addFileImage(module.get(), path, &c));
}

TEST_F(FileImageProviderTests, clearRemovesAllData)
{
	std::stringstream emptySs;
	auto format = std::make_unique<RawDataFormat>(emptySs);
	if (format == nullptr)
	{
		throw std::runtime_error("failed to create RawDataFormat");
	}
	std::shared_ptr<RawDataFormat> formatShared(std::move(format));
	auto c = Config::empty(module.get());
	FileImageProvider::addFileImage(module.get(), formatShared, &c);
	auto* r1 = FileImageProvider::getFileImage(module.get());
	EXPECT_NE(nullptr, r1);

	FileImageProvider::clear();
	auto* r2 = FileImageProvider::getFileImage(module.get());
	EXPECT_EQ(nullptr, r2);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
