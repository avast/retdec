/**
* @file tests/unpacker/signature_tests.cpp
* @brief Tests for the @c signature module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/unpacker/dynamic_buffer.h"
#include "retdec/unpacker/signature.h"

using namespace ::testing;

namespace retdec {
namespace unpacker {
namespace tests {

class SignatureMatchSettingsTests : public Test {};

TEST_F(SignatureMatchSettingsTests,
InitializationWorks) {
	Signature::MatchSettings settings1;
	Signature::MatchSettings settings2(2, 3);

	EXPECT_EQ(0, settings1.getOffset());
	EXPECT_EQ(0, settings1.getSearchDistance());
	EXPECT_FALSE(settings1.isSearch());

	EXPECT_EQ(2, settings2.getOffset());
	EXPECT_EQ(3, settings2.getSearchDistance());
	EXPECT_TRUE(settings2.isSearch());
}

TEST_F(SignatureMatchSettingsTests,
GetOffsetWorks) {
	Signature::MatchSettings settings(5);

	EXPECT_EQ(5, settings.getOffset());
}

TEST_F(SignatureMatchSettingsTests,
SetOffsetWorks) {
	Signature::MatchSettings settings(5);
	EXPECT_EQ(5, settings.getOffset());

	settings.setOffset(6);
	EXPECT_EQ(6, settings.getOffset());
}

TEST_F(SignatureMatchSettingsTests,
GetSearchDistanceWorks) {
	Signature::MatchSettings settings(5, 6);

	EXPECT_EQ(6, settings.getSearchDistance());
}

TEST_F(SignatureMatchSettingsTests,
SetSearchDistanceWorks) {
	Signature::MatchSettings settings(5, 6);
	EXPECT_EQ(6, settings.getSearchDistance());

	settings.setSearchDistance(7);
	EXPECT_EQ(7, settings.getSearchDistance());
}

TEST_F(SignatureMatchSettingsTests,
IsSearchWorks) {
	Signature::MatchSettings settings;
	settings.setSearchDistance(0);
	EXPECT_FALSE(settings.isSearch());

	settings.setSearchDistance(5);
	EXPECT_TRUE(settings.isSearch());
}

class SignatureByteTests : public Test {};

TEST_F(SignatureByteTests,
DefaultInitializationWorks) {
	Signature::Byte byte;

	EXPECT_EQ(Signature::Byte::Type::NORMAL, byte.getType());
	EXPECT_EQ(0, byte.getExpectedValue());
	EXPECT_EQ(0, byte.getWildcardMask());
}

TEST_F(SignatureByteTests,
PureByteInitializationWorks) {
	Signature::Byte byte(0x42);

	EXPECT_EQ(Signature::Byte::Type::NORMAL, byte.getType());
	EXPECT_EQ(0x42, byte.getExpectedValue());
	EXPECT_EQ(0, byte.getWildcardMask());
}

TEST_F(SignatureByteTests,
CustomInitializationWorks) {
	Signature::Byte byte(Signature::Byte::Type::WILDCARD, 0xF0, 0x0F);

	EXPECT_EQ(Signature::Byte::Type::WILDCARD, byte.getType());
	EXPECT_EQ(0xF0, byte.getExpectedValue());
	EXPECT_EQ(0x0F, byte.getWildcardMask());
}

TEST_F(SignatureByteTests,
CopyInitializationWorks) {
	Signature::Byte byte(Signature::Byte::Type::CAPTURE, 0x11, 0x88);
	Signature::Byte copiedByte(byte);

	EXPECT_EQ(byte.getType(), copiedByte.getType());
	EXPECT_EQ(byte.getExpectedValue(), copiedByte.getExpectedValue());
	EXPECT_EQ(byte.getWildcardMask(), copiedByte.getWildcardMask());
}

TEST_F(SignatureByteTests,
PureByteAssignOperatorWorks) {
	Signature::Byte byte = 0x55;

	EXPECT_EQ(Signature::Byte::Type::NORMAL, byte.getType());
	EXPECT_EQ(0x55, byte.getExpectedValue());
	EXPECT_EQ(0, byte.getWildcardMask());
}

TEST_F(SignatureByteTests,
SignatureByteAssignOperatorWorks) {
	Signature::Byte byte(Signature::Byte::Type::WILDCARD, 0x01, 0x10);
	Signature::Byte copiedByte = byte;

	EXPECT_EQ(byte.getType(), copiedByte.getType());
	EXPECT_EQ(byte.getExpectedValue(), copiedByte.getExpectedValue());
	EXPECT_EQ(byte.getWildcardMask(), copiedByte.getWildcardMask());
}

TEST_F(SignatureByteTests,
GetTypeWorks) {
	Signature::Byte byte(Signature::Byte::Type::WILDCARD, 0x01, 0x10);

	EXPECT_EQ(Signature::Byte::Type::WILDCARD, byte.getType());
}

TEST_F(SignatureByteTests,
GetExpectedValueWorks) {
	Signature::Byte byte(Signature::Byte::Type::WILDCARD, 0x01, 0x10);

	EXPECT_EQ(0x01, byte.getExpectedValue());
}

TEST_F(SignatureByteTests,
GetWildcardMaskWorks) {
	Signature::Byte byte(Signature::Byte::Type::WILDCARD, 0x01, 0x10);

	EXPECT_EQ(0x10, byte.getWildcardMask());
}

TEST_F(SignatureByteTests,
EqualOperatorWorks) {
	Signature::Byte byte = 0x66;

	EXPECT_EQ(0x66, byte);
}

TEST_F(SignatureByteTests,
NotEqualOperatorWorks) {
	Signature::Byte byte = 0x66;

	EXPECT_NE(0x77, byte);
}

class SignatureTests : public Test {};

TEST_F(SignatureTests,
InitializerListInitializationWorks) {
	Signature sig = { 0x01, 0x02, 0x03, ANY, CAP };

	EXPECT_EQ(5, sig.getSize());
	EXPECT_EQ(1, sig.getCaptureSize());
}

TEST_F(SignatureTests,
AssignOperatorWorks) {
	Signature sig = { 0x11, 0x12, 0x13, ANY, CAP };

	EXPECT_EQ(5, sig.getSize());
	EXPECT_EQ(1, sig.getCaptureSize());
}

TEST_F(SignatureTests,
GetSizeWorks) {
	Signature sig = { 0x20, 0x21, 0x22 };

	EXPECT_EQ(3, sig.getSize());
}

TEST_F(SignatureTests,
GetCaptureSizeWorks) {
	Signature sig = { 0x30, CAP, ANY, 0x32 };

	EXPECT_EQ(1, sig.getCaptureSize());
}

TEST_F(SignatureTests,
ExactMatchWithoutCaptureWorks) {
	Signature sig = { 0x40, 0x41, 0x42, 0x43 };
	DynamicBuffer matchedBuffer({ 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44 });

	Signature::MatchSettings settings(2);
	EXPECT_TRUE(sig.match(settings, matchedBuffer));
}

TEST_F(SignatureTests,
WildcardMatchWithoutCaptureWorks) {
	Signature sig = { 0x40, ANY, ANY, 0x43 };
	DynamicBuffer matchedBuffer1({ 0x38, 0x39, 0x40, 0xCC, 0xDD, 0x43, 0x44 });
	DynamicBuffer matchedBuffer2({ 0x38, 0x39, 0x40, 0xEE, 0xFF, 0x43, 0x44 });

	Signature::MatchSettings settings(2);
	EXPECT_TRUE(sig.match(settings, matchedBuffer1));
	EXPECT_TRUE(sig.match(settings, matchedBuffer2));
}

TEST_F(SignatureTests,
WildcardMatchWithCaptureWorks) {
	Signature sig = { 0x40, CAP, CAP, 0x43 };
	DynamicBuffer matchedBuffer1({ 0x38, 0x39, 0x40, 0xCC, 0xDD, 0x43, 0x44 });
	DynamicBuffer matchedBuffer2({ 0x38, 0x39, 0x40, 0xEE, 0xFF, 0x43, 0x44 });

	Signature::MatchSettings settings(2);
	DynamicBuffer capturedData1, capturedData2;
	EXPECT_TRUE(sig.match(settings, matchedBuffer1, capturedData1));
	EXPECT_TRUE(sig.match(settings, matchedBuffer2, capturedData2));
	EXPECT_EQ(0xDDCC, capturedData1.read<uint16_t>(0));
	EXPECT_EQ(0xFFEE, capturedData2.read<uint16_t>(0));
}

TEST_F(SignatureTests,
FailedMatchWorks) {
	Signature sig = { 0x50, 0x51, 0x52, 0x53 };
	DynamicBuffer matchedBuffer({ 0x54, 0x55, 0x56, 0x57, 0x58, 0x59 });

	Signature::MatchSettings settings(0);
	EXPECT_FALSE(sig.match(settings, matchedBuffer));
}

TEST_F(SignatureTests,
ExactSearchMatchWorks) {
	Signature sig = { 0x62, 0x63 };
	DynamicBuffer matchedBuffer({ 0x60, 0x61, 0x62, 0x63, 0x64 });

	Signature::MatchSettings settings(0, 5);
	EXPECT_TRUE(sig.match(settings, matchedBuffer));
}

TEST_F(SignatureTests,
WildcardSearchMatchWithoutCaptureWorks) {
	Signature sig = { 0x62, ANY };
	DynamicBuffer matchedBuffer1({ 0x60, 0x61, 0x62, 0xEE, 0x64 });
	DynamicBuffer matchedBuffer2({ 0x60, 0x61, 0x62, 0xFF, 0x64 });

	Signature::MatchSettings settings(0, 5);
	EXPECT_TRUE(sig.match(settings, matchedBuffer1));
	EXPECT_TRUE(sig.match(settings, matchedBuffer2));
}

TEST_F(SignatureTests,
WildcardSearchMatchWithCaptureWorks) {
	Signature sig = { 0x62, CAP };
	DynamicBuffer matchedBuffer1({ 0x60, 0x61, 0x62, 0xEE, 0x64 });
	DynamicBuffer matchedBuffer2({ 0x60, 0x61, 0x62, 0xFF, 0x64 });

	Signature::MatchSettings settings(0, 5);
	DynamicBuffer capturedData1, capturedData2;
	EXPECT_TRUE(sig.match(settings, matchedBuffer1, capturedData1));
	EXPECT_TRUE(sig.match(settings, matchedBuffer2, capturedData2));
	EXPECT_EQ(std::vector<uint8_t>({ 0xEE }), capturedData1.getBuffer());
	EXPECT_EQ(std::vector<uint8_t>({ 0xFF }), capturedData2.getBuffer());
}

TEST_F(SignatureTests,
SearchMatchWithSymbolFromPatternWorks) {
	Signature sig = { 0x11, 0x10, 0x12 };
	DynamicBuffer matchedBuffer({ 0x10, 0x11, 0x10, 0x12, 0x10, 0x13 });

	Signature::MatchSettings settings(0, 5);
	EXPECT_TRUE(sig.match(settings, matchedBuffer));
}

TEST_F(SignatureTests,
FailedSearchMatchWorks) {
	Signature sig = { 0x50, 0x51, 0x52, 0x53 };
	DynamicBuffer matchedBuffer({ 0x54, 0x55, 0x56, 0x57, 0x58, 0x59 });

	Signature::MatchSettings settings(0, 6);
	EXPECT_FALSE(sig.match(settings, matchedBuffer));
}

TEST_F(SignatureTests,
WildcardBitMatchWithoutCaptureWorks) {
	Signature sig = { 0x70, ANYB(0x03, 0xF0), 0x71 };
	DynamicBuffer okBuffer1(std::vector<uint8_t>({ 0x70, 0x73, 0x71 }));
	DynamicBuffer okBuffer2(std::vector<uint8_t>({ 0x70, 0x13, 0x71 }));
	DynamicBuffer failBuffer1(std::vector<uint8_t>({ 0x70, 0x71, 0x71 }));
	DynamicBuffer failBuffer2(std::vector<uint8_t>({0x70, 0x14, 0x71 }));

	Signature::MatchSettings settings(0);
	EXPECT_TRUE(sig.match(settings, okBuffer1));
	EXPECT_TRUE(sig.match(settings, okBuffer2));
	EXPECT_FALSE(sig.match(settings, failBuffer1));
	EXPECT_FALSE(sig.match(settings, failBuffer2));
}

TEST_F(SignatureTests,
WildcardBitMatchWithCaptureWorks) {
	Signature sig = { 0x70, CAPB(0x03, 0xF0), 0x71 };
	DynamicBuffer okBuffer1(std::vector<uint8_t>({ 0x70, 0x73, 0x71 }));
	DynamicBuffer okBuffer2(std::vector<uint8_t>({ 0x70, 0x13, 0x71 }));
	DynamicBuffer failBuffer1(std::vector<uint8_t>({ 0x70, 0x71, 0x71 }));
	DynamicBuffer failBuffer2(std::vector<uint8_t>({0x70, 0x14, 0x71 }));

	Signature::MatchSettings settings(0);
	DynamicBuffer captured1, captured2;
	EXPECT_TRUE(sig.match(settings, okBuffer1, captured1));
	EXPECT_TRUE(sig.match(settings, okBuffer2, captured2));
	EXPECT_EQ(std::vector<uint8_t>({ 0x73 }), captured1.getBuffer());
	EXPECT_EQ(std::vector<uint8_t>({ 0x13 }), captured2.getBuffer());
	EXPECT_FALSE(sig.match(settings, failBuffer1));
	EXPECT_FALSE(sig.match(settings, failBuffer2));
}

} // namespace unpacker
} // namespace retdec
} // namespace tests
