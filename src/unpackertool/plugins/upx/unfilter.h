/**
 * @file src/unpackertool/plugins/upx/unfilter.h
 * @brief Declaration of jump unfilters for UPX.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_UNFILTER_H
#define UNPACKERTOOL_PLUGINS_UPX_UNFILTER_H

#include "retdec/unpacker/dynamic_buffer.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Enumeration of all supported filters.
 */
enum Filters
{
	FILTER_NONE     = 0x0,
	FILTER_11       = 0x11,
	FILTER_16       = 0x16,
	FILTER_24       = 0x24,
	FILTER_26       = 0x26,
	FILTER_46       = 0x46,
	FILTER_49       = 0x49,
	FILTER_50       = 0x50,
	FILTER_D0       = 0xD0,
	FILTER_UNKNOWN  = 0xFF,
};

/**
 * Base abstract class for all unfiltering objects.
 */
struct Unfilter
{
	virtual ~Unfilter() {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) = 0;

	static bool run(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterId, std::uint32_t filterParam, std::uint32_t filterCount = 0, std::uint32_t startOffset = 0, std::uint32_t size = 0);
};

/**
 * Filter 11. Unfilter CALL instructions on x86.
 */
struct Unfilter11 : public Unfilter
{
	virtual ~Unfilter11() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter 16. Unfilter JMP and CALL instructions on x86.
 */
struct Unfilter16 : public Unfilter
{
	virtual ~Unfilter16() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter 24. Unfilter CALL instructions on x86 (with parameter).
 */
struct Unfilter24 : public Unfilter
{
	virtual ~Unfilter24() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter 26/46. Unfilter JMP and CALL instructions on x86 (with parameter).
 */
struct Unfilter26_46 : public Unfilter
{
	virtual ~Unfilter26_46() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter 49. Unfilter JMP, CALL and Jcc instructions on x86 (with parameter).
 */
struct Unfilter49 : public Unfilter
{
	virtual ~Unfilter49() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter 50. Unfilter Bcc with link instructions on ARM.
 */
struct Unfilter50 : public Unfilter
{
	virtual ~Unfilter50() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

/**
 * Filter D0. Unfiler Bx instructions on PowerPC (with parameter).
 */
struct UnfilterD0 : public Unfilter
{
	virtual ~UnfilterD0() override {}

	virtual void perform(retdec::unpacker::DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size) override;
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
