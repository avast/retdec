/**
 * @file src/unpackertool/plugins/upx/unfilter.cpp
 * @brief Implementation of jump unfilters for UPX.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>

#include "unpackertool/plugins/upx/unfilter.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Runs the specified unfiltering on the provided data.
 *
 * @param unpackedData Data to unfilter.
 * @param filterId ID of the filter that is used.
 * @param filterParam Parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter. 0 means unlimited size (limited by size of @c unpackedData).
 *
 * @return True if the specified filter was supported, otherwise false.
 */
bool Unfilter::run(DynamicBuffer& unpackedData, std::uint32_t filterId, std::uint32_t filterParam, std::uint32_t filterCount /*= 0*/, std::uint32_t startOffset/* = 0*/, std::uint32_t size/* = 0*/)
{
	std::unique_ptr<Unfilter> unfilter;
	switch (filterId)
	{
		case FILTER_NONE: // No filter used, just end successfully
			return true;
		case FILTER_11:
			unfilter = std::make_unique<Unfilter11>();
			break;
		case FILTER_16:
			unfilter = std::make_unique<Unfilter16>();
			break;
		case FILTER_24:
			unfilter = std::make_unique<Unfilter24>();
			break;
		case FILTER_26:
		case FILTER_46:
			unfilter = std::make_unique<Unfilter26_46>();
			break;
		case FILTER_49:
			unfilter = std::make_unique<Unfilter49>();
			break;
		case FILTER_50:
			unfilter = std::make_unique<Unfilter50>();
			break;
		case FILTER_D0:
			unfilter = std::make_unique<UnfilterD0>();
			break;
		case FILTER_UNKNOWN:
		default:
			return false;
	}

	// This needs to be here, because there are samples with FILTER_NONE with bogus @c startOffset, but they shouldn't fail
	// Unfilter the whole buffer when invalid @c startOffset is found
	if (startOffset >= unpackedData.getRealDataSize())
		startOffset = 0;

	// If no size specified, run unfilter on the whole buffer
	if (size == 0)
		size = unpackedData.getRealDataSize() - startOffset;

	unfilter->perform(unpackedData, filterParam, filterCount, startOffset, size);
	return true;
}

/**
 * Performs unfiltering of Filter 11.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter11::perform(DynamicBuffer& unpackedData, std::uint32_t/* filterParam*/, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the opcode of an instruction
		std::uint8_t opcode = unpackedData.read<std::uint8_t>(readPos++);

		// Only CALL instruction
		if (opcode == 0xE8)
		{
			// Take its operand
			std::uint32_t operand = unpackedData.read<std::uint32_t>(readPos);

			// Unfilter
			operand -= readPos;

			// Store back to unpacked data
			unpackedData.write<std::uint32_t>(operand, readPos);
			readPos += 4;

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}
	}
}

/**
 * Performs unfiltering of Filter 16.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter16::perform(DynamicBuffer& unpackedData, std::uint32_t/* filterParam*/, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the opcode of an instruction
		std::uint8_t opcode = unpackedData.read<std::uint8_t>(readPos++);

		// JMP and CALL instruction
		if (opcode == 0xE8 || opcode == 0xE9)
		{
			// Take its operand
			std::uint32_t operand = unpackedData.read<std::uint32_t>(readPos);

			// From big to little endian
			operand = ((operand & 0xFF000000) >> 24) |
					  ((operand & 0x00FF0000) >> 8) |
					  ((operand & 0x0000FF00) << 8) |
					  ((operand & 0x000000FF) << 24);

			// Unfilter
			operand -= readPos;

			// Store back to unpacked data
			unpackedData.write<std::uint32_t>(operand, readPos);
			readPos += 4;

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}
	}
}

/**
 * Performs unfiltering of Filter 24.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter24::perform(DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the opcode of an instruction
		std::uint8_t opcode = unpackedData.read<std::uint8_t>(readPos++);

		// Only CALL instruction
		if (opcode == 0xE8)
		{
			if (unpackedData.read<std::uint8_t>(readPos) != filterParam)
				continue;

			// Take its operand
			std::uint32_t operand = unpackedData.read<std::uint32_t>(readPos);

			// From big to little endian, but cutting off lowest byte
			operand = ((operand & 0xFF000000) >> 24) |
					  ((operand & 0x00FF0000) >> 8) |
					  ((operand & 0x0000FF00) << 8);

			// Unfilter
			operand -= readPos;

			// Store back to unpacked data
			unpackedData.write<std::uint32_t>(operand, readPos);
			readPos += 4;

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}
	}
}

/**
 * Performs unfiltering of Filter 26/46.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter26_46::perform(DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the opcode of an instruction
		std::uint8_t opcode = unpackedData.read<std::uint8_t>(readPos++);

		// Look only for JMP/CALL
		if (opcode == 0xE8 || opcode == 0xE9)
		{
			if (unpackedData.read<std::uint8_t>(readPos) != filterParam)
				continue;

			// Take its operand
			std::uint32_t operand = unpackedData.read<std::uint32_t>(readPos);

			// From big to little endian, but cutting off lowest byte
			operand = ((operand & 0xFF000000) >> 24) |
					  ((operand & 0x00FF0000) >> 8) |
					  ((operand & 0x0000FF00) << 8);

			// Unfilter
			operand -= readPos;

			// Store back to the unpacked data
			unpackedData.write<std::uint32_t>(operand, readPos);
			readPos += 4;

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}
	}
}

/**
 * Performs unfiltering of Filter 49.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter49::perform(DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	std::uint32_t next = readPos;
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the opcode of an instruction
		std::uint8_t opcode = unpackedData.read<std::uint8_t>(readPos++);

		// Look only for JMP/CALL or Jcc
		if ((opcode == 0xE8 || opcode == 0xE9)
			|| (next != readPos && 0x80 <= opcode && opcode <= 0x8F && unpackedData.read<std::uint8_t>(readPos - 2) == 0xF))
		{
			if (unpackedData.read<std::uint8_t>(readPos) != filterParam)
				continue;

			// Take its operand
			std::uint32_t operand = unpackedData.read<std::uint32_t>(readPos);

			// From big to little endian, but cutting off lowest byte
			operand = ((operand & 0xFF000000) >> 24) |
					  ((operand & 0x00FF0000) >> 8) |
					  ((operand & 0x0000FF00) << 8);

			// Unfilter
			operand -= readPos;

			// Store back to the unpacked data
			unpackedData.write<std::uint32_t>(operand, readPos);
			readPos += 4;
			next = readPos + 1;

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}
	}
}

/**
 * Performs unfiltering of Filter 50.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void Unfilter50::perform(DynamicBuffer& unpackedData, std::uint32_t/* filterParam*/, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the instruction
		std::uint32_t instruction = unpackedData.read<std::uint32_t>(readPos);

		// Look only for Bcc instructions with links
		if (((instruction >> 24) & 0x0F) == 0x0B)
		{
			std::uint32_t operand = instruction & 0x00FFFFFF;

			// Unfilter
			operand -= (readPos >> 2); // divide by 4, seems like distance here is per instruction

			// Store back to the unpacked data
			instruction = (instruction & 0xFF000000) | (operand & 0x00FFFFFF);
			unpackedData.write<std::uint32_t>(instruction, readPos);

			if (useCount)
			{
				if (--filterCount == 0)
					break;
			}
		}

		readPos += 4;
	}
}

/**
 * Performs unfiltering of Filter D0.
 *
 * @param unpackedData The data to be unfiltered.
 * @param filterParam The parameter of the filter.
 * @param filterCount Number of filtered instructions. If 0, no limit is assumed.
 * @param startOffset Starting offset (relative to @c unpackedData) where to start unfiltering.
 * @param size Amount of bytes to unfilter.
 */
void UnfilterD0::perform(DynamicBuffer& unpackedData, std::uint32_t filterParam, std::uint32_t filterCount, std::uint32_t startOffset, std::uint32_t size)
{
	std::uint32_t readPos = startOffset;
	std::uint32_t endPos = std::min(startOffset + size, unpackedData.getRealDataSize());
	bool useCount = filterCount > 0;

	while (readPos < endPos)
	{
		// Read the instruction
		std::uint32_t instruction = unpackedData.read<std::uint32_t>(readPos);

		// It is Bx instruction
		if ((instruction >> 26) == 18)
		{
			if (((instruction >> 22) & 0xF) == filterParam)
			{
				// Load the operand
				std::uint32_t operand = instruction & 0x003FFFFC;

				// Unfilter
				operand -= readPos;

				// Store back to the unpacked data
				instruction = (instruction & 0xFC000003) | (operand & 0x03FFFFFC);
				unpackedData.write<std::uint32_t>(instruction, readPos);

				if (useCount)
				{
					if (--filterCount == 0)
						break;
				}
			}
		}

		readPos += 4;
	}
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
