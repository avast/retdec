/**
* @file src/bin2llvmir/optimizations/decoder/decoder_ranges.cpp
* @brief Representation of ranges to decode.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h"

using namespace retdec::utils;

namespace {

inline retdec::utils::Address align(
		const retdec::utils::Address& s,
		unsigned a)
{
	return a && s % a ? retdec::utils::Address(s + a - (s % a)) : s;
}

} // namespace anonymous

namespace retdec {
namespace bin2llvmir {

void RangesToDecode::addPrimary(utils::Address s, utils::Address e)
{
	s = align(s, archInsnAlign);
	if (e > s)
	{
		_primaryRanges.insert(s, e);
	}
}

void RangesToDecode::addPrimary(const utils::AddressRange& r)
{
	addPrimary(r.getStart(), r.getEnd());
}

void RangesToDecode::addAlternative(utils::Address s, utils::Address e)
{
	s = align(s, archInsnAlign);
	if (e > s)
	{
		_alternativeRanges.insert(s, e);
	}
}

void RangesToDecode::addAlternative(const utils::AddressRange& r)
{
	addAlternative(r.getStart(), r.getEnd());
}

void RangesToDecode::promoteAlternativeToPrimary()
{
	_primaryRanges = std::move(_alternativeRanges);
	_strict = true;
}

void RangesToDecode::remove(utils::Address s, utils::Address e)
{
	e = align(e, archInsnAlign);
	_primaryRanges.remove(s, e);
	_alternativeRanges.remove(s, e);
}

void RangesToDecode::remove(const utils::AddressRange& r)
{
	remove(r.getStart(), r.getEnd());
}

void RangesToDecode::removeZeroSequences(FileImage* image)
{
	removeZeroSequences(image, _primaryRanges);
	removeZeroSequences(image, _alternativeRanges);
}

void RangesToDecode::removeZeroSequences(
		FileImage* image,
		utils::AddressRangeContainer& rs)
{
	static unsigned minSequence = 0x50; // TODO: Maybe should be smaller.
	retdec::utils::AddressRangeContainer toRemove;

	for (auto& range : rs)
	{
		Address start = range.getStart();
		Address end = range.getEnd();
		uint64_t size = range.getSize();

		uint64_t iter = 0;
		Address zeroStart;
		uint64_t byte = 0;
		Address addr;

		while (iter < size)
		{
			addr = start + iter;
			if (image->getImage()->get1Byte(addr, byte))
			{
				if (byte == 0)
				{
					if (zeroStart.isUndefined())
					{
						zeroStart = addr;
					}
				}
				else
				{
					// +8 -> first few zeroes might be a part of some
					// instruction. only somewhere after them might the real
					// sequence start. if we remove them, we make instruction
					// undecodable.
					//
					if (zeroStart.isDefined()
							&& zeroStart + 8 < addr
							&& addr - zeroStart >= minSequence)
					{
						toRemove.insert(zeroStart+8, addr);
					}
					zeroStart = Address::getUndef;
				}

				iter += 1;
			}
			else
			{
				if (zeroStart.isDefined()
						&& zeroStart + 8 < end
						&& end - zeroStart >= minSequence)
				{
					toRemove.insert(zeroStart + 8, end);
				}
				break;
			}
		}

		if (iter >= size
				&& byte == 0
				&& zeroStart.isDefined()
				&& zeroStart + 8 < addr
				&& addr - zeroStart >= minSequence)
		{
			toRemove.insert(zeroStart + 8, addr);
		}
	}

	for (auto& range : toRemove)
	{
		rs.remove(range);
	}
}

bool RangesToDecode::isStrict() const
{
	return _strict;
}

bool RangesToDecode::primaryEmpty() const
{
	return _primaryRanges.empty();
}

bool RangesToDecode::alternativeEmpty() const
{
	return _alternativeRanges.empty();
}

const utils::AddressRange& RangesToDecode::primaryFront() const
{
	return *_primaryRanges.begin();
}

const utils::AddressRange& RangesToDecode::alternativeFront() const
{
	return *_alternativeRanges.begin();
}

const utils::AddressRange* RangesToDecode::getPrimary(utils::Address a) const
{
	return _primaryRanges.getRange(a);
}

const utils::AddressRange* RangesToDecode::getAlternative(
		utils::Address a) const
{
	return _alternativeRanges.getRange(a);
}

const utils::AddressRange* RangesToDecode::get(utils::Address a) const
{
	auto* p = getPrimary(a);
	return p ? p : getAlternative(a);
}

void RangesToDecode::setArchitectureInstructionAlignment(unsigned a)
{
	archInsnAlign = a;
}

std::ostream& operator<<(std::ostream &os, const RangesToDecode& rs)
{
	os << "Primary ranges:" << std::endl;
	os << rs._primaryRanges << std::endl;
	os << "Alternative ranges:" << std::endl;
	os << rs._alternativeRanges << std::endl;
	return os;
}

} // namespace bin2llvmir
} // namespace retdec
