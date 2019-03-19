#include "llvm/Demangle/Allocator.h"
#include "llvm/Demangle/ItaniumDemangle.h"

namespace llvm {
namespace itanium_demangle {

void BumpPointerAllocator::grow()
{
	char *NewMeta = static_cast<char *>(std::malloc(AllocSize));
	if (NewMeta == nullptr)
		std::terminate();
	BlockList = new(NewMeta) BlockMeta{BlockList, 0};
}

void *BumpPointerAllocator::allocateMassive(size_t NBytes)
{
	NBytes += sizeof(BlockMeta);
	BlockMeta *NewMeta = reinterpret_cast<BlockMeta *>(std::malloc(NBytes));
	if (NewMeta == nullptr)
		std::terminate();
	BlockList->Next = new(NewMeta) BlockMeta{BlockList->Next, 0};
	return static_cast<void *>(NewMeta + 1);
}

BumpPointerAllocator::BumpPointerAllocator() :
	BlockList(new(InitialBuffer) BlockMeta{nullptr, 0}) {}

void *BumpPointerAllocator::allocate(size_t N)
{
	N = (N + 15u) & ~15u;
	if (N + BlockList->Current >= UsableAllocSize) {
		if (N > UsableAllocSize)
			return allocateMassive(N);
		grow();
	}
	BlockList->Current += N;
	return static_cast<void *>(reinterpret_cast<char *>(BlockList + 1) +
		BlockList->Current - N);
}

void BumpPointerAllocator::reset()
{
	while (BlockList) {
		BlockMeta *Tmp = BlockList;
		BlockList = BlockList->Next;
		if (reinterpret_cast<char *>(Tmp) != InitialBuffer)
			std::free(Tmp);
	}
	BlockList = new(InitialBuffer) BlockMeta{nullptr, 0};
}

BumpPointerAllocator::~BumpPointerAllocator()
{
	reset();
}

void DefaultAllocator::reset() { Alloc.reset(); }

void *DefaultAllocator::allocateNodeArray(size_t sz)
{
	return Alloc.allocate(sizeof(Node *) * sz);
}

void *DefaultAllocator::allocateBytes(size_t sz)
{
	return Alloc.allocate(sz);
}

}
}
