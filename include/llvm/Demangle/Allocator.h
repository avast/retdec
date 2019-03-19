#ifndef RETDEC_ALLOCATOR_H
#define RETDEC_ALLOCATOR_H

#include <cassert>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <numeric>
#include <utility>
#include <vector>

namespace llvm {
namespace itanium_demangle {

class BumpPointerAllocator {
private:
	struct BlockMeta {
		BlockMeta* Next;
		size_t Current;
	};

	static constexpr size_t AllocSize = 4096;
	static constexpr size_t UsableAllocSize = AllocSize - sizeof(BlockMeta);

	alignas(long double) char InitialBuffer[AllocSize];
	BlockMeta* BlockList = nullptr;

	void grow() {
		char* NewMeta = static_cast<char *>(std::malloc(AllocSize));
		if (NewMeta == nullptr)
			std::terminate();
		BlockList = new (NewMeta) BlockMeta{BlockList, 0};
	}

	void* allocateMassive(size_t NBytes) {
		NBytes += sizeof(BlockMeta);
		BlockMeta* NewMeta = reinterpret_cast<BlockMeta*>(std::malloc(NBytes));
		if (NewMeta == nullptr)
			std::terminate();
		BlockList->Next = new (NewMeta) BlockMeta{BlockList->Next, 0};
		return static_cast<void*>(NewMeta + 1);
	}

public:
	BumpPointerAllocator()
		: BlockList(new (InitialBuffer) BlockMeta{nullptr, 0}) {}

	void* allocate(size_t N) {
		N = (N + 15u) & ~15u;
		if (N + BlockList->Current >= UsableAllocSize) {
			if (N > UsableAllocSize)
				return allocateMassive(N);
			grow();
		}
		BlockList->Current += N;
		return static_cast<void*>(reinterpret_cast<char*>(BlockList + 1) +
			BlockList->Current - N);
	}

	void reset() {
		while (BlockList) {
			BlockMeta* Tmp = BlockList;
			BlockList = BlockList->Next;
			if (reinterpret_cast<char*>(Tmp) != InitialBuffer)
				std::free(Tmp);
		}
		BlockList = new (InitialBuffer) BlockMeta{nullptr, 0};
	}

	~BumpPointerAllocator() { reset(); }
};

class DefaultAllocator {
	BumpPointerAllocator Alloc;

public:
	void reset();

	template<typename T, typename ...Args> T *makeNode(Args &&...args) {
		return new (Alloc.allocate(sizeof(T)))
			T(std::forward<Args>(args)...);
	}

	void *allocateNodeArray(size_t sz);

	void *allocateBytes(size_t sz);
};

}
}

#endif //RETDEC_ALLOCATOR_H
