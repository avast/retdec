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

	void grow();

	void* allocateMassive(size_t NBytes);

public:
	BumpPointerAllocator();

	void* allocate(size_t N);

	void reset();

	~BumpPointerAllocator();
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
