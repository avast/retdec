#include "llvm/Demangle/Allocator.h"
#include "llvm/Demangle/ItaniumDemangle.h"

namespace llvm {
namespace itanium_demangle {

void DefaultAllocator::reset() { Alloc.reset(); }

void *DefaultAllocator::allocateNodeArray(size_t sz) {
	return Alloc.allocate(sizeof(Node *) * sz);
}

void* DefaultAllocator::allocateBytes(size_t sz) {
	return Alloc.allocate(sz);
}

}
}
