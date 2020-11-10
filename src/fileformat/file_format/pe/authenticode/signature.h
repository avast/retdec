#pragma once

#include "certificate.h"

#include <string>
#include <vector>

namespace authenticode {

/*  I'll leave these in separate structures if there'd be necessary to associate more data with them? */
struct CounterSigner {
	std::vector<Certificate> chain;
	std::vector<CounterSigner> counter_signers;
};

struct Signer {
	std::vector<Certificate> chain;
	std::vector<CounterSigner> counter_signers;
};

struct Signature 
{
	std::vector<std::uint8_t> signed_digest;
	std::string digest_algorithm;

	/* same data can have multiple signers, each signer has a chain of certificates 
	each signer (chain) can be counter-signed and each counter signature can also be counter signed?, prototype idea 
	SOLVED,  "Because Authenticode signatures support only one signer,",  https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf page 7
	there are only counter signatures then and single signer */

	Signer signer;
};

} // namespace authenticode