/**
 * @file include/retdec/demangler/borland_demangler.h
 * @brief Borland demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_BORLAND_DEMANGLER_H
#define RETDEC_LLVM_BORLAND_DEMANGLER_H

#include "retdec/demangler/demangler_base.h"
#include "retdec/demangler/context.h"
#include "retdec/demangler/borland_ast_parser.h"

namespace retdec {
namespace demangler {

/**
 * @brief Borland demangler.
 */
class BorlandDemangler : public Demangler
{
public:
	BorlandDemangler();

	std::string demangleToString(const std::string &mangled) override;

private:
	static Status astStatusToDemStatus(const borland::BorlandASTParser::Status &parserStatus);

	std::string astToString(const std::shared_ptr<borland::Node> &ast) const;

private:
	borland::Context _context;
};

}
}

#endif //RETDEC_LLVM_BORLAND_DEMANGLER_H
