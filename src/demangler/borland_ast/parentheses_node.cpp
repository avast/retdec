#include <sstream>

#include "retdec/demangler/borland_ast/parentheses_node.h"

namespace retdec {
namespace demangler {
namespace borland {

ParenthesesNode::ParenthesesNode(std::shared_ptr<retdec::demangler::borland::Node> type) :
	Node(Kind::KParentheses), _type(std::move(type)) {}

void ParenthesesNode::printLeft(std::ostream &s) const
{
	s << "(";
	_type->print(s);
	s << ")";
}

std::shared_ptr<ParenthesesNode> ParenthesesNode::create(
	retdec::demangler::borland::Context &context,
	std::shared_ptr<retdec::demangler::borland::Node> type)
{
	// TODO context
	return std::shared_ptr<ParenthesesNode>(new ParenthesesNode(std::move(type)));
}

}
}
}
