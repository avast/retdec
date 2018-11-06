/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "llvm/Demangle/borland_demangler.h"
#include "llvm/Demangle/borland_ast.h"

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for borland demangler.
 */
BorlandDemangler::BorlandDemangler() : Demangler("borland") {}

/**
 * @brief Demangles name mangled by borland mangling scheme into string.
 * @param mangled Name mangled by borland mangling scheme.
 * @return Demangled name.
 */
std::string BorlandDemangler::demangleToString(const std::string &mangled)
{
	borland::BorlandASTParser parser{mangled};
	auto ast = parser.ast();
	return ast ? ast->str() : std::string{};
}

namespace borland {

/**
 * @brief Constructor for AST parser. It parses name mangled by borland mangling scheme into AST.
 * @param mangled Name mangled by borland mangling scheme.
 */
BorlandASTParser::BorlandASTParser(const std::string &mangled) :
	_status(init),
	_mangled(mangled.c_str(), mangled.length()),
	_ast(nullptr)
{
	parse();
}

/**
 * @return Status of parser.
 */
BorlandASTParser::Status BorlandASTParser::status()
{
	return _status;
}

/**
 * @brief Main method of parser. Tries to create AST, sets status.
 */
void BorlandASTParser::parse()
{
	if (_mangled.consumeFront('@')) {
		_ast = parseFullName();
	}
	_status = success;
}

/**
 * @brief Tries to consume first nested name in in source and returns it.
 */
StringView BorlandASTParser::getNestedName(StringView &source)
{
	auto nested = source.substrUntil('@');
	source.consumeFront(nested);
	source.consumeFront('@');
	return nested;
}

/**
 * @brief Tries to parse whole name into AST.
 * @return Pointer to Node that represents name.
 */
std::unique_ptr<Node> BorlandASTParser::parseFullName()
{
	auto name = _mangled.substrUntil('$');
	if (name.empty()) {
		return nullptr;
	}
	_mangled.consumeFront(name);
	_mangled.consumeFront('$');

	auto nestedPart = getNestedName(name);
	if (nestedPart.empty()) {
		return NameNode::create(name);
	}
	std::unique_ptr<Node> nameNode = NameNode::create(nestedPart);

	StringView nextNested;
	while (!(nextNested = getNestedName(name)).empty()) {
		auto nextNestedNode = NameNode::create(nextNested);
		nameNode = NestedNameNode::create(std::move(nameNode), std::move(nextNestedNode));
	}

	// everything left must be absolute name
	auto absNameNode = NameNode::create(name);
	return NestedNameNode::create(std::move(nameNode), std::move(absNameNode));
}

/**
 * @return Shared pointer to AST.
 */
std::shared_ptr<Node> BorlandASTParser::ast()
{
	return _status == success ? _ast : nullptr;
}

/**
 * @brief Abstract constructor for base node.
 * @param kind Kind of node.
 */
Node::Node(Kind kind, bool has_right_side) :
	_kind(kind) {}

/**
 * @brief Prints left side of node.
 * @param s output stream
 */
void Node::print(std::ostream &s)
{
	printLeft(s);
}

/**
 * @return String representation of node.
 */
std::string Node::str()
{
	std::stringstream ss;
	print(ss);
	return ss.str();
}

/**
 * @return Kind of node.
 */
Node::Kind Node::kind()
{
	return _kind;
}

/**
 * @brief Constructor for NameNode
 * @param name StringView representation of name.
 */
NameNode::NameNode(const StringView &name) : Node(KName, false), _name(name) {}

/**
 * @param name StringView representation of name.
 * @return Unique pointer to new NameNode
 */
std::unique_ptr<NameNode> NameNode::create(const StringView &name)
{
	return std::unique_ptr<NameNode>(new NameNode(name));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NameNode::printLeft(std::ostream &s)
{
	s << std::string{_name.begin(), _name.size()};
}

/**
 * NestedName constructor.
 * @param super Higher level node.
 * @param name Lower level node.
 */
NestedNameNode::NestedNameNode(
	std::unique_ptr<Node> super, std::unique_ptr<Node> name) :
	Node(KNestedName, false), _super(std::move(super)), _name(std::move(name)) {}

/**
 * @param super Higher level node.
 * @param name Lower level node.
 * @return Unique pointer to new nested name node.
 */
std::unique_ptr<NestedNameNode> NestedNameNode::create(
	std::unique_ptr<Node> super, std::unique_ptr<Node> name)
{
	return std::unique_ptr<NestedNameNode>(new NestedNameNode(std::move(super), std::move(name)));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NestedNameNode::printLeft(std::ostream &s)
{
	_super->print(s);
	s << std::string{"::"};
	_name->print(s);
}

} // borland
} // demangler
} // retdec
