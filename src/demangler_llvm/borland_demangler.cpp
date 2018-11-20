/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <map>

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
	if (!_mangled.consumeFront('@')) {    // name
		_status = invalid_mangled_name;
		return;
	}

	auto name = parseFullName();
	if (!name) {
		_status = invalid_mangled_name;
		return;
	}

	if (_mangled.empty()) {
		_status = success;
		_ast = std::move(name);
		return;
	}

	auto call_conv = parseCallConv();
	if (!call_conv) {
		_status = invalid_mangled_name;
		return;
	}

//	auto params = parseParams();
	auto params = NameNode::create("");    //TODO

	_ast = FunctionNode::create(std::move(call_conv), std::move(name), std::move(params));
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
 * @brief Tries to parse calling convention into AST node.
 * @return Pointer to CallConv on success, else nullptr.
 */
std::unique_ptr<CallConv> BorlandASTParser::parseCallConv()
{
	using Convention = CallConv::Conventions;

	if (!_mangled.consumeFront('q')) {
		return nullptr;
	}

	auto conv = Convention::unknown;
	if (_mangled.consumeFront('q')) {
		switch (_mangled.popFront()) {
		case 'r':
			conv = Convention::fastcall;
			break;
		case 's':
			conv = Convention::stdcall;
			break;
		default:
			break;
		}
	} //else unknown, cant tell for certain

	return CallConv::create(conv);
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
	_kind(kind), _has_right(has_right_side) {}

void Node::printRight(std::ostream &s) {}

/**
 * @brief Prints left side of node.
 * @param s output stream
 */
void Node::print(std::ostream &s)
{
	printLeft(s);
	if (_has_right) {
		printRight(s);
	}
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
NameNode::NameNode(const StringView &name) : Node(NameNode::Kind::KName, false), _name(name) {}

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
	Node(NameNode::Kind::KNestedName, false), _super(std::move(super)), _name(std::move(name)) {}

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

/**
 * @brief Calling convention node private constructor. Use create().
 * @param conv Calling convention.
 * @param has_right Weather the space after calling convention should be printed.
 */
CallConv::CallConv(CallConv::Conventions &conv, bool has_right) :
	Node(Kind::KCallConv, has_right), _conv(conv) {}

/**
 * @brief Prints string representation of calling convention into ostream s.
 * @param s Output stream.
 */
void CallConv::printLeft(std::ostream &s)
{
	std::map<Conventions, std::string> to_str{
		{Conventions::stdcall, "__stdcall"},
		{Conventions::fastcall, "__fastcall"},
		{Conventions::cdecl, "__cdecl"},
		{Conventions::pascal, "__pascal"},
		{Conventions::unknown, ""}
	};

	s << to_str[_conv];
}

/**
 * @brief Prints space after calling convention.
 * @param s Output stream.
 */
void CallConv::printRight(std::ostream &s)
{
	s << " ";
}

/**
 * @brief Creates unique pointer to CallConv node.
 * @param conv Calling convention.
 * @return Unique pointer to CallConv node.
 */
std::unique_ptr<CallConv> CallConv::create(Conventions &conv)
{
	bool has_rhs = conv == Conventions::unknown;
	return std::unique_ptr<CallConv>(new CallConv(conv, has_rhs));
}

/**
 * @return Call convention type.
 */
CallConv::Conventions CallConv::conv()
{
	return _conv;
}

/**
 * @brief Private function node constructor. Use create().
 * @param call_conv Pointer to calling convention.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 */
FunctionNode::FunctionNode(
	std::unique_ptr<retdec::demangler::borland::CallConv> call_conv,
	std::unique_ptr<retdec::demangler::borland::Node> name,
	std::unique_ptr<retdec::demangler::borland::Node> params) :
	Node(Kind::KFunction, false),
	_call_conv(std::move(call_conv)),
	_name(std::move(name)),
	_params(std::move(params)) {}

/**
 * @brief Creates unique pointer to function node.
 * @param call_conv Pointer to calling convention node.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 * @return Unique pointer to constructed FunctionNode.
 */
std::unique_ptr<FunctionNode> FunctionNode::create(
	std::unique_ptr<retdec::demangler::borland::CallConv> call_conv,
	std::unique_ptr<retdec::demangler::borland::Node> name,
	std::unique_ptr<retdec::demangler::borland::Node> params)
{
	return std::unique_ptr<FunctionNode>(
		new FunctionNode(std::move(call_conv), std::move(name), std::move(params)));
}

/**
 * @brief Prints text representation of function.
 * @param s Output stream.
 */
void FunctionNode::printLeft(std::ostream &s)
{
	if (_call_conv->conv() != CallConv::Conventions::unknown) {
		_call_conv->print(s);
		s << " ";
	}
	_name->print(s);
	s << "(";
	_params->print(s);
	s << ")";
}

} // borland
} // demangler
} // retdec
