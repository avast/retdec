/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler parsing into AST.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/demangler/borland_ast_parser.h"
#include "retdec/demangler/borland_ast/array_type.h"
#include "retdec/demangler/borland_ast/built_in_type.h"
#include "retdec/demangler/borland_ast/char_type.h"
#include "retdec/demangler/borland_ast/conversion_operator.h"
#include "retdec/demangler/borland_ast/float_type.h"
#include "retdec/demangler/borland_ast/function_type.h"
#include "retdec/demangler/borland_ast/function_node.h"
#include "retdec/demangler/borland_ast/integral_type.h"
#include "retdec/demangler/borland_ast/name_node.h"
#include "retdec/demangler/borland_ast/named_type.h"
#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/borland_ast/node_array.h"
#include "retdec/demangler/borland_ast/pointer_type.h"
#include "retdec/demangler/borland_ast/qualifiers.h"
#include "retdec/demangler/borland_ast/reference_type.h"
#include "retdec/demangler/borland_ast/rreference_type.h"
#include "retdec/demangler/borland_ast/template_node.h"
#include "retdec/demangler/borland_ast/type_node.h"

namespace {

/**
* @return New string from StringView object.
*/
inline std::string getString(const retdec::demangler::borland::StringView &s)
{
	return {s.begin(), s.size()};
}

}	// anonymous namespace

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Constructor for AST parser. Immediately parses name mangled by borland mangling scheme into AST.
 * @param mangled Name mangled by borland mangling scheme.
 */
BorlandASTParser::BorlandASTParser(Context &context) :
	_status(init),
	_mangled(""),
	_ast(nullptr),
	_context(context) {}

/**
 * @return Shared pointer to AST.
 */
std::shared_ptr<Node> BorlandASTParser::ast()
{
	return _status == success ? _ast : nullptr;
}

/**
 * @return Status of parser.
 */
BorlandASTParser::Status BorlandASTParser::status()
{
	return _status;
}

/**
 * @return First character from rest of the mangled name. If empty then EOF.
 */
inline char BorlandASTParser::peek() const
{
	return _mangled.empty() ? static_cast<char>(EOF) : _mangled.front();
}

/**
 * @return True if _mangled starts with c. Else false.
 */
inline bool BorlandASTParser::peek(char c) const
{
	return _mangled.startsWith(c);
}

/**
 * @return True if _mangled starts with string s. Else false.
 */
inline bool BorlandASTParser::peek(const StringView &s) const
{
	return _mangled.startsWith(s);
}


/**
 * @return If present number on the front of rest of mangled string. Else 0.
 */
unsigned BorlandASTParser::peekNumber() const
{
	StringView mangledCopy = _mangled;
	unsigned acc = 0;
	if (!mangledCopy.empty()) {
		char c = mangledCopy.front();
		if (c == '0') {
			return 0;
		}

		while (!mangledCopy.empty() && mangledCopy.front() >= '0' && mangledCopy.front() <= '9') {
			c = mangledCopy.popFront();
			acc = 10 * acc + static_cast<unsigned>(c - '0');
		}
	}

	return acc;
}

inline bool BorlandASTParser::statusOk() const
{
	return _status == in_progress;
}

/**
 * Checks result after parsing function.
 * Sets status of parser.
 * @param node Result of previous parsing.
 * @return true if result was OK, false otherwise.
 */
bool BorlandASTParser::checkResult(std::shared_ptr<Node> node)
{
	if (node == nullptr || _status == invalid_mangled_name) {
		_status = invalid_mangled_name;
		return false;
	}

	return true;
}

/**
 * If mangled name starts with c, consumes the front and returns true. Else returns false.
 */
inline bool BorlandASTParser::consumeIfPossible(char c)
{
	return _mangled.consumeFront(c);
}

/**
 * If mangled name starts with s, consumes the front and returns true. Else returns false.
 */
inline bool BorlandASTParser::consumeIfPossible(const StringView &s)
{
	return _mangled.consumeFront(s);
}

/**
 * If mangled name starts with c, consumes the front and returns true.
 * Else sets invalid name status and returns false.
 */
bool BorlandASTParser::consume(char c)
{
	if (!_mangled.consumeFront(c)) {
		_status = invalid_mangled_name;
		return false;
	}

	return true;
}

/**
 * If mangled name starts with s, consumes the front and returns true.
 * Else sets invalid name status and returns false.
 */
bool BorlandASTParser::consume(const StringView &s)
{
	if (!_mangled.consumeFront(s)) {
		_status = invalid_mangled_name;
		return false;
	}

	return true;
}

/**
 * @brief Main method of parser. Tries to create AST, sets status.
 *
 * <mangled-name> ::= <mangled-function>
 */
void BorlandASTParser::parse(const std::string &mangled)
{
	_status = in_progress;
	_mangled = llvm::itanium_demangle::StringView{mangled.c_str(), mangled.length()};

	auto func = parseFunction();
	if (checkResult(func)){
		_ast = func;
		_status = success;
	}

	if (!_mangled.empty()) {
		_status = invalid_mangled_name;
		_ast = nullptr;
	}
}

/*
 * @brief Tries to parse mangled name to function Node.
 *
 * <mangled-function> ::= <func-name> $ <func-quals> <func-type>
 */
std::shared_ptr<Node> BorlandASTParser::parseFunction()
{
	auto mangled_str = getString(_mangled);
	auto func = _context.getFunction(mangled_str);
	if (func) {
		_mangled.drop(_mangled.size());
		return func;
	}

	std::shared_ptr<Node> absNameNode = parseFuncName();
	if (!checkResult(absNameNode)) {
		return nullptr;
	}

	if (!consume('$')) {
		return nullptr;
	}

	auto quals = parseQualifiers();
	auto funcType = parseFuncType(quals);
	if (!checkResult(std::static_pointer_cast<Node>(funcType))) {
		return nullptr;
	}

	func = FunctionNode::create(absNameNode, funcType);
	_context.addFunction(mangled_str, func);
	return func;
}

/**
 * @return Node representing name, could be nullptr on failure.
 *
 * <func-name> ::= @ <classic-func-name>
 * <func-name> ::= <llvm-func-name>
 */
std::shared_ptr<Node> BorlandASTParser::parseFuncName() {
	if (consumeIfPossible('@')) {
		return parseFuncNameClasic();
	} else {
		return parseFuncNameLlvm();
	}
}

/**
 *
 * @return Node representing function name on success or nullptr on failure.
 * On failure, status is set to incorrect_mangled_name
 *
 * <classic-func-name> ::= <name> <template-name> $ <operator>
 * <name> ::= <name> @ <name>
 * <name> ::=
 * <template-name> ::= % <abs-name> %
 * <template-name ::=
 */
std::shared_ptr<Node> BorlandASTParser::parseFuncNameClasic()
{
	std::shared_ptr<Node> name = nullptr;

	const char *start = _mangled.begin();
	const char *end = _mangled.end();
	const char *c = _mangled.begin();
	while (c <= end) {
		if (*c == '$' || *c == '%' || *c == '@') {
			auto nameView = StringView(start, c);
			if (!nameView.empty()) {
				_mangled.consumeFront(nameView);        // propagate to mangled
				auto nameNode = NameNode::create(_context, getString(nameView));
				name =
					name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
				start = c + 1;    // skip already checked chars and one of '%', '$', '@'
			}
			if (!consumeIfPossible('@')) {    // $ or %
				break;
			}
		}
		++c;
	}

	if (peek('%')) {
		name = parseTemplate(name);
		if (!statusOk()) {
			return nullptr;
		}
	}

	auto op = parseOperator();
	if (!statusOk()) {
		return nullptr;
	}
	if (op) {
		name = name ? NestedNameNode::create(_context, name, op) : op;
	}

	checkResult(name);

	return name;
}

/**
 *
 * @return Node representing function name on success or nullptr on failure.
 * On failure, status is set to incorrect_mangled_name
 *
 * <llvm-func-name> ::= <name> $ <template-name> <operator>
 * <name> ::= <name> @ <name>
 * <name> ::=
 * <template-name> ::= % <abs-name> %
 * <template-name ::=
 */
std::shared_ptr<Node> BorlandASTParser::parseFuncNameLlvm()
{
	if (!consume("Lllvm$")) {
		return nullptr;
	}

	std::shared_ptr<Node> name = NameNode::create(_context, "Lllvm");

	while (!consumeIfPossible('@')) {
		auto partName = _mangled.cutUntil('$');
		if (partName.empty() || _mangled.empty()) {
			_status = invalid_mangled_name;
			return nullptr;
		}

		consumeIfPossible('$');
		auto partNameNode = std::static_pointer_cast<Node>(NameNode::create(_context, getString(partName)));
		name = NestedNameNode::create(_context, name, partNameNode);
	}

	if (peek('%')) {
		name = parseTemplate(name);
		if (!statusOk()) {
			return nullptr;
		}
	}

	auto op = parseOperator();
	if (!statusOk()) {
		return nullptr;
	}
	if (op) {
		name = name ? NestedNameNode::create(_context, name, op) : op;
	}

	checkResult(name);

	return name;
}

/**
 * Tries to parse operator. If no operator could be substituted, method doesn't change mangled name.
 * @return Node representing operator on success, or nullptr on failure.
 */
std::shared_ptr<Node> BorlandASTParser::parseOperator()
{
	if (consumeIfPossible("$o")) {	// conversion operator
		auto type = parseType();
		if (!checkResult(type)) {
			return nullptr;
		}
		return ConversionOperatorNode::create(_context, type);
	}

	if (peek("$b")) {
		if (consumeIfPossible("$badd")) {
			return NameNode::create(_context, "operator+");
		} else if (consumeIfPossible("$bsubs")) {    // must be before '$sub'
			return NameNode::create(_context, "operator[]");
		} else if (consumeIfPossible("$bsub")) {
			return NameNode::create(_context, "operator-");
		} else if (consumeIfPossible("$basg")) {
			return NameNode::create(_context, "operator=");
		} else if (consumeIfPossible("$bmul")) {
			return NameNode::create(_context, "operator*");
		} else if (consumeIfPossible("$bdiv")) {
			return NameNode::create(_context, "operator/");
		} else if (consumeIfPossible("$bmod")) {
			return NameNode::create(_context, "operator%");
		} else if (consumeIfPossible("$binc")) {
			return NameNode::create(_context, "operator++");
		} else if (consumeIfPossible("$bdec")) {
			return NameNode::create(_context, "operator--");
		} else if (consumeIfPossible("$beql")) {
			return NameNode::create(_context, "operator==");
		} else if (consumeIfPossible("$bneq")) {
			return NameNode::create(_context, "operator!=");
		} else if (consumeIfPossible("$bgtr")) {
			return NameNode::create(_context, "operator>");
		} else if (consumeIfPossible("$blss")) {
			return NameNode::create(_context, "operator<");
		} else if (consumeIfPossible("$bgeq")) {
			return NameNode::create(_context, "operator>=");
		} else if (consumeIfPossible("$bleq")) {
			return NameNode::create(_context, "operator<=");
		} else if (consumeIfPossible("$bnot")) {
			return NameNode::create(_context, "operator!");
		} else if (consumeIfPossible("$bland")) {
			return NameNode::create(_context, "operator&&");
		} else if (consumeIfPossible("$blor")) {
			return NameNode::create(_context, "operator||");
		} else if (consumeIfPossible("$bcmp")) {
			return NameNode::create(_context, "operator~");
		} else if (consumeIfPossible("$band")) {
			return NameNode::create(_context, "operator&");
		} else if (consumeIfPossible("$bor")) {
			return NameNode::create(_context, "operator|");
		} else if (consumeIfPossible("$bxor")) {
			return NameNode::create(_context, "operator^");
		} else if (consumeIfPossible("$blsh")) {
			return NameNode::create(_context, "operator<<");
		} else if (consumeIfPossible("$brsh")) {
			return NameNode::create(_context, "operator>>");
		} else if (consumeIfPossible("$brplu")) {
			return NameNode::create(_context, "operator+=");
		} else if (consumeIfPossible("$brmin")) {
			return NameNode::create(_context, "operator-=");
		} else if (consumeIfPossible("$brmul")) {
			return NameNode::create(_context, "operator*=");
		} else if (consumeIfPossible("$brdiv")) {
			return NameNode::create(_context, "operator/=");
		} else if (consumeIfPossible("$brmod")) {
			return NameNode::create(_context, "operator%=");
		} else if (consumeIfPossible("$brand")) {
			return NameNode::create(_context, "operator&=");
		} else if (consumeIfPossible("$bror")) {
			return NameNode::create(_context, "operator|=");
		} else if (consumeIfPossible("$brxor")) {
			return NameNode::create(_context, "operator^=");
		} else if (consumeIfPossible("$brlsh")) {
			return NameNode::create(_context, "operator<<=");
		} else if (consumeIfPossible("$brrsh")) {
			return NameNode::create(_context, "operator>>=");
		} else if (consumeIfPossible("$bind")) {
			return NameNode::create(_context, "operator*");
		} else if (consumeIfPossible("$badr")) {
			return NameNode::create(_context, "operator&");
		} else if (consumeIfPossible("$barow")) {
			return NameNode::create(_context, "operator->");
		} else if (consumeIfPossible("$barwm")) {
			return NameNode::create(_context, "operator->*");
		} else if (consumeIfPossible("$bcall")) {
			return NameNode::create(_context, "operator()");
		} else if (consumeIfPossible("$bcoma")) {
			return NameNode::create(_context, "operator,");
		} else if (consumeIfPossible("$bnew")) {
			return NameNode::create(_context, "operator new");
		} else if (consumeIfPossible("$bnwa")) {
			return NameNode::create(_context, "operator new[]");
		} else if (consumeIfPossible("$bdele")) {
			return NameNode::create(_context, "operator delete");
		} else if (consumeIfPossible("$bdla")) {
			return NameNode::create(_context, "operator delete[]");
		}
	}

	return nullptr;
}

/**
 * Parses mangled string as nested named type until end.
 * @param end Pointer behind the last char to parse.
 * @return Node representing named type on success, or nullptr of failure.
 * On failure status is set to invalid_mangled_name.
 */
std::shared_ptr<Node> BorlandASTParser::parseAsNameUntil(const char *end)
{
	std::shared_ptr<Node> name = nullptr;

	const char *start = _mangled.begin();
	const char *c = _mangled.begin();
	while (c < end) {
		if (*c == '%' || *c == '@') {
			auto nameView = StringView(start, c);
			if (!nameView.empty()) {
				_mangled.consumeFront(nameView);        // propagate to mangled
				auto nameNode = NameNode::create(_context, getString(nameView));
				name =
					name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
				start = c + 1;
			}
			if (!consumeIfPossible('@')) {
				break;
			}
		}
		++c;
	}

	if (c == end) { // parse remainder as name
		auto nameView = StringView(start, c);
		_mangled.consumeFront(nameView);        // propagate to mangled
		auto nameNode = NameNode::create(_context, getString(nameView));
		name = name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
	}

	if (peek('%') && c != end) {    // check end if next parameter is template
		name = parseTemplate(name);
	}

	if (_mangled.begin() != end) {        // length was wrong
		_status = invalid_mangled_name;
		return nullptr;
	}

	return name;
}

/**
 * Parse function details (call conv, parameter types, varargness, return type)
 * @param quals Function qualifiers.
 * @return Node representing function type on success, or nullptr on failure.
 */
std::shared_ptr<FunctionTypeNode> BorlandASTParser::parseFuncType(Qualifiers &quals)
{
	/* function calling convention */
	auto callConv = parseCallConv();
	if (!statusOk()) {
		return nullptr;
	}

	/* parameters */
	auto paramsNode = parseFuncParams();
	if (!statusOk()) {
		return nullptr;
	}

	bool isVarArg = consumeIfPossible('e');

	/* return type */
	std::shared_ptr<TypeNode> retType = nullptr;
	if (consumeIfPossible('$')) {
		retType = parseType();
		if (!checkResult(retType)) {
			return nullptr;
		}
	}

	return FunctionTypeNode::create(callConv, paramsNode, retType, quals, isVarArg);
}

/**
 * Tries to parse qualifiers. If no are found, mangled string is unchanged.
 * @return Qualifiers object.
 */
Qualifiers BorlandASTParser::parseQualifiers()
{
	bool is_volatile = consumeIfPossible('w');
	bool is_const = consumeIfPossible('x');

	return {is_volatile, is_const};
}

/**
 * Tries to parse function call convention.
 * If no call conv is recognized, status is set to invalid_mangled_name.
 * @return Call conv.
 */
CallConv BorlandASTParser::parseCallConv()
{
	if (_mangled.consumeFront("qqr")) {
		return CallConv::fastcall;
	} else if (_mangled.consumeFront("qqs")) {
		return CallConv::stdcall;
	} else if (_mangled.consumeFront("q")) {    // most likely cdecl, pascal
		return CallConv::unknown;
	} else {
		_status = Status::invalid_mangled_name;
		return CallConv::unknown;
	}
}

/**
 * Parses funtion parameters.
 * @return ArrayNode with parameters if parameters are found, or nullptr if no.
 */
std::shared_ptr<NodeArray> BorlandASTParser::parseFuncParams()
{
	auto params = NodeArray::create();

	while (!_mangled.empty() && statusOk() && !peek('$')) {
		if (consumeIfPossible('t')) {
			if (!parseBackref(params)) {
				return nullptr;
			}
		} else {
			auto param = parseType();
			if (!statusOk()) {
				return nullptr;
			}
			if (!param) {
				break;
			}
			params->addNode(param);
		}
	}

	return params->empty() ? nullptr : params;
}

/**
 * Parses backreference in parameter list and adds it to parameter array.
 * @return true on success, false otherwise.
 */
bool BorlandASTParser::parseBackref(std::shared_ptr<retdec::demangler::borland::NodeArray> &paramArray)
{
	unsigned backref = parseNumber();
	if (backref == 0 || backref > paramArray->size() || !statusOk()) {
		_status = invalid_mangled_name;
		return false;
	}

	paramArray->addNode(paramArray->get(backref - 1));
	return true;
}

/**
 * Parses mangled types.
 * Can have no effect, if no viable type is found and mangled string didnt breake any rule for types.
 * @return Type on success, nullptr on failure.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseType()
{
	/* qualifiers */
	auto quals = parseQualifiers();

	if (consumeIfPossible('p')) {
		return parsePointer(quals);
	}

	if (consumeIfPossible('r')) {
		if (quals.isConst() || quals.isVolatile()) {
			_status = invalid_mangled_name;
			return nullptr;
		}
		return parseReference();
	}

	if (consumeIfPossible('h')) {
		if (quals.isConst() || quals.isVolatile()) {
			_status = invalid_mangled_name;
			return nullptr;
		}
		return parseRReference();
	}

	if (consumeIfPossible('a')) {
		return parseArray(quals);
	}

	if (peek('q')) {
		return parseFuncType(quals);
	}

	/* named type */
	/* named type is prefixed with size of mangled name
	 * if no number is found parsing continues with no side effects */
	unsigned len = parseNumber();
	if (_status == invalid_mangled_name) {
		return nullptr;
	}
	if (len > 0) {
		return parseNamedType(len, quals);
	}

	/* must be built-in type or no type */
	return parseBuildInType(quals);
}

/**
 * Parses pointer type.
 * @return Pointer type on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parsePointer(const Qualifiers &quals)
{
	auto pointeeType = parseType();
	if (!checkResult(pointeeType)) {
		return nullptr;
	}

	return PointerTypeNode::create(_context, pointeeType, quals);
}

/**
 * Parses reference type.
 * @return Reference type on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseReference()
{
	if (consumeIfPossible('$')) {    // must be reference to function
		auto fakeQuals = Qualifiers(false, false);    // reference to function cannot have qualifiers
		auto funcType = parseFuncType(fakeQuals);
		if (!checkResult(funcType)) {
			return nullptr;
		}
		return ReferenceTypeNode::create(_context, funcType);
	}

	auto referencedType = parseType();
	if (!checkResult(referencedType) ||
		referencedType->kind() == Node::Kind::KReferenceType ||
		referencedType->kind() == Node::Kind::KRReferenceType) {
		return nullptr;
	}

	return ReferenceTypeNode::create(_context, referencedType);
}

/**
 * Parses R-reference type.
 * @return R-reference type on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseRReference()
{
	if (consumeIfPossible('$')) {    // must be reference to function
		auto fakeQuals = Qualifiers(false, false);    // reference to function cannot have
		auto funcType = parseFuncType(fakeQuals);
		if (!checkResult(funcType)) {
			return nullptr;
		}
		return RReferenceTypeNode::create(_context, funcType);
	}

	auto referencedType = parseType();
	if (!referencedType || referencedType->kind() == Node::Kind::KReferenceType) {
		_status = invalid_mangled_name;
		return nullptr;
	}
	return RReferenceTypeNode::create(_context, referencedType);
}

/**
 * Parses array type.
 * @return Array on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseArray(const retdec::demangler::borland::Qualifiers &quals)
{
	unsigned len = parseNumber();
	if (len == 0) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	if (!consume('$')) {
		return nullptr;
	}

	auto arrType = parseType();
	if (!checkResult(arrType)) {
		return nullptr;
	}

	return ArrayNode::create(_context, arrType, len, quals);
}

/**
 * Tries to parse built-in type.
 * If no viable type is found, method has no effect.
 * @return Type on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseBuildInType(const Qualifiers &quals)
{
	if (consumeIfPossible('o')) {
		return BuiltInTypeNode::create(_context, "bool", quals);
	} else if (consumeIfPossible('b')) {
		return BuiltInTypeNode::create(_context, "wchar_t", quals);
	} else if (consumeIfPossible('v')) {
		return BuiltInTypeNode::create(_context, "void", quals);
	}

	/* char types */
	if (consumeIfPossible("zc")) {    //only explicitly signed type
		return CharTypeNode::create(_context, ThreeStateSignedness::signed_char, quals);
	} else if (consumeIfPossible("uc")) {
		return CharTypeNode::create(_context, ThreeStateSignedness::unsigned_char, quals);
	} else if (consumeIfPossible('c')) {
		return CharTypeNode::create(_context, ThreeStateSignedness::no_prefix, quals);
	}

	/* integral types */
	bool isUnsigned = false;
	if (consumeIfPossible('u')) {
		isUnsigned = true;
	}
	if (consumeIfPossible('s')) {
		return IntegralTypeNode::create(_context, "short", isUnsigned, quals);
	} else if (consumeIfPossible('i')) {
		return IntegralTypeNode::create(_context, "int", isUnsigned, quals);
	} else if (consumeIfPossible('l')) {
		return IntegralTypeNode::create(_context, "long", isUnsigned, quals);
	} else if (consumeIfPossible('j')) {
		return IntegralTypeNode::create(_context, "long long", isUnsigned, quals);
	}
	if (isUnsigned) {    // was 'u' then not integral type
		_status = Status::invalid_mangled_name;
		return nullptr;
	}

		/* float types */
	else if (consumeIfPossible('f')) {
		return FloatTypeNode::create(_context, "float", quals);
	} else if (consumeIfPossible('d')) {
		return FloatTypeNode::create(_context, "double", quals);
	} else if (consumeIfPossible('g')) {
		return FloatTypeNode::create(_context, "long double", quals);
	}

	return nullptr;        // did nothing
}

/**
 * Parses number.
 * If number starts with 0, status is set to invalid_mangled_name.
 * If no number is found, method has no effect.
 * @return parsed number
 */
unsigned BorlandASTParser::parseNumber()
{
	char c = peek();
	if (c == '0' || c == EOF) {
		_status = invalid_mangled_name;
		return 0;
	}

	unsigned acc = 0;
	while (c >= '0' && c <= '9') {
		_mangled.popFront();
		acc = 10 * acc + static_cast<unsigned>(c - '0');
		c = peek();
	}
	return acc;
}

/**
 * Parses named types.
 * @param nameLen Length of mangled name of the type.
 * @return Named type on success, nullptr otherwise.
 */
std::shared_ptr<TypeNode> BorlandASTParser::parseNamedType(unsigned nameLen, const Qualifiers &quals)
{
	const char *end_named = _mangled.begin() + nameLen;
	if (_mangled.end() < end_named) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	auto mangled_type = std::string{_mangled.begin(), nameLen};
	auto type = _context.getNamedType(mangled_type, quals);
	if (type) {
		_mangled.drop(nameLen);
		return type;
	}

	auto nameNode = parseAsNameUntil(end_named);
	if (nameNode == nullptr) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	auto newType = NamedTypeNode::create(nameNode, quals);
	_context.addNamedType(mangled_type, quals, newType);
	return newType;
}


/**
 * Parses template name without namespace.
 * @param templateNamespace namespace of template.
 * @return Template Node with namespace on success, nullptr otherwise.
 */
std::shared_ptr<Node> BorlandASTParser::parseTemplateName(std::shared_ptr<Node> templateNamespace)
{
	std::shared_ptr<Node> templateNameNode = nullptr;
	auto op = parseOperator();
	if (!statusOk()) {
		return nullptr;
	}
	if (op) {
		templateNameNode = op;
	} else {
		auto templateName = _mangled.cutUntil('$');
		if (templateName.empty()) {
			_status = invalid_mangled_name;
			return nullptr;
		}
		templateNameNode = NameNode::create(_context, getString(templateName));
	}

	if (templateNamespace) {
		templateNameNode = NestedNameNode::create(_context, templateNamespace, templateNameNode);
	}

	return templateNameNode;
}

/**
 * Parse template parameters.
 * @return ArrayNode with  parameters on success, nullptr otherwise
 */
std::shared_ptr<Node> BorlandASTParser::parseTemplateParams()
{
	auto params = NodeArray::create();
	while (!peek('%')) {
		consumeIfPossible('V');    // information about varargness of template is not used
		if (consumeIfPossible('t')) {
			unsigned backref = peekNumber();
			if (backref > 0 && backref <= params->size()) {
				parseNumber();
				params->addNode(params->get(backref - 1));
				continue;
			}
		}	// TODO else nothing, check delphi tests if t can be before named types in templates
		auto typeNode = parseType();
		if (!statusOk()) {
			return nullptr;
		}
		if (!typeNode) {
			break;
		}
		params->addNode(typeNode);
	}

	return params->empty() ? nullptr : params;
}

/**
 * Parses template.
 * @param templateNamespace Namespace of template.
 * @return Template on success, nullptr otherwise.
 */
std::shared_ptr<Node> BorlandASTParser::parseTemplate(std::shared_ptr<Node> templateNamespace)
{
	if (!consume('%')) {
		return nullptr;
	}

	auto templateNameNode = parseTemplateName(std::move(templateNamespace));
	if (!checkResult(templateNameNode)) {
		return nullptr;
	}

	if (!consume('$')) {
		return nullptr;
	}

	auto params = parseTemplateParams();
	if (!checkResult(params)) {
		return nullptr;
	}

	if (!consume('%')) {
		return nullptr;
	}

	return TemplateNode::create(templateNameNode, params);
}

} // borland
} // demangler
} // retdec
