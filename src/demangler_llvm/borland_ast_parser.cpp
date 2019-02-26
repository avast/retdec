/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler parsing into AST.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_parser.h"
#include "llvm/Demangle/borland_ast_types.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Constructor for AST parser. It parses name mangled by borland mangling scheme into AST.
 * @param mangled Name mangled by borland mangling scheme.
 */
BorlandASTParser::BorlandASTParser(Context &context, const std::string &mangled) :
	_status(in_progress),
	_mangled(mangled.c_str(), mangled.length()),
	_ast(nullptr),
	_context(context)
{
	parse();
}

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

inline char BorlandASTParser::peek() const
{
	if (!_mangled.empty()) {
		return _mangled.front();
	}
	return EOF;
}

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

bool BorlandASTParser::peekChar(const char c) const
{
	if (!_mangled.empty()) {
		return _mangled.front() == c;
	}

	return false;
}

bool BorlandASTParser::peek(const StringView &s) const
{
	StringView mangledCopy = _mangled;
	return mangledCopy.consumeFront(s);
}

inline bool BorlandASTParser::statusOk() const
{
	return _status == in_progress;
}

bool BorlandASTParser::checkResult(std::shared_ptr<Node> node)
{
	if (node == nullptr || _status == invalid_mangled_name) {
		_status = invalid_mangled_name;
		return false;
	}

	return true;
}

inline bool BorlandASTParser::consumeIfPossible(char c)
{
	return _mangled.consumeFront(c);
}

inline bool BorlandASTParser::consumeIfPossible(const StringView &s)
{
	return _mangled.consumeFront(s);
}

bool BorlandASTParser::consume(char c)
{
	if (!_mangled.consumeFront(c)) {
		_status = invalid_mangled_name;
		return false;
	}

	return true;
}

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
void BorlandASTParser::parse()
{
	if (peekChar('@')) {
		parseFunction();
	}

	if (!_mangled.empty()) {
		_status = invalid_mangled_name;
	}
}

/*
 * @brief Tries to parse mangled name to function Node.
 *
 * <mangled-function> ::= @ <abslute-name> <type-info>
 */
void BorlandASTParser::parseFunction()
{
	auto func = _context.getFunction(_mangled);
	if (func) {
		_status = Status::success;
		_ast = func;
		return;
	}
	auto mangledCopy = _mangled;

	/* name part */
	consume('@');
	auto absNameNode = parseFuncName();
	if (!checkResult(absNameNode)) {
		return;
	}

	if (!consume('$')) {
		return;
	}

	auto quals = parseQualifiers();
	auto funcType = parseFuncType(quals);
	if (!checkResult(funcType)) {
		return;
	}

	if (!_mangled.empty()) {
		_status = invalid_mangled_name;
		return;
	}

	_status = Status::success;
	_ast = FunctionNode::create(absNameNode, funcType);
	_context.addFunction(mangledCopy, _ast);
}

std::shared_ptr<Node> BorlandASTParser::parseFuncName()
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
				auto nameNode = NameNode::create(_context, nameView);
				name = name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
				start = c + 1;    // skip already checked chars and one of '%', '$', '@'
			}
			if (!consumeIfPossible('@')) {    // $ or %
				break;
			}
		}
		++c;
	}

	if (peekChar('%')) {
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

std::shared_ptr<Node> BorlandASTParser::parseOperator()
{
	if (consumeIfPossible("$o")) {
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

std::shared_ptr<Node> BorlandASTParser::parseName(const char *end)
{
	std::shared_ptr<Node> name = nullptr;

	const char *start = _mangled.begin();
	const char *c = _mangled.begin();
	while (c < end) {
		if (*c == '%' || *c == '@') {
			auto nameView = StringView(start, c);
			if (!nameView.empty()) {
				_mangled.consumeFront(nameView);        // propagate to mangled
				auto nameNode = NameNode::create(_context, nameView);
				name = name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
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
		auto nameNode = NameNode::create(_context, nameView);
		name = name ? std::static_pointer_cast<Node>(NestedNameNode::create(_context, name, nameNode)) : nameNode;
	}

	if (peekChar('%') && c != end) {    // check end if next parameter is template
		name = parseTemplate(name);
	}

	if (_mangled.begin() != end) {        // length was wrong
		_status = invalid_mangled_name;
		return nullptr;
	}

	return name;
}

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
	std::shared_ptr<Node> retType = nullptr;
	if (consumeIfPossible('$')) {
		retType = parseType();
		if (!checkResult(retType)) {
			return nullptr;
		}
	}

	return FunctionTypeNode::create(_context, callConv, paramsNode, retType, quals, isVarArg);
}

Qualifiers BorlandASTParser::parseQualifiers()
{
	bool is_volatile = consumeIfPossible('w');
	bool is_const = consumeIfPossible('x');

	return {is_volatile, is_const};
}

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

std::shared_ptr<NodeArray> BorlandASTParser::parseFuncParams()
{
	auto params = NodeArray::create();

	while (!_mangled.empty() && statusOk() && !peekChar('$')) {
		if (consumeIfPossible('t')) {    // TODO delphi check for t before named types
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

std::shared_ptr<Node> BorlandASTParser::parseType()
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

	if (_mangled.consumeFront('a')) {
		return parseArray(quals);
	}

	if (peekChar('q')) {
		return parseFuncType(quals);
	}

	/* named type */
	unsigned len = parseNumber();
	if (_status == invalid_mangled_name) {
		return nullptr;
	}
	if (len > 0) {
		return parseNamedType(len, quals);
	}

	/* must be built-in type */
	return parseBuildInType(quals);
}

std::shared_ptr<Node> BorlandASTParser::parsePointer(const retdec::demangler::borland::Qualifiers &quals)
{
	auto pointeeType = parseType();
	if (!checkResult(pointeeType)) {
		return nullptr;
	}

	return PointerTypeNode::create(_context, pointeeType, quals);
}

std::shared_ptr<Node> BorlandASTParser::parseReference()
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

std::shared_ptr<Node> BorlandASTParser::parseRReference()
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

std::shared_ptr<Node> BorlandASTParser::parseArray(const retdec::demangler::borland::Qualifiers &quals)
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

std::shared_ptr<Node> BorlandASTParser::parseBuildInType(const Qualifiers &quals)
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
		return CharTypeNode::create(_context, ThreeStateSignness::signed_char, quals);
	} else if (consumeIfPossible("uc")) {
		return CharTypeNode::create(_context, ThreeStateSignness::unsigned_char, quals);
	} else if (consumeIfPossible('c')) {
		return CharTypeNode::create(_context, ThreeStateSignness::no_prefix, quals);
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

std::shared_ptr<Node> BorlandASTParser::parseNamedType(unsigned nameLen, const Qualifiers &quals)
{
	const char *end_named = _mangled.begin() + nameLen;
	if (_mangled.end() < end_named) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	auto type = _context.getNamedType({_mangled.begin(), nameLen}, quals);
	if (type) {
		return type;
	}

	auto nameNode = parseName(end_named);
	if (nameNode == nullptr) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	auto newType = NamedTypeNode::create(_context, nameNode, quals);
	_context.addNamedType(newType);
	return newType;
}

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
		templateNameNode = NameNode::create(_context, templateName);
	}

	if (templateNamespace) {
		templateNameNode = NestedNameNode::create(_context, templateNamespace, templateNameNode);
	}

	return templateNameNode;
}

std::shared_ptr<Node> BorlandASTParser::parseTemplateParams()
{
	auto params = NodeArray::create();
	while (!peekChar('%')) {
		consumeIfPossible('V');    // information about varargness of template is not used
		if (consumeIfPossible('t')) {
			unsigned backref = peekNumber();
			if (backref > 0 && backref <= params->size()) {
				parseNumber();
				params->addNode(params->get(backref - 1));
				continue;
			}
//			if (!parseBackref(params)) {
//				return nullptr;
//			}
		}// TODO else nothing, check delphi for tests
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
