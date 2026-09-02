package hook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- lexer ----

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokString
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokLBracket
	tokRBracket
	tokComma
	tokSemi
	tokDot
	tokColon
	tokAssign
	tokPlus
	tokMinus
	tokStar
	tokSlash
	tokPercent
	tokEq
	tokNeq
	tokStrictEq
	tokStrictNeq
	tokLt
	tokLe
	tokGt
	tokGe
	tokAnd
	tokOr
	tokBang
	tokFunction
	tokReturn
	tokIf
	tokElse
	tokFor
	tokOf
	tokVar
	tokLet
	tokConst
	tokTrue
	tokFalse
	tokNull
	tokUndefined
	tokDelete
	tokNew
)

type token struct {
	kind tokKind
	text string
	num  float64
}

var keywords = map[string]tokKind{
	"function": tokFunction, "return": tokReturn, "if": tokIf, "else": tokElse,
	"for": tokFor, "of": tokOf, "var": tokVar, "let": tokLet, "const": tokConst,
	"true": tokTrue, "false": tokFalse, "null": tokNull, "undefined": tokUndefined,
	"delete": tokDelete, "new": tokNew,
}

type lexer struct {
	src string
	pos int
}

func lex(src string) ([]token, error) {
	l := &lexer{src: src}
	var toks []token
	for {
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, tok)
		if tok.kind == tokEOF {
			return toks, nil
		}
	}
}

func (l *lexer) next() (token, error) {
	for {
		for l.pos < len(l.src) {
			c := l.src[l.pos]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				l.pos++
				continue
			}
			if c == '/' {
				if l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					for l.pos < len(l.src) && l.src[l.pos] != '\n' {
						l.pos++
					}
					continue
				}
				if l.pos+1 < len(l.src) && l.src[l.pos+1] == '*' {
					l.pos += 2
					for l.pos+1 < len(l.src) && !(l.src[l.pos] == '*' && l.src[l.pos+1] == '/') {
						l.pos++
					}
					l.pos += 2
					continue
				}
			}
			break
		}
		if l.pos >= len(l.src) {
			return token{kind: tokEOF}, nil
		}
		c := l.src[l.pos]
		if isIdentStart(c) {
			start := l.pos
			for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
				l.pos++
			}
			text := l.src[start:l.pos]
			if kw, ok := keywords[text]; ok {
				return token{kind: kw, text: text}, nil
			}
			return token{kind: tokIdent, text: text}, nil
		}
		if c >= '0' && c <= '9' {
			start := l.pos
			for l.pos < len(l.src) && (l.src[l.pos] >= '0' && l.src[l.pos] <= '9' || l.src[l.pos] == '.') {
				l.pos++
			}
			n, err := strconv.ParseFloat(l.src[start:l.pos], 64)
			if err != nil {
				return token{}, fmt.Errorf("syntax: invalid number %q", l.src[start:l.pos])
			}
			return token{kind: tokNumber, text: l.src[start:l.pos], num: n}, nil
		}
		if c == '"' || c == '\'' {
			quote := c
			l.pos++
			var b strings.Builder
			for l.pos < len(l.src) && l.src[l.pos] != quote {
				if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
					l.pos++
					switch l.src[l.pos] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case '\\':
						b.WriteByte('\\')
					default:
						b.WriteByte(l.src[l.pos])
					}
					l.pos++
					continue
				}
				b.WriteByte(l.src[l.pos])
				l.pos++
			}
			if l.pos >= len(l.src) {
				return token{}, errors.New("syntax: unterminated string")
			}
			l.pos++
			return token{kind: tokString, text: b.String()}, nil
		}
		l.pos++
		switch c {
		case '(':
			return token{kind: tokLParen}, nil
		case ')':
			return token{kind: tokRParen}, nil
		case '{':
			return token{kind: tokLBrace}, nil
		case '}':
			return token{kind: tokRBrace}, nil
		case '[':
			return token{kind: tokLBracket}, nil
		case ']':
			return token{kind: tokRBracket}, nil
		case ',':
			return token{kind: tokComma}, nil
		case ';':
			return token{kind: tokSemi}, nil
		case '.':
			return token{kind: tokDot}, nil
		case ':':
			return token{kind: tokColon}, nil
		case '=':
			if l.pos < len(l.src) && l.src[l.pos] == '=' {
				l.pos++
				if l.pos < len(l.src) && l.src[l.pos] == '=' {
					l.pos++
					return token{kind: tokStrictEq}, nil
				}
				return token{kind: tokEq}, nil
			}
			return token{kind: tokAssign}, nil
		case '!':
			if l.pos < len(l.src) && l.src[l.pos] == '=' {
				l.pos++
				if l.pos < len(l.src) && l.src[l.pos] == '=' {
					l.pos++
					return token{kind: tokStrictNeq}, nil
				}
				return token{kind: tokNeq}, nil
			}
			return token{kind: tokBang}, nil
		case '+':
			return token{kind: tokPlus}, nil
		case '-':
			return token{kind: tokMinus}, nil
		case '*':
			return token{kind: tokStar}, nil
		case '/':
			return token{kind: tokSlash}, nil
		case '%':
			return token{kind: tokPercent}, nil
		case '<':
			if l.pos < len(l.src) && l.src[l.pos] == '=' {
				l.pos++
				return token{kind: tokLe}, nil
			}
			return token{kind: tokLt}, nil
		case '>':
			if l.pos < len(l.src) && l.src[l.pos] == '=' {
				l.pos++
				return token{kind: tokGe}, nil
			}
			return token{kind: tokGt}, nil
		case '&':
			if l.pos < len(l.src) && l.src[l.pos] == '&' {
				l.pos++
				return token{kind: tokAnd}, nil
			}
			return token{}, errors.New("syntax: single & is not supported")
		case '|':
			if l.pos < len(l.src) && l.src[l.pos] == '|' {
				l.pos++
				return token{kind: tokOr}, nil
			}
			return token{}, errors.New("syntax: single | is not supported")
		}
		return token{}, fmt.Errorf("syntax: unexpected character %q", string(c))
	}
}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

// ---- AST ----

type expr interface{}

type numLit float64
type strLit string
type boolLit bool
type nullLit struct{}
type ident string
type objLit map[string]expr
type arrLit []expr
type member struct {
	obj  expr
	prop expr
}
type call struct {
	fn   expr
	args []expr
}
type binary struct {
	op   string
	l, r expr
}
type unary struct {
	op string
	x  expr
}
type assignExpr struct {
	target expr
	value  expr
}
type ifExpr struct {
	cond, then, els expr
}
type forOfExpr struct {
	v    string
	it   expr
	body []expr
}
type fnLit struct {
	name   string
	params []string
	body   []expr
}

// statements
type varDecl struct {
	name string
	init expr
}
type exprStmt struct {
	x expr
}
type retStmt struct {
	value expr
}
type blockStmt []expr
type ifStmt struct {
	cond expr
	then expr
	els  expr
}
type forOfStmt struct {
	v    string
	it   expr
	body []expr
}
type fnDecl struct {
	fn fnLit
}

// ---- parser ----

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) match(k tokKind) (token, bool) {
	if p.toks[p.pos].kind == k {
		t := p.toks[p.pos]
		p.pos++
		return t, true
	}
	return token{}, false
}

func parse(src string) ([]expr, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var body []expr
	for p.peek().kind != tokEOF {
		st, err := p.stmt()
		if err != nil {
			return nil, err
		}
		if st != nil {
			body = append(body, st)
		}
	}
	return body, nil
}

func (p *parser) stmt() (expr, error) {
	t := p.peek()
	switch t.kind {
	case tokSemi:
		p.next()
		return nil, nil
	case tokVar, tokLet, tokConst:
		p.next()
		name := p.next()
		if name.kind != tokIdent {
			return nil, errors.New("syntax: expected variable name")
		}
		var init expr
		if _, ok := p.match(tokAssign); ok {
			e, err := p.expression()
			if err != nil {
				return nil, err
			}
			init = e
		}
		if _, ok := p.match(tokSemi); !ok {
			// tolerate a missing semicolon before a block-end or EOF
			if p.peek().kind != tokRBrace && p.peek().kind != tokEOF {
				return nil, errors.New("syntax: expected ; after declaration")
			}
		}
		return &varDecl{name: name.text, init: init}, nil
	case tokFunction:
		return p.functionDecl()
	case tokIf:
		p.next()
		if _, ok := p.match(tokLParen); !ok {
			return nil, errors.New("syntax: expected ( after if")
		}
		cond, err := p.expression()
		if err != nil {
			return nil, err
		}
		if _, ok := p.match(tokRParen); !ok {
			return nil, errors.New("syntax: expected ) in if")
		}
		thenBranch, err := p.blockOrStmt()
		if err != nil {
			return nil, err
		}
		var elseBranch expr
		if _, ok := p.match(tokElse); ok {
			elseBranch, err = p.blockOrStmt()
			if err != nil {
				return nil, err
			}
		}
		return &ifStmt{cond: cond, then: thenBranch, els: elseBranch}, nil
	case tokFor:
		p.next()
		if _, ok := p.match(tokLParen); !ok {
			return nil, errors.New("syntax: expected ( after for")
		}
		if _, ok := p.match(tokVar); !ok {
			if _, ok := p.match(tokLet); !ok {
				p.match(tokConst)
			}
		}
		v := p.next()
		if v.kind != tokIdent {
			return nil, errors.New("syntax: expected loop variable")
		}
		if _, ok := p.match(tokOf); !ok {
			return nil, errors.New("syntax: only for..of is supported")
		}
		it, err := p.expression()
		if err != nil {
			return nil, err
		}
		if _, ok := p.match(tokRParen); !ok {
			return nil, errors.New("syntax: expected ) in for")
		}
		branch, err := p.blockOrStmt()
		if err != nil {
			return nil, err
		}
		body, ok := branch.(blockStmt)
		if !ok {
			return nil, errors.New("syntax: for body must be a block")
		}
		return &forOfStmt{v: v.text, it: it, body: body}, nil
	case tokReturn:
		p.next()
		var e expr
		if p.peek().kind != tokSemi && p.peek().kind != tokRBrace && p.peek().kind != tokEOF {
			var err error
			e, err = p.expression()
			if err != nil {
				return nil, err
			}
		}
		p.eatSemi()
		return &retStmt{value: e}, nil
	default:
		e, err := p.expression()
		if err != nil {
			return nil, err
		}
		p.eatSemi()
		return &exprStmt{x: e}, nil
	}
}

func (p *parser) eatSemi() {
	if _, ok := p.match(tokSemi); !ok {
		if p.peek().kind != tokRBrace && p.peek().kind != tokEOF {
			p.syntaxPoint()
		}
	}
}

func (p *parser) syntaxPoint() {}

func (p *parser) functionDecl() (expr, error) {
	p.next() // function
	name := p.next()
	if name.kind != tokIdent {
		return nil, errors.New("syntax: top-level functions must be named")
	}
	params, body, err := p.functionBody()
	if err != nil {
		return nil, err
	}
	return &fnDecl{fn: fnLit{name: name.text, params: params, body: body}}, nil
}

func (p *parser) functionBody() ([]string, []expr, error) {
	if _, ok := p.match(tokLParen); !ok {
		return nil, nil, errors.New("syntax: expected ( after function name")
	}
	var params []string
	for p.peek().kind != tokRParen {
		param := p.next()
		if param.kind != tokIdent {
			return nil, nil, errors.New("syntax: expected parameter name")
		}
		params = append(params, param.text)
		if _, ok := p.match(tokComma); !ok {
			break
		}
	}
	if _, ok := p.match(tokRParen); !ok {
		return nil, nil, errors.New("syntax: expected ) after parameters")
	}
	if _, ok := p.match(tokLBrace); !ok {
		return nil, nil, errors.New("syntax: expected { for function body")
	}
	var body []expr
	for p.peek().kind != tokRBrace {
		if p.peek().kind == tokEOF {
			return nil, nil, errors.New("syntax: unterminated function body")
		}
		st, err := p.stmt()
		if err != nil {
			return nil, nil, err
		}
		if st != nil {
			body = append(body, st)
		}
	}
	p.next() // }
	return params, body, nil
}

func (p *parser) blockOrStmt() (expr, error) {
	if p.peek().kind == tokLBrace {
		p.next()
		var body []expr
		for p.peek().kind != tokRBrace {
			if p.peek().kind == tokEOF {
				return nil, errors.New("syntax: unterminated block")
			}
			st, err := p.stmt()
			if err != nil {
				return nil, err
			}
			if st != nil {
				body = append(body, st)
			}
		}
		p.next() // }
		return blockStmt(body), nil
	}
	return p.stmt()
}

var binaryPrecedence = map[string]int{
	"||": 1, "&&": 2,
	"==": 3, "!=": 3, "===": 3, "!==": 3,
	"<": 4, "<=": 4, ">": 4, ">=": 4,
	"+": 5, "-": 5,
	"*": 6, "/": 6, "%": 6,
}

func (p *parser) expression() (expr, error) {
	return p.binary(1)
}

func (p *parser) binOp() string {
	switch p.peek().kind {
	case tokOr:
		return "||"
	case tokAnd:
		return "&&"
	case tokEq:
		return "=="
	case tokNeq:
		return "!="
	case tokStrictEq:
		return "==="
	case tokStrictNeq:
		return "!=="
	case tokLt:
		return "<"
	case tokLe:
		return "<="
	case tokGt:
		return ">"
	case tokGe:
		return ">="
	case tokPlus:
		return "+"
	case tokMinus:
		return "-"
	case tokStar:
		return "*"
	case tokSlash:
		return "/"
	case tokPercent:
		return "%"
	}
	return ""
}

func (p *parser) binary(minPrec int) (expr, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		op := p.binOp()
		if op == "" {
			return left, nil
		}
		prec := binaryPrecedence[op]
		if prec < minPrec {
			return left, nil
		}
		p.next()
		right, err := p.binary(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &binary{op: op, l: left, r: right}
	}
}

func (p *parser) unary() (expr, error) {
	if p.peek().kind == tokBang {
		p.next()
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &unary{op: "!", x: x}, nil
	}
	if p.peek().kind == tokMinus {
		p.next()
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &unary{op: "-", x: x}, nil
	}
	return p.postfix()
}

func (p *parser) postfix() (expr, error) {
	e, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch p.peek().kind {
		case tokDot:
			p.next()
			prop := p.next()
			if prop.kind != tokIdent {
				return nil, errors.New("syntax: expected property name after .")
			}
			e = &member{obj: e, prop: strLit(prop.text)}
		case tokLBracket:
			p.next()
			idx, err := p.expression()
			if err != nil {
				return nil, err
			}
			if _, ok := p.match(tokRBracket); !ok {
				return nil, errors.New("syntax: expected ]")
			}
			e = &member{obj: e, prop: idx}
		case tokLParen:
			p.next()
			var args []expr
			for p.peek().kind != tokRParen {
				arg, err := p.expression()
				if err != nil {
					return nil, err
				}
				args = append(args, arg)
				if _, ok := p.match(tokComma); !ok {
					break
				}
			}
			if _, ok := p.match(tokRParen); !ok {
				return nil, errors.New("syntax: expected ) in call")
			}
			e = &call{fn: e, args: args}
		case tokAssign:
			// assignment expression inside an expression statement
			p.next()
			val, err := p.expression()
			if err != nil {
				return nil, err
			}
			return &assignExpr{target: e, value: val}, nil
		default:
			return e, nil
		}
	}
}

func (p *parser) primary() (expr, error) {
	t := p.peek()
	switch t.kind {
	case tokNumber:
		p.next()
		return numLit(t.num), nil
	case tokString:
		p.next()
		return strLit(t.text), nil
	case tokTrue:
		p.next()
		return boolLit(true), nil
	case tokFalse:
		p.next()
		return boolLit(false), nil
	case tokNull, tokUndefined:
		p.next()
		return nullLit{}, nil
	case tokIdent:
		p.next()
		return ident(t.text), nil
	case tokLParen:
		p.next()
		e, err := p.expression()
		if err != nil {
			return nil, err
		}
		if _, ok := p.match(tokRParen); !ok {
			return nil, errors.New("syntax: expected )")
		}
		return e, nil
	case tokLBrace:
		return p.objectLit()
	case tokLBracket:
		p.next()
		var items []expr
		for p.peek().kind != tokRBracket {
			if p.peek().kind == tokEOF {
				return nil, errors.New("syntax: unterminated array")
			}
			e, err := p.expression()
			if err != nil {
				return nil, err
			}
			items = append(items, e)
			if _, ok := p.match(tokComma); !ok {
				break
			}
		}
		if _, ok := p.match(tokRBracket); !ok {
			return nil, errors.New("syntax: expected ]")
		}
		return arrLit(items), nil
	case tokFunction:
		p.next()
		params, body, err := p.functionBody()
		if err != nil {
			return nil, err
		}
		return &fnLit{params: params, body: body}, nil
	case tokDelete, tokNew:
		return nil, errors.New("syntax: delete/new are not supported")
	}
	return nil, fmt.Errorf("syntax: unexpected token %q", t.text)
}

func (p *parser) objectLit() (expr, error) {
	if _, ok := p.match(tokLBrace); !ok {
		return nil, errors.New("syntax: expected {")
	}
	obj := objLit{}
	for p.peek().kind != tokRBrace {
		if p.peek().kind == tokEOF {
			return nil, errors.New("syntax: unterminated object")
		}
		var key string
		switch p.peek().kind {
		case tokIdent:
			key = p.next().text
		case tokString:
			key = p.next().text
		default:
			return nil, errors.New("syntax: object keys must be identifiers or strings")
		}
		if _, ok := p.match(tokColon); !ok {
			return nil, errors.New("syntax: expected : in object literal")
		}
		val, err := p.expression()
		if err != nil {
			return nil, err
		}
		obj[key] = val
		if _, ok := p.match(tokComma); !ok {
			break
		}
	}
	if _, ok := p.match(tokRBrace); !ok {
		return nil, errors.New("syntax: expected }")
	}
	return obj, nil
}

// ---- evaluator ----

type value interface{}

type num float64
type str string
type boolV bool
type nullV struct{}
type objV map[string]value
type arrBox struct {
	items []value
}

// arrV is a boxed slice (pointer) so push()/sort() mutate the same array the
// enclosing variable references (JS array semantics; an unboxed slice would
// copy the header and lose pushes on reallocation).
type arrV *arrBox
type fnV struct {
	name   string
	params []string
	body   []expr
	env    *env
}
type nfnV struct {
	name string
	fn   func(vm *vm, args []value) (value, error)
}

type env struct {
	parent *env
	vars   map[string]value
}

func (e *env) lookup(name string) (value, bool) {
	for cur := e; cur != nil; cur = cur.parent {
		if v, ok := cur.vars[name]; ok {
			return v, true
		}
	}
	return nil, false
}

func (e *env) define(name string, v value) { e.vars[name] = v }

type runnerErr struct {
	kind string
	msg  string
}

func (e *runnerErr) Error() string { return e.kind + ": " + e.msg }

func runErr(kind, msg string) *runnerErr { return &runnerErr{kind: kind, msg: msg} }

// retSignal is a control-flow error carrying an explicit `return` value. A
// `return` nested inside if/for/block statements propagates up through
// execStmt/execBranch/execForOf until callValue aborts on it (P1-1), so a
// nested return SHORT-CIRCUITS the function instead of being evaluated and
// discarded (which previously let the function continue and return the wrong
// value, and the broker then signed/delivered the wrong request).
type retSignal struct {
	value value
}

func (r *retSignal) Error() string { return "hook: return" }

type vm struct {
	limits    Limits
	ctx       context.Context
	logs      []string
	steps     int
	callDepth int
	outputLen int
}

func (v *vm) bump() error {
	v.steps++
	if v.steps > v.limits.MaxSteps {
		return runErr("budget", "execution step budget exceeded (infinite loop?)")
	}
	if v.steps%1024 == 0 {
		select {
		case <-v.ctx.Done():
			return runErr("timeout", "execution time budget exceeded")
		default:
		}
	}
	return nil
}

func (v *vm) logLine(s string) error {
	if v.outputLen+len(s)+1 > v.limits.MaxOutputBytes {
		return runErr("budget", "output exceeds the runner bound")
	}
	v.outputLen += len(s) + 1
	v.logs = append(v.logs, s)
	return nil
}

func (v *vm) executeScript(src string, request map[string]any) status {
	body, err := parse(src)
	if err != nil {
		return status{err: err, result: fail(ResultError{Kind: "syntax", Message: err.Error()})}
	}
	root := &env{vars: map[string]value{}}
	root.define("runtime", runtimeObject(v))
	root.define("Object", objectNative(v))
	root.define("encodeURIComponent", nfnV{name: "encodeURIComponent", fn: percentEncodeNative})
	root.define("req", goToValue(request))

	for _, st := range body {
		if err := v.execStmt(root, st); err != nil {
			return status{err: err, result: fail(ResultError{Kind: errorKind(err), Message: err.Error()})}
		}
	}
	mainFn, ok := root.lookup("main")
	if !ok {
		return status{err: runErr("schema", "script must define a function named main(request)"),
			result: fail(ResultError{Kind: "schema", Message: "script must define a function named main(request)"})}
	}
	result, err := v.callValue(root, mainFn, []value{root.lookupValue("req")})
	if err != nil {
		return status{err: err, result: fail(ResultError{Kind: errorKind(err), Message: err.Error()})}
	}
	return status{ok: true, value: result}
}

func errorKind(err error) string {
	if re, ok := err.(*runnerErr); ok {
		return re.kind
	}
	return "runtime"
}

func (e *env) lookupValue(name string) value {
	v, _ := e.lookup(name)
	if v == nil {
		return nullV{}
	}
	return v
}

func (v *vm) execStmt(e *env, st expr) error {
	if err := v.bump(); err != nil {
		return err
	}
	switch s := st.(type) {
	case nil:
		return nil
	case *varDecl:
		if s.init != nil {
			val, err := v.eval(e, s.init)
			if err != nil {
				return err
			}
			e.define(s.name, val)
		} else {
			e.define(s.name, nullV{})
		}
		return nil
	case *exprStmt:
		_, err := v.eval(e, s.x)
		return err
	case *retStmt:
		// A nested return must short-circuit the enclosing function. Evaluate
		// the value and propagate it as a retSignal control-flow marker that
		// callValue interprets as "abort with this return value" (P1-1). The
		// value is no longer evaluated-and-discarded.
		if s.value != nil {
			val, err := v.eval(e, s.value)
			if err != nil {
				return err
			}
			return &retSignal{value: val}
		}
		return &retSignal{value: nullV{}}
	case blockStmt:
		child := &env{parent: e, vars: map[string]value{}}
		for _, sub := range s {
			if err := v.execStmt(child, sub); err != nil {
				return err
			}
		}
		return nil
	case *ifStmt:
		cond, err := v.eval(e, s.cond)
		if err != nil {
			return err
		}
		if truthy(cond) {
			return v.execBranch(e, s.then)
		}
		if s.els != nil {
			return v.execBranch(e, s.els)
		}
		return nil
	case *forOfStmt:
		iter, err := v.eval(e, s.it)
		if err != nil {
			return err
		}
		items, ok := iter.(arrV)
		if !ok {
			return runErr("type", "for..of expects an array")
		}
		// Iterate by index over the live array (JS array iterator semantics):
		// a body that appends to the iterated array is still bounded by the
		// interpreter step budget rather than running forever.
		for i := 0; i < len(items.items); i++ {
			if err := v.bump(); err != nil {
				return err
			}
			item := items.items[i]
			child := &env{parent: e, vars: map[string]value{s.v: item}}
			for _, sub := range s.body {
				if err := v.execStmt(child, sub); err != nil {
					return err
				}
			}
		}
		return nil
	case *fnDecl:
		if s.fn.name != "" {
			e.define(s.fn.name, fnV{name: s.fn.name, params: s.fn.params, body: s.fn.body, env: e})
		}
		return nil
	}
	return runErr("runtime", "unsupported statement")
}

func (v *vm) execBranch(e *env, branch expr) error {
	if b, ok := branch.(blockStmt); ok {
		return v.execStmt(e, b)
	}
	if dl, ok := branch.(*fnDecl); ok {
		_ = dl
	}
	return v.execStmt(e, branch)
}

func (v *vm) eval(e *env, node expr) (value, error) {
	if err := v.bump(); err != nil {
		return nil, err
	}
	switch n := node.(type) {
	case numLit:
		return num(n), nil
	case strLit:
		return str(n), nil
	case boolLit:
		return boolV(n), nil
	case nullLit:
		return nullV{}, nil
	case ident:
		if val, ok := e.lookup(string(n)); ok {
			return val, nil
		}
		return nil, runErr("reference", "undefined identifier "+string(n))
	case objLit:
		o := objV{}
		for k, valExpr := range n {
			val, err := v.eval(e, valExpr)
			if err != nil {
				return nil, err
			}
			o[k] = val
		}
		return o, nil
	case arrLit:
		a := &arrBox{}
		for _, item := range n {
			val, err := v.eval(e, item)
			if err != nil {
				return nil, err
			}
			a.items = append(a.items, val)
		}
		return arrV(a), nil
	case *member:
		return v.evalMember(e, n)
	case *call:
		return v.evalCall(e, n)
	case *binary:
		return v.evalBinary(e, n)
	case *unary:
		return v.evalUnary(e, n)
	case *ifExpr:
		cond, err := v.eval(e, n.cond)
		if err != nil {
			return nil, err
		}
		if truthy(cond) {
			return v.eval(e, n.then)
		}
		if n.els != nil {
			return v.eval(e, n.els)
		}
		return nullV{}, nil
	case *fnLit:
		return fnV{name: n.name, params: n.params, body: n.body, env: e}, nil
	case *assignExpr:
		val, err := v.eval(e, n.value)
		if err != nil {
			return nil, err
		}
		if err := v.assignTarget(e, n.target, val); err != nil {
			return nil, err
		}
		return val, nil
	case *retStmt:
		if n.value != nil {
			return v.eval(e, n.value)
		}
		return nullV{}, nil
	}
	return nil, runErr("runtime", "unsupported expression")
}

func (v *vm) assignTarget(e *env, target expr, val value) error {
	switch t := target.(type) {
	case ident:
		if _, ok := e.lookup(string(t)); !ok {
			return runErr("reference", "assignment to undeclared variable "+string(t))
		}
		for cur := e; cur != nil; cur = cur.parent {
			if _, ok := cur.vars[string(t)]; ok {
				cur.vars[string(t)] = val
				return nil
			}
		}
		return runErr("reference", "assignment to undeclared variable "+string(t))
	case *member:
		base, err := v.eval(e, t.obj)
		if err != nil {
			return err
		}
		obj, ok := base.(objV)
		if !ok {
			return runErr("type", "cannot assign a property on a non-object")
		}
		key, err := v.propKey(e, t.prop)
		if err != nil {
			return err
		}
		obj[key] = val
		return nil
	}
	return runErr("type", "unsupported assignment target")
}

func (v *vm) propKey(e *env, prop expr) (string, error) {
	switch p := prop.(type) {
	case strLit:
		return string(p), nil
	default:
		val, err := v.eval(e, prop)
		if err != nil {
			return "", err
		}
		s, ok := toString(val)
		if !ok {
			return "", runErr("type", "property key must be a string")
		}
		return s, nil
	}
}

func (v *vm) evalMember(e *env, n *member) (value, error) {
	base, err := v.eval(e, n.obj)
	if err != nil {
		return nil, err
	}
	key, err := v.propKey(e, n.prop)
	if err != nil {
		return nil, err
	}
	switch b := base.(type) {
	case objV:
		if val, ok := b[key]; ok {
			if val == nil {
				return nil, runErr("reference", "no such runtime capability "+key)
			}
			return val, nil
		}
		if key == "length" {
			return num(len(b)), nil
		}
		return nil, runErr("reference", "no property "+key+" on object")
	case arrV:
		return v.arrMember(b, key)
	case str:
		return v.strMember(b, key)
	case nfnV:
		return nil, runErr("reflection", "reflection on native functions is disabled")
	case fnV:
		return nil, runErr("reflection", "reflection on functions is disabled")
	}
	return nil, runErr("type", "cannot read a property on this value")
}

func (v *vm) arrMember(b arrV, key string) (value, error) {
	if key == "length" {
		return num(len(b.items)), nil
	}
	if key == "push" {
		return nfnV{name: "push", fn: func(v *vm, args []value) (value, error) {
			for _, a := range args {
				b.items = append(b.items, a)
			}
			return num(len(b.items)), nil
		}}, nil
	}
	if key == "sort" {
		return nfnV{name: "sort", fn: func(v *vm, args []value) (value, error) {
			sort.SliceStable(b.items, func(i, j int) bool {
				si, ok1 := toString(b.items[i])
				sj, ok2 := toString(b.items[j])
				if !ok1 || !ok2 {
					return false
				}
				return si < sj
			})
			return b, nil
		}}, nil
	}
	if key == "join" {
		return nfnV{name: "join", fn: func(v *vm, args []value) (value, error) {
			sep := ","
			if len(args) > 0 {
				if s, ok := toString(args[0]); ok {
					sep = s
				}
			}
			parts := make([]string, 0, len(b.items))
			for _, item := range b.items {
				s, ok := toString(item)
				if !ok {
					return nil, runErr("type", "join expects stringable items")
				}
				parts = append(parts, s)
			}
			return str(strings.Join(parts, sep)), nil
		}}, nil
	}
	// numeric index
	if idx, err := strconv.Atoi(key); err == nil {
		if idx >= 0 && idx < len(b.items) {
			return b.items[idx], nil
		}
		return nil, runErr("reference", "array index out of range "+key)
	}
	return nil, runErr("reference", "no such array member "+key)
}

func (v *vm) strMember(b str, key string) (value, error) {
	if key == "length" {
		return num(len(b)), nil
	}
	if key == "toUpperCase" {
		return nfnV{name: "toUpperCase", fn: func(v *vm, args []value) (value, error) {
			return str(strings.ToUpper(string(b))), nil
		}}, nil
	}
	if key == "toLowerCase" {
		return nfnV{name: "toLowerCase", fn: func(v *vm, args []value) (value, error) {
			return str(strings.ToLower(string(b))), nil
		}}, nil
	}
	if key == "split" {
		return nfnV{name: "split", fn: func(v *vm, args []value) (value, error) {
			sep := ","
			if len(args) > 0 {
				if s, ok := toString(args[0]); ok {
					sep = s
				}
			}
			out := &arrBox{}
			for _, part := range strings.Split(string(b), sep) {
				out.items = append(out.items, str(part))
			}
			return arrV(out), nil
		}}, nil
	}
	if key == "indexOf" {
		return nfnV{name: "indexOf", fn: func(v *vm, args []value) (value, error) {
			if len(args) == 0 {
				return num(-1), nil
			}
			needle, ok := toString(args[0])
			if !ok {
				return nil, runErr("type", "indexOf expects a string")
			}
			return num(strings.Index(string(b), needle)), nil
		}}, nil
	}
	if key == "substring" {
		return nfnV{name: "substring", fn: func(v *vm, args []value) (value, error) {
			start := 0.0
			if len(args) > 0 {
				if n, ok := toNumber(args[0]); ok {
					start = n
				}
			}
			end := float64(len(b))
			if len(args) > 1 {
				if n, ok := toNumber(args[1]); ok {
					end = n
				}
			}
			s := int(start)
			e := int(end)
			if s < 0 {
				s = 0
			}
			if s > len(b) {
				s = len(b)
			}
			if e < s {
				e = s
			}
			if e > len(b) {
				e = len(b)
			}
			return str(string(b)[s:e]), nil
		}}, nil
	}
	return nil, runErr("reference", "no such string method "+key)
}

func (v *vm) evalCall(e *env, n *call) (value, error) {
	callee, err := v.eval(e, n.fn)
	if err != nil {
		return nil, err
	}
	args := make([]value, 0, len(n.args))
	for _, a := range n.args {
		val, err := v.eval(e, a)
		if err != nil {
			return nil, err
		}
		args = append(args, val)
	}
	return v.callValue(e, callee, args)
}

func (v *vm) callValue(e *env, callee value, args []value) (value, error) {
	if err := v.bump(); err != nil {
		return nil, err
	}
	switch fn := callee.(type) {
	case nfnV:
		return fn.fn(v, args)
	case fnV:
		if len(args) < len(fn.params) {
			return nil, runErr("type", "function "+fn.name+" expects "+strconv.Itoa(len(fn.params))+" arguments, got "+strconv.Itoa(len(args)))
		}
		// Enforce MaxCallDepth in the evaluator's call path (P2-6): a
		// deep-recursion script is refused before it can overflow the Go stack.
		v.callDepth++
		if v.callDepth > v.limits.MaxCallDepth {
			v.callDepth--
			return nil, runErr("budget", "call depth limit exceeded")
		}
		defer func() { v.callDepth-- }()
		callEnv := &env{parent: fn.env, vars: map[string]value{}}
		for i, p := range fn.params {
			callEnv.define(p, args[i])
		}
		for _, st := range fn.body {
			if err := v.execStmt(callEnv, st); err != nil {
				// A nested return propagates as a retSignal control-flow marker:
				// abort the function and return its value (does not wrap, so the
				// signal survives and the function SHORT-CIRCUITS correctly).
				var ret *retSignal
				if errors.As(err, &ret) {
					return ret.value, nil
				}
				return nil, err
			}
		}
		return nullV{}, nil
	}
	return nil, runErr("type", "value is not callable")
}

func (v *vm) evalBinary(e *env, n *binary) (value, error) {
	l, err := v.eval(e, n.l)
	if err != nil {
		return nil, err
	}
	switch n.op {
	case "&&":
		if !truthy(l) {
			return boolV(false), nil
		}
		return v.eval(e, n.r)
	case "||":
		if truthy(l) {
			return boolV(true), nil
		}
		return v.eval(e, n.r)
	}
	r, err := v.eval(e, n.r)
	if err != nil {
		return nil, err
	}
	switch n.op {
	case "+":
		if ls, ok := toString(l); ok {
			if rs, ok2 := toString(r); ok2 {
				return str(ls + rs), nil
			}
		}
		if lv, ok := toNumber(l); ok {
			if rv, ok2 := toNumber(r); ok2 {
				return num(lv + rv), nil
			}
		}
		return nil, runErr("type", "+ operands must be numbers or strings")
	case "-", "*", "/", "%":
		lv, ok1 := toNumber(l)
		rv, ok2 := toNumber(r)
		if !ok1 || !ok2 {
			return nil, runErr("type", "arithmetic on non-numbers")
		}
		switch n.op {
		case "-":
			return num(lv - rv), nil
		case "*":
			return num(lv * rv), nil
		case "/":
			if rv == 0 {
				return nil, runErr("type", "division by zero")
			}
			return num(lv / rv), nil
		default:
			if rv == 0 {
				return nil, runErr("type", "modulo by zero")
			}
			return num(float64(int(lv) % int(rv))), nil
		}
	case "<", "<=", ">", ">=":
		if ls, ok := toString(l); ok {
			if rs, ok2 := toString(r); ok2 {
				switch n.op {
				case "<":
					return boolV(ls < rs), nil
				case "<=":
					return boolV(ls <= rs), nil
				case ">":
					return boolV(ls > rs), nil
				default:
					return boolV(ls >= rs), nil
				}
			}
		}
		if lv, ok := toNumber(l); ok {
			if rv, ok2 := toNumber(r); ok2 {
				switch n.op {
				case "<":
					return boolV(lv < rv), nil
				case "<=":
					return boolV(lv <= rv), nil
				case ">":
					return boolV(lv > rv), nil
				default:
					return boolV(lv >= rv), nil
				}
			}
		}
		return nil, runErr("type", "comparison on incompatible operands")
	case "==", "===", "!=", "!==":
		eq := looseEq(l, r)
		if n.op == "!=" || n.op == "!==" {
			eq = !eq
		}
		return boolV(eq), nil
	}
	return nil, runErr("runtime", "unsupported operator "+n.op)
}

func (v *vm) evalUnary(e *env, n *unary) (value, error) {
	x, err := v.eval(e, n.x)
	if err != nil {
		return nil, err
	}
	if n.op == "!" {
		return boolV(!truthy(x)), nil
	}
	if n.op == "-" {
		val, ok := toNumber(x)
		if !ok {
			return nil, runErr("type", "unary - on a non-number")
		}
		return num(-val), nil
	}
	return nil, runErr("runtime", "unsupported unary operator")
}

func truthy(v value) bool {
	switch t := v.(type) {
	case boolV:
		return bool(t)
	case num:
		return t != 0
	case str:
		return t != ""
	case nullV:
		return false
	}
	return true
}

func toNumber(v value) (float64, bool) {
	switch t := v.(type) {
	case num:
		return float64(t), true
	case boolV:
		if t {
			return 1, true
		}
		return 0, true
	case str:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func toString(v value) (string, bool) {
	switch t := v.(type) {
	case str:
		return string(t), true
	case num:
		f := float64(t)
		if f == float64(int64(f)) && f < 1e15 {
			return strconv.FormatInt(int64(f), 10), true
		}
		return strconv.FormatFloat(f, 'f', -1, 64), true
	case boolV:
		if t {
			return "true", true
		}
		return "false", true
	case nullV:
		return "null", true
	}
	return "", false
}

func looseEq(a, b value) bool {
	if av, ok := a.(str); ok {
		if bv, ok2 := b.(str); ok2 {
			return string(av) == string(bv)
		}
		return false
	}
	if an, ok := a.(num); ok {
		if bn, ok2 := b.(num); ok2 {
			return float64(an) == float64(bn)
		}
		return false
	}
	if ab, ok := a.(boolV); ok {
		if bb, ok2 := b.(boolV); ok2 {
			return bool(ab) == bool(bb)
		}
		return false
	}
	if _, ok := a.(nullV); ok {
		_, ok2 := b.(nullV)
		return ok2
	}
	return false
}

func goToValue(v any) value {
	switch t := v.(type) {
	case nil:
		return nullV{}
	case map[string]any:
		o := objV{}
		for k, item := range t {
			o[k] = goToValue(item)
		}
		return o
	case []any:
		a := &arrBox{}
		for _, item := range t {
			a.items = append(a.items, goToValue(item))
		}
		return arrV(a)
	case string:
		return str(t)
	case float64:
		return num(t)
	case int64:
		return num(float64(t))
	case bool:
		return boolV(t)
	}
	return nullV{}
}

func valueToGo(v value) (any, bool) {
	return valueToGoDepth(v, 0)
}

// maxGoConvertDepth bounds valueToGo's structural recursion so a script-built
// CYCLIC object/array cannot trigger an unbounded Go stack overflow (which is a
// fatal runtime error, not a recoverable panic). A cyclic structure fails
// closed as "unconvertible" instead of crashing the controller (P2-6).
const maxGoConvertDepth = 512

func valueToGoDepth(v value, depth int) (any, bool) {
	if depth > maxGoConvertDepth {
		return nil, false
	}
	switch t := v.(type) {
	case str:
		return string(t), true
	case num:
		return float64(t), true
	case boolV:
		return bool(t), true
	case nullV:
		return nil, true
	case objV:
		out := map[string]any{}
		for k, item := range t {
			converted, ok := valueToGoDepth(item, depth+1)
			if !ok {
				return nil, false
			}
			out[k] = converted
		}
		return out, true
	case arrV:
		out := []any{}
		for _, item := range t.items {
			converted, ok := valueToGoDepth(item, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, converted)
		}
		return out, true
	}
	return nil, false
}

func percentEncodeNative(v *vm, args []value) (value, error) {
	if len(args) != 1 {
		return nil, runErr("type", "percentEncode takes one argument")
	}
	s, ok := toString(args[0])
	if !ok {
		return nil, runErr("type", "percentEncode expects a string")
	}
	return str(PercentEncode(s)), nil
}

func runtimeObject(v *vm) objV {
	return objV{
		"ts": nfnV{name: "ts", fn: func(v *vm, args []value) (value, error) {
			return str(time.Now().UTC().Format("2006-01-02T15:04Z")), nil
		}},
		"now": nfnV{name: "now", fn: func(v *vm, args []value) (value, error) {
			return num(float64(time.Now().UnixMilli())), nil
		}},
		"nonce": nfnV{name: "nonce", fn: func(v *vm, args []value) (value, error) {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, runErr("type", "nonce: random unavailable")
			}
			return str(hex.EncodeToString(b[:])), nil
		}},
		"percentEncode": nfnV{name: "percentEncode", fn: percentEncodeNative},
		"canonicalQuery": nfnV{name: "canonicalQuery", fn: func(v *vm, args []value) (value, error) {
			if len(args) != 1 {
				return nil, runErr("type", "canonicalQuery takes one object")
			}
			m, ok := args[0].(objV)
			if !ok {
				return nil, runErr("type", "canonicalQuery expects an object")
			}
			params := map[string]string{}
			for k, item := range m {
				s, ok := toString(item)
				if !ok {
					return nil, runErr("type", "canonicalQuery param values must be strings")
				}
				params[k] = s
			}
			return str(CanonicalQuery(params)), nil
		}},
		"log": nfnV{name: "log", fn: func(v *vm, args []value) (value, error) {
			parts := make([]string, 0, len(args))
			for _, a := range args {
				s, ok := toString(a)
				if !ok {
					return nil, runErr("type", "log expects stringable values")
				}
				parts = append(parts, s)
			}
			if err := v.logLine(strings.Join(parts, " ")); err != nil {
				return nil, err
			}
			return nullV{}, nil
		}},
		"require": nfnV{name: "require", fn: func(v *vm, args []value) (value, error) {
			return nil, runErr("reference", "no bridge: require()/module loading is disabled")
		}},
		"fetch": nfnV{name: "fetch", fn: func(v *vm, args []value) (value, error) {
			return nil, runErr("reference", "no bridge: network is disabled")
		}},
		"process": nfnV{name: "process", fn: func(v *vm, args []value) (value, error) {
			return nil, runErr("reference", "no bridge: process is disabled")
		}},
	}
}

func objectNative(v *vm) objV {
	return objV{
		"keys": nfnV{name: "keys", fn: func(v *vm, args []value) (value, error) {
			if len(args) != 1 {
				return nil, runErr("type", "Object.keys takes one argument")
			}
			out := &arrBox{}
			switch t := args[0].(type) {
			case objV:
				keys := make([]string, 0, len(t))
				for k := range t {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					out.items = append(out.items, str(k))
				}
				return arrV(out), nil
			case arrV:
				for i := range t.items {
					out.items = append(out.items, str(strconv.Itoa(i)))
				}
				return arrV(out), nil
			}
			return nil, runErr("type", "Object.keys expects an object")
		}},
	}
}

// status is the execution outcome of one script.
type status struct {
	ok     bool
	value  value
	result Result
	err    error
}
