// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package versifier recognizes internal structure of random (currently text-only) data
// and allows to generate data of a similar structure (for some very weak definition of "similar").
package main

/*
On efficiency of versifier.
On xml text after 2.5 hours of fuzzing:
Without versifier fuzzing discovered 902 inputs.
With versifier fuzzing discovered 1055 inputs and versifier discovered 83 inputs.
Versifier generated new inputs + increased fuzzing efficiency by 25% +
uncovered 62 new basic blocks (excluding counters) which accounts for 2.5% of all discovered basic blocks.
On json test after 1 hour of fuzzing:
Versifier uncovered 15 new basic blocks (excluding counters) which accounts for 1.15% of all discovered basic blocks.

Research on automatic protocol reverse engineering:
- Sequitur (or Nevill-Manning algorithm) algorithm:
http://en.wikipedia.org/wiki/Sequitur_algorithm
- Discoverer: Automatic Protocol Reverse Engineering from Network Traces
http://research.microsoft.com/pubs/153196/discoverer-security07.pdf
- Reverse Engineering of Protocols from Network Traces
http://www.di.fc.ul.pt/~nuno/PAPERS/WCRE11.pdf
*/

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	// For PCG
	"math/bits"
	"sync/atomic"
	"time"
)

func buildVerse(data []byte) *verse {
	// Check if the data is something texty. If not, don't bother parsing it.
	// Versifier don't know how to recognize structure in binary data.
	// TODO: we could detect detect text and binary parts and handle them separately
	// (think of an HTTP request with compressed body).
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	if printable < len(data)*9/10 {
		return nil
	}

	newv := &verse{}
	n := tokenize(data)
	n = structure(n)
	b := &blockNode{n}
	newv.blocks = append(newv.blocks, b)
	b.visit(func(n verseNode) {
		newv.allNodes = append(newv.allNodes, n)
	})
	//newv.r = newPCG()
	return newv
}

type verseNode interface {
	visit(f func(verseNode))
	printN(w io.Writer, ident int)
	generate(w io.Writer, v *verse)
}

func makeDict(s []byte) map[string]struct{} {
	return map[string]struct{}{string(s): struct{}{}}
}

func fmtDict(dict map[string]struct{}) string {
	var list []string
	for s := range dict {
		list = append(list, fmt.Sprintf("%q", s))
	}
	return strings.Join(list, ",")
}

func randTerm(v *verse, dict map[string]struct{}) []byte {
	terms := make([]string, 0, len(dict))
	for k := range dict {
		terms = append(terms, k)
	}
	return []byte(terms[v.rand(len(terms))])
}

func singleTerm(dict map[string]struct{}) string {
	for k := range dict {
		return k
	}
	panic("bad")
}

type wsNode struct {
	dict map[string]struct{}
}

func (n *wsNode) visit(f func(n verseNode)) {
	f(n)
}

func (n *wsNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%sws{%s}\n", strings.Repeat("  ", ident), fmtDict(n.dict))
}

func (n *wsNode) generate(w io.Writer, v *verse) {
	if v.rand(5) != 0 {
		w.Write(randTerm(v, n.dict))
	} else {
	loop:
		for {
			switch v.rand(3) {
			case 0:
				break loop
			case 1:
				w.Write([]byte{' '})
			case 2:
				w.Write([]byte{'\t'})
			}
		}
	}
}

type alphaNumNode struct {
	dict map[string]struct{}
}

func (n *alphaNumNode) visit(f func(n verseNode)) {
	f(n)
}

func (n *alphaNumNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%salphanum{%s}\n", strings.Repeat("  ", ident), fmtDict(n.dict))
}

func (n *alphaNumNode) generate(w io.Writer, v *verse) {
	if v.rand(5) != 0 {
		w.Write(randTerm(v, n.dict))
	} else {
		len := 0
		switch v.rand(3) {
		case 0:
			len = v.rand(4)
		case 1:
			len = v.rand(20)
		case 2:
			len = v.rand(100)
		}
		res := make([]byte, len)
		for i := range res {
			switch v.rand(4) {
			case 0:
				res[i] = '_'
			case 1:
				res[i] = '0' + byte(v.rand(10))
			case 2:
				res[i] = 'a' + byte(v.rand(26))
			case 3:
				res[i] = 'A' + byte(v.rand(26))
			}
		}
		w.Write(res)
	}
}

type numNode struct {
	dict map[string]struct{}
	hex  bool
}

func (n *numNode) visit(f func(n verseNode)) {
	f(n)
}

func (n *numNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%snum{hex=%v, %s}\n", strings.Repeat("  ", ident), n.hex, fmtDict(n.dict))
}

func (n *numNode) generate(w io.Writer, v *verse) {
	if v.rand(2) == 0 {
		w.Write(randTerm(v, n.dict))
	} else {
		randNum := func() []byte {
			base := []int{8, 10, 16}[v.rand(3)]
			len := 0
			switch v.rand(3) {
			case 0:
				len = v.rand(4)
			case 1:
				len = v.rand(16)
			case 2:
				len = v.rand(40)
			}
			num := make([]byte, len+1)
			for i := range num {
				switch base {
				case 8:
					num[i] = '0' + byte(v.rand(8))
				case 10:
					num[i] = '0' + byte(v.rand(10))
				case 16:
					switch v.rand(3) {
					case 0:
						num[i] = '0' + byte(v.rand(10))
					case 1:
						num[i] = 'a' + byte(v.rand(6))
					case 2:
						num[i] = 'A' + byte(v.rand(6))
					}
				}
			}
			switch base {
			case 8:
				num = append([]byte{'0'}, num...)
			case 10:
			case 16:
				num = append([]byte{'0', 'x'}, num...)
			default:
				panic("bad")
			}
			if v.rand(2) == 0 {
				num = append([]byte{'-'}, num...)
			}
			return num
		}
		switch v.rand(3) {
		case 0:
			w.Write(randNum())
		case 1:
			w.Write(randNum())
			w.Write([]byte{'.'})
			w.Write(randNum())
		case 2:
			w.Write(randNum())
			w.Write([]byte{'e'})
			w.Write(randNum())
		}
	}
}

type controlNode struct {
	ch rune
}

func (n *controlNode) visit(f func(n verseNode)) {
	f(n)
}

func (n *controlNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%s%q\n", strings.Repeat("  ", ident), string(n.ch))
}

func (n *controlNode) generate(w io.Writer, v *verse) {
	if v.rand(10) != 0 {
		w.Write([]byte{byte(n.ch)})
	} else {
		for {
			b := byte(v.rand(128))
			if b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' {
				continue
			}
			w.Write([]byte{b})
			break
		}
	}
}

type bracketNode struct {
	open rune
	clos rune
	b    *blockNode
}

var brackets = map[rune]rune{
	'<':  '>',
	'[':  ']',
	'(':  ')',
	'{':  '}',
	'\'': '\'',
	'"':  '"',
	'`':  '`',
}

func (n *bracketNode) visit(f func(n verseNode)) {
	f(n)
	n.b.visit(f)
}

func (n *bracketNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%s%s\n", strings.Repeat("  ", ident), string(n.open))
	n.b.printN(w, ident+1)
	fmt.Fprintf(w, "%s%s\n", strings.Repeat("  ", ident), string(n.clos))
}

func (n *bracketNode) generate(w io.Writer, v *verse) {
	if v.rand(10) != 0 {
		w.Write([]byte{byte(n.open)})
		n.b.generate(w, v)
		w.Write([]byte{byte(n.clos)})
	} else {
		brk := []rune{'<', '[', '(', '{', '\'', '"', '`'}
		open := brk[v.rand(len(brk))]
		clos := brackets[open]
		if v.rand(5) == 0 {
			clos = brackets[brk[v.rand(len(brk))]]
		}
		w.Write([]byte{byte(open)})
		n.b.generate(w, v)
		w.Write([]byte{byte(clos)})
	}
}

type keyValNode struct {
	delim rune
	key   *alphaNumNode
	value *alphaNumNode
}

func (n *keyValNode) visit(f func(n verseNode)) {
	f(n)
	n.key.visit(f)
	n.value.visit(f)
}
func (n *keyValNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%skeyval\n", strings.Repeat("  ", ident))
	n.key.printN(w, ident+1)
	fmt.Fprintf(w, "%s%s\n", strings.Repeat("  ", ident+1), string(n.delim))
	n.value.printN(w, ident+1)
}

func (n *keyValNode) generate(w io.Writer, v *verse) {
	delim := []rune{'=', ':'}
	n.delim = delim[v.rand(len(delim))]
	n.key.generate(w, v)
	w.Write([]byte{byte(n.delim)})
	n.value.generate(w, v)
}

type listNode struct {
	delim  rune
	blocks []*blockNode
}

func (n *listNode) visit(f func(n verseNode)) {
	f(n)
	for _, b := range n.blocks {
		b.visit(f)
	}
}

func (n *listNode) printN(w io.Writer, ident int) {
	fmt.Fprintf(w, "%slist\n", strings.Repeat("  ", ident))
	for i, b := range n.blocks {
		if i != 0 {
			fmt.Fprintf(w, "%s%s\n", strings.Repeat("  ", ident), string(n.delim))
		}
		b.printN(w, ident+1)
	}
}

func (n *listNode) generate(w io.Writer, v *verse) {
	blocks := n.blocks
	if v.rand(5) == 0 {
		blocks = nil
		for v.rand(3) != 0 {
			blocks = append(blocks, n.blocks[v.rand(len(n.blocks))])
		}
	}
	for i, b := range blocks {
		if i != 0 {
			w.Write([]byte{byte(n.delim)})
		}
		b.generate(w, v)
	}
}

type lineNode struct {
	r bool
	b *blockNode
}

func (n *lineNode) visit(f func(n verseNode)) {
	f(n)
	n.b.visit(f)
}

func (n *lineNode) printN(w io.Writer, ident int) {
	rn := "\\n"
	if n.r {
		rn = "\\r\\n"
	}
	fmt.Fprintf(w, "%sline %s\n", strings.Repeat("  ", ident), rn)
	n.b.printN(w, ident+1)
}

func (n *lineNode) generate(w io.Writer, v *verse) {
	n.b.generate(w, v)
	if n.r {
		w.Write([]byte{'\r', '\n'})
	} else {
		w.Write([]byte{'\n'})
	}
}

type blockNode struct {
	nodes []verseNode
}

func (n *blockNode) visit(f func(n verseNode)) {
	f(n)
	for _, n := range n.nodes {
		n.visit(f)
	}
}

func (n *blockNode) printN(w io.Writer, ident int) {
	for _, n := range n.nodes {
		n.printN(w, ident)
	}
}

func (n *blockNode) generate(w io.Writer, v *verse) {
	nodes := append([]verseNode{}, n.nodes...)
	if v.rand(10) == 0 {
		for len(nodes) > 0 && v.rand(2) == 0 {
			idx := v.rand(len(nodes))
			copy(nodes[:idx], nodes[idx+1:])
			nodes = nodes[:len(nodes)-1]
		}
	}
	if v.rand(10) == 0 {
		for len(nodes) > 0 && v.rand(2) == 0 {
			idx := v.rand(len(nodes))
			nodes = append(nodes, nil)
			copy(nodes[idx+1:], nodes[idx:])
		}
	}
	if v.rand(10) == 0 {
		for len(nodes) > 0 && v.rand(2) == 0 {
			idx1 := v.rand(len(nodes))
			idx2 := v.rand(len(nodes))
			nodes[idx1], nodes[idx2] = nodes[idx2], nodes[idx1]
		}
	}
	for _, n := range nodes {
		if v.rand(20) == 0 {
			continue
		}
		if v.rand(20) == 0 {
			// TODO: replace subranges of nodes with other subranges of nodes.
			// That is, currently RandNode returns either a BlockNode or
			// an individual node within that BlockNode, but it ought to
			// be able to return a subrange of nodes within a BlockNode.
			n = v.randNode()
		}
		n.generate(w, v)
	}
}

type verse struct {
	blocks   []*blockNode
	allNodes []verseNode
	r        *pcgRand
}

func (v *verse) printN(w io.Writer) {
	for _, b := range v.blocks {
		b.printN(w, 0)
		fmt.Fprintf(w, "========\n")
	}
}

func (v *verse) rhyme() []byte {
	buf := &bytes.Buffer{}
	v.blocks[v.rand(len(v.blocks))].generate(buf, v)
	return buf.Bytes()
}

func (v *verse) rand(n int) int {
	return v.r.Intn(n)
}

func (v *verse) randNode() verseNode {
	return v.allNodes[v.rand(len(v.allNodes))]
}

func tokenize(data []byte) []verseNode {
	var res []verseNode
	const (
		stateControl = iota
		stateWs
		stateAlpha
		stateNum
	)
	state := stateControl
	start := 0
	for i := 0; i < len(data); {
		r, s := utf8.DecodeRune(data[i:])
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_':
			switch state {
			case stateControl:
				start = i
				state = stateAlpha
			case stateWs:
				res = append(res, &wsNode{makeDict(data[start:i])})
				start = i
				state = stateAlpha
			case stateAlpha:
			case stateNum:
				state = stateAlpha
			}

		case r >= '0' && r <= '9':
			switch state {
			case stateControl:
				start = i
				state = stateNum
			case stateWs:
				res = append(res, &wsNode{makeDict(data[start:i])})
				start = i
				state = stateNum
			case stateAlpha:
			case stateNum:
			}

		case r == ' ' || r == '\t':
			switch state {
			case stateControl:
				start = i
				state = stateWs
			case stateWs:
			case stateAlpha:
				res = append(res, &alphaNumNode{makeDict(data[start:i])})
				start = i
				state = stateWs
			case stateNum:
				res = append(res, &numNode{dict: makeDict(data[start:i])})
				start = i
				state = stateWs
			}

		default:
			switch state {
			case stateControl:
			case stateWs:
				res = append(res, &wsNode{makeDict(data[start:i])})
			case stateAlpha:
				res = append(res, &alphaNumNode{makeDict(data[start:i])})
			case stateNum:
				res = append(res, &numNode{dict: makeDict(data[start:i])})
			}
			state = stateControl
			res = append(res, &controlNode{r})
		}
		i += s
	}
	switch state {
	case stateAlpha:
		res = append(res, &alphaNumNode{map[string]struct{}{string(data[start:]): struct{}{}}})
	case stateNum:
		res = append(res, &numNode{dict: map[string]struct{}{string(data[start:]): struct{}{}}})
	}
	return res
}

func structure(nn []verseNode) []verseNode {
	nn = extractNumbers(nn)
	nn = structureBrackets(nn)
	nn = structureKeyValue(nn)
	nn = structureLists(nn)
	nn = structureLines(nn)
	return nn
}

func isHexNum(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return false
	}
	return true
}

func isDecNum(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func extractNumbers(nn []verseNode) []verseNode {
	// TODO: replace this mess with a real parser.
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(nn); i++ {
			n := nn[i]
			if num, ok := n.(*alphaNumNode); ok {
				v := singleTerm(num.dict)
				if len(v) >= 3 {
					if v[0] == '0' && v[1] == 'x' && isHexNum(v[2:]) {
						nn[i] = &numNode{hex: true, dict: num.dict}
						changed = true
						continue
					}
					if e := strings.IndexByte(v, 'e'); e != -1 {
						if isDecNum(v[:e]) && isDecNum(v[e+1:]) {
							nn[i] = &numNode{hex: false, dict: num.dict}
							changed = true
							continue
						}
						if e == len(v)-1 && i != len(nn)-1 {
							if num1, ok := nn[i+1].(*numNode); ok {
								nn[i+1] = &numNode{hex: false, dict: makeDict([]byte(v + singleTerm(num1.dict)))}
								copy(nn[i:], nn[i+1:])
								nn = nn[:len(nn)-1]
								changed = true
								continue
							}
						}
					}
				}
			}
			if minus, ok := n.(*controlNode); ok && minus.ch == '-' && i != len(nn)-1 {
				if num, ok := nn[i+1].(*numNode); ok {
					var prev verseNode
					if i != 0 {
						prev = nn[i-1]
					}
					// TODO: check that previous is not alphanum
					// e.g. ID-001, but allow 1e-1.
					if prev1, ok := prev.(*alphaNumNode); !ok || len(singleTerm(prev1.dict)) > 1 && singleTerm(prev1.dict)[len(singleTerm(prev1.dict))-1] == 'e' {
						num.dict = makeDict([]byte("-" + singleTerm(num.dict)))
						copy(nn[i:], nn[i+1:])
						nn = nn[:len(nn)-1]
						changed = true
						continue
					}
				}
			}
			if ctrl, ok := n.(*controlNode); ok && ctrl.ch == '.' && i != 0 && i != len(nn)-1 {
				num1, ok1 := nn[i-1].(*numNode)
				num2, ok2 := nn[i+1].(*numNode)
				if ok1 && ok2 {
					nn[i+1] = &numNode{hex: false, dict: makeDict([]byte(singleTerm(num1.dict) + "." + singleTerm(num2.dict)))}
					copy(nn[i-1:], nn[i+1:])
					nn = nn[:len(nn)-2]
					changed = true
					continue
				}
			}
		}
	}
	return nn
}

func structureKeyValue(nn []verseNode) (res []verseNode) {
	// TODO: extract numeric key-value pairs
	delims := map[rune]bool{'=': true, ':': true}
	for _, n := range nn {
		if brk, ok := n.(*bracketNode); ok {
			brk.b.nodes = structureKeyValue(brk.b.nodes)
		}
	}

	for i := 0; i < len(nn); i++ {
		n := nn[i]
		ctrl, ok := n.(*controlNode)
		if !ok {
			continue
		}
		if delims[ctrl.ch] &&
			!(i == 0 || i == len(nn)-1) {
			var key, value *alphaNumNode
			key, ok = nn[i-1].(*alphaNumNode)
			if !ok {
				continue
			}
			value, ok = nn[i+1].(*alphaNumNode)
			if !ok {
				continue
			}
			nn[i+1] = &keyValNode{ctrl.ch, key, value}
			copy(nn[i-1:], nn[i+1:])
			nn = nn[:len(nn)-2]
		}
	}
	return nn
}

func structureBrackets(nn []verseNode) []verseNode {
	type Brk struct {
		open rune
		clos rune
		pos  int
	}
	var stk []Brk
loop:
	for i := 0; i < len(nn); i++ {
		n := nn[i]
		ctrl, ok := n.(*controlNode)
		if !ok {
			continue
		}
		for si := len(stk) - 1; si >= 0; si-- {
			if ctrl.ch == stk[si].clos {
				b := &bracketNode{stk[si].open, stk[si].clos, &blockNode{append([]verseNode{}, nn[stk[si].pos+1:i]...)}}
				nn[stk[si].pos] = b
				copy(nn[stk[si].pos+1:], nn[i+1:])
				nn = nn[:len(nn)-i+stk[si].pos]
				i = stk[si].pos
				stk = stk[:si]
				continue loop
			}
		}
		if clos, ok := brackets[ctrl.ch]; ok {
			stk = append(stk, Brk{ctrl.ch, clos, i})
		}
	}
	return nn
}

func structureLists(nn []verseNode) (res []verseNode) {
	delims := map[rune]bool{',': true, ';': true}
	for _, n := range nn {
		if brk, ok := n.(*bracketNode); ok {
			brk.b.nodes = structureLists(brk.b.nodes)
		}
	}
	// TODO: fails on:
	//	"f1": "v1", "f2": "v2", "f3": "v3"
	// the first detected list is "v2", "f3"
	for i := len(nn) - 1; i >= 0; i-- {
		n := nn[i]
		if ctrl, ok := n.(*controlNode); ok && delims[ctrl.ch] {
			type Elem struct {
				tok  map[rune]bool
				done bool
				pos  int
				inc  int
			}
			elems := [2]*Elem{
				{make(map[rune]bool), false, i - 1, -1},
				{make(map[rune]bool), false, i + 1, +1},
			}
			for {
				for _, e := range elems {
					if e.done || e.pos < 0 || e.pos >= len(nn) {
						e.done = true
						continue
					}
					if ctrl1, ok := nn[e.pos].(*controlNode); ok {
						if ctrl1.ch == ctrl.ch {
							e.done = true
							continue
						}
						e.tok[ctrl1.ch] = true
					}
					if brk1, ok := nn[e.pos].(*bracketNode); ok {
						e.tok[brk1.open] = true
						e.tok[brk1.clos] = true
					}
					e.pos += e.inc
				}
				if elems[0].done && elems[1].done {
					break
				}
				union := make(map[rune]bool)
				for k := range elems[0].tok {
					union[k] = true
				}
				for k := range elems[1].tok {
					union[k] = true
				}
				if reflect.DeepEqual(elems[0].tok, union) || reflect.DeepEqual(elems[1].tok, union) {
					break
				}
			}

			for k := range elems[1].tok {
				elems[0].tok[k] = true
			}

		elemLoop:
			for _, e := range elems {
				for ; e.pos >= 0 && e.pos < len(nn); e.pos += e.inc {
					if ctrl1, ok := nn[e.pos].(*controlNode); ok && !elems[0].tok[ctrl1.ch] {
						continue elemLoop
					}
					if brk1, ok := nn[e.pos].(*bracketNode); ok && !(elems[0].tok[brk1.open] && elems[0].tok[brk1.clos]) {
						continue elemLoop
					}
				}
			}

			for _, e := range elems {
				for {
					if e.done || e.pos < 0 || e.pos >= len(nn) {
						break
					}
					if ctrl1, ok := nn[e.pos].(*controlNode); ok {
						if ctrl1.ch == ctrl.ch {
							break
						}
						if !elems[0].tok[ctrl1.ch] {
							break
						}
					}
					if brk1, ok := nn[e.pos].(*bracketNode); ok {
						if !elems[0].tok[brk1.open] || !elems[0].tok[brk1.clos] {
							break
						}
					}
					e.pos += e.inc
				}
			}
			lst := &listNode{ctrl.ch, []*blockNode{
				{append([]verseNode{}, nn[elems[0].pos+1:i]...)},
				{append([]verseNode{}, nn[i+1:elems[1].pos]...)},
			}}
			start := elems[0].pos
			end := elems[1].pos
			for {
				if start < 0 {
					break
				}
				if ctrl1, ok := nn[start].(*controlNode); !ok || ctrl1.ch != ctrl.ch {
					break
				}
				pos := start - 1
				for {
					if pos < 0 {
						break
					}
					if ctrl1, ok := nn[pos].(*controlNode); ok {
						if ctrl1.ch == ctrl.ch {
							break
						}
						if !elems[0].tok[ctrl1.ch] {
							break
						}
					}
					if brk1, ok := nn[pos].(*bracketNode); ok {
						if !elems[0].tok[brk1.open] || !elems[0].tok[brk1.clos] {
							break
						}
					}
					pos--
				}
				lst.blocks = append([]*blockNode{{append([]verseNode{}, nn[pos+1:start]...)}}, lst.blocks...)
				start = pos
			}
			nn[start+1] = lst
			copy(nn[start+2:], nn[end:])
			nn = nn[:len(nn)-end+start+2]
			i = start + 1
		}
	}
	return nn
}

type nodeSet struct {
	ctrl map[rune]bool
	brk  map[rune]bool
}

func structureLines(nn []verseNode) (res []verseNode) {
	for i := 0; i < len(nn); i++ {
		n := nn[i]
		if brk, ok := n.(*bracketNode); ok {
			brk.b.nodes = structureLines(brk.b.nodes)
			continue
		}
		if ctrl, ok := n.(*controlNode); !ok || ctrl.ch != '\n' {
			continue
		}
		r := false
		end := i
		if i != 0 {
			if prev, ok := nn[i-1].(*controlNode); ok && prev.ch == '\r' {
				r = true
				end--
			}
		}
		res = append(res, &lineNode{r, &blockNode{nn[:end]}})
		nn = nn[i+1:]
		i = -1
	}
	if len(nn) != 0 {
		res = append(res, nn...)
	}
	return res
}

// *****************************************************************************
// ********************************** PCG **************************************

var globalInc uint64 // PCG stream

const multiplier uint64 = 6364136223846793005

// pcgRand is a PRNG.
// It should not be copied or shared. No pcgRand methods are concurrency safe.
// They are small, and cheap to create. If in doubt: Just make another one.
type pcgRand struct {
	noCopy noCopy // help avoid mistakes: ask vet to ensure that we don't make a copy
	state  uint64
	inc    uint64
}

// newPCG generates a new, seeded Rand, ready for use.
func newPCG() *pcgRand {
	r := new(pcgRand)
	now := uint64(time.Now().UnixNano())
	inc := atomic.AddUint64(&globalInc, 1)
	r.state = now
	r.inc = (inc << 1) | 1
	r.step()
	r.state += now
	r.step()
	return r
}

func (r *pcgRand) step() {
	r.state *= multiplier
	r.state += r.inc
}

// Uint32 returns a pseudo-random uint32.
func (r *pcgRand) Uint32() uint32 {
	x := r.state
	r.step()
	return bits.RotateLeft32(uint32(((x>>18)^x)>>27), -int(x>>59))
}

// Intn returns a pseudo-random number in [0, n).
// n must fit in a uint32.
func (r *pcgRand) Intn(n int) int {
	if int(uint32(n)) != n {
		panic("large Intn")
	}
	return int(r.Uint32n(uint32(n)))
}

// Uint32n returns a pseudo-random number in [0, n).
//
// For implementation details, see:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
// https://lemire.me/blog/2016/06/30/fast-random-shuffling
func (r *pcgRand) Uint32n(n uint32) uint32 {
	v := r.Uint32()
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < n {
		thresh := uint32(-int32(n)) % n
		for low < thresh {
			v = r.Uint32()
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return uint32(prod >> 32)
}

// Exp2 generates n with probability 1/2^(n+1).
func (r *pcgRand) Exp2() int {
	return bits.TrailingZeros32(r.Uint32())
}

// Bool generates a random bool.
func (r *pcgRand) Bool() bool {
	return r.Uint32()&1 == 0
}

// noCopy may be embedded into structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
