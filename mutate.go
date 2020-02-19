package main

import (
	"fmt"
	"log"

	"encoding/binary"
	"math"
	"math/rand"

	// For debug
	"sync"
	"time"
)

// **************************************
// ********* Consts and Init ************

var minMaxs = [...][2]int{[2]int{1, blkSmall}, [2]int{blkSmall, blkMedium},
	[2]int{blkMedium, blkLarge}, [2]int{blkLarge, blkXL}}

const (
	arithMax  = 35
	blkSmall  = 32
	blkMedium = 128
	blkLarge  = 1500
	blkXL     = 32768
)

// *****************************************************************************
// ************************* Mutation Interface ********************************

const (
	scStr  = "stackSizeChoice"
	bcStr  = "byteChoice"
	bocStr = "byteOrderChoice"
)

// Limitation of the decisionSpec as a slice is that cannot vary in function of
// decision that are taken :( .
type mutationFunc interface {
	name() string
	getMutContract(tcLen int) (contract mutationContract)
	// Each decision should respect the contract spec, with regard to the order.
	mutate(decisions []int, testCase []byte) []byte
}

type mutationContract struct {
	ok        bool
	changeLen func(decisions []int, tcLen int) (newTcLen int)
	specs     []decisionSpec
}
type decisionSpec struct {
	decisionType string
	min, max     int // Interval of for valid decision. Min included, max excluded.

	// In case there is a dependency between previous decisions and this one
	dependency func(rSrc *rand.Rand, prevDecisions []int) int
}

// *****************************************************************************
// ************************* Main Mutator Object *******************************

type mutator struct {
	funcs   []mutationFunc // Mutating functions
	rSrc    *rand.Rand     // Random source
	seedLen int

	// Prelude computation
	okFuncs   []mutationFunc
	contracts []mutationContract

	// Mu paramenter of log-normal distribution for chosing number of mutation
	// stacked. Variance constant: sigma=1.
	stackMu float64

	// For debug
	preludeT *time.Duration
	decT     *time.Duration
	mutT     *time.Duration
}

func makeBasicMutator(rSrc *rand.Rand, dictWords [][]byte,
	seedMutMan seedMutationManager, stackMu float64, seedLen int) (m mutator) {

	m.funcs = []mutationFunc{
		flipper{},
		randByter{},
		intByteSetter{-128, -1, 0, 1, 16, 32, 64, 100, 127},
		intWordSetter{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4093, 32767},
		intDWordSetter{-2147483648, -100663046, -32769, 32768, 65535, 65536,
			100663045, 2147483647},

		// Use add (true) or substraction (false) operation;
		// and which level: byte, word, double word.
		makeArithMut(true, 0),
		makeArithMut(false, 0),
		makeArithMut(true, 1),
		makeArithMut(false, 1),
		makeArithMut(true, 2),
		makeArithMut(false, 2),

		overwriter(true),
		overwriter(false),
		inserter(true),
		inserter(false),
		deleter{},
	}

	if len(dictWords) > 0 {
		m.funcs = append(m.funcs,
			dictWordIns(dictWords), makeDictWordOverwiter(dictWords))
	}

	m.stackMu = stackMu
	if math.IsNaN(stackMu) {
		m.stackMu = 1
	}

	m.rSrc = rSrc
	m.seedLen = seedLen

	m.okFuncs, m.contracts = m.getAllContracts(seedLen)

	m.preludeT, m.decT, m.mutT = new(time.Duration), new(time.Duration), new(time.Duration)

	return m
}

func (m mutator) mutate(seedInput []byte) (testCase []byte, rep []decisionReport) {
	// *** I - Prepare the mutation ***
	step1 := time.Now() // @TODO: remove
	testCase = seedInput
	tcLen := len(testCase)

	okFuncs, contracts := m.okFuncs, m.contracts

	type mutDec struct {
		mf        mutationFunc
		decisions []int
	}
	stackNb := 1
	if useStacking {
		normR := m.rSrc.NormFloat64()*stackSizeSig + m.stackMu
		stackNb = 1 + int(math.Exp(normR))
	} else {
		stackNb = 1 << uint(m.rSrc.Intn(5))
	}
	if stackNb <= 0 || stackNb > 1e3 { // Put a cap. (Negative=overflow).
		stackNb = 1e3
	}
	stackedDecisions := make([]mutDec, stackNb)
	rep = make([]decisionReport, 0, 3*stackNb)
	rep = append(rep, decisionReport{decisionType: scStr, decision: stackNb})
	// For debug
	tcLens := make([]int, stackNb)

	// *** II - Take mutation decision ***
	step2 := time.Now()
	for i := range stackedDecisions {
		// 1. Chosing the mutation operator
		funcIndex := m.rSrc.Intn(len(okFuncs))
		mf := okFuncs[funcIndex]
		specs := contracts[funcIndex].specs

		// 2. Make mutation decisions
		decisions := make([]int, len(specs))
		for i, spec := range specs {
			var dec int
			if spec.dependency != nil {
				dec = spec.dependency(m.rSrc, decisions)

			} else {
				interval := spec.max - spec.min
				dec = spec.min
				if interval > 1 {
					dec += m.rSrc.Intn(interval)
				}
			}

			decisions[i] = dec
			rep = append(rep,
				decisionReport{decisionType: spec.decisionType, decision: dec})
		}

		stackedDecisions[i].mf = mf
		stackedDecisions[i].decisions = decisions

		if contracts[funcIndex].changeLen != nil {
			// If the test case changed, need to update all contracts (decisions
			// to take change).
			tcLen = contracts[funcIndex].changeLen(decisions, tcLen)
			okFuncs, contracts = m.getAllContracts(tcLen)
		}
		tcLens[i] = tcLen
	}

	// *** III - Now for the mutation: i.e. "acting" of decisions ****
	step3 := time.Now()
	for i, dec := range stackedDecisions {
		testCase = dec.mf.mutate(dec.decisions, testCase)
		if len(testCase) != tcLens[i] {
			str := fmt.Sprintf("Non foreseen test case length: (real) %d v. %d",
				len(testCase), tcLens[i])
			panic(str)
		}
	}

	end := time.Now()
	*m.preludeT += step2.Sub(step1)
	*m.decT += step3.Sub(step2)
	*m.mutT += end.Sub(step3)

	return testCase, rep
}

// okFuncs: mutation functions that are possible to execute for seed of this
// length.
// allSpecs: contracts corresponding to the function above.
func (m mutator) getAllContracts(tcLen int) (
	okFuncs []mutationFunc, allSpecs []mutationContract) {

	for _, f := range m.funcs {
		contract := f.getMutContract(tcLen)
		if !contract.ok {
			continue
		}
		okFuncs = append(okFuncs, f)
		allSpecs = append(allSpecs, contract)
	}
	return okFuncs, allSpecs
}

type step1MutTRep struct {
	t    time.Duration
	hash uint64
}

const useStep1bench = false

var step1MutTChan = make(chan step1MutTRep)
var step1MutWG sync.WaitGroup

func init() {
	if !useStep1bench {
		return
	}

	step1MutWG.Add(1)
	go func() {
		step1Ts := make(map[uint64][]time.Duration)
		for rep := range step1MutTChan {
			if list, ok := step1Ts[rep.hash]; ok {
				step1Ts[rep.hash] = append(list, rep.t)
			} else {
				step1Ts[rep.hash] = []time.Duration{rep.t}
			}
			fmt.Printf("Step1Ts: %v.\n", step1Ts[rep.hash])
		}

		fmt.Printf("\nPrinting step1s:\n")
		for _, list := range step1Ts {
			if len(list) > 1 {
				fmt.Printf("%v\n", list)
			}
		}
		fmt.Println("")
		step1MutWG.Done()
	}()
}

// *****************************************************************************
// **************************** Implementations ********************************

// Repeat simple mutation functions to amortize the cost of their function call.
const simpleRepeat = 10

// **** Bit Flipper ****
type flipper struct{}

func (f flipper) name() string { return "Flip" }
func (f flipper) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen == 0 {
		return // Not ok.
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, tcLen, nil},
		decisionSpec{"bitChoice", 0, 8, nil},
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}
	return contract
}
func (f flipper) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		chosenByte := dec0
		chosenBit := uint64(dec1)
		testCase[chosenByte] ^= 128 >> chosenBit
	}
	return testCase
}

// *************************
// **** Set Interesting ****

// **** Set Interesting Byte ****
type intByteSetter []int

func (ibs intByteSetter) name() string { return "SetBI" }
func (ibs intByteSetter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen == 0 {
		return
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, tcLen, nil},
		decisionSpec{"intByteChoice", 0, len(ibs), nil},
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}

	return contract
}
func (ibs intByteSetter) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		byteToSet := dec0
		testCase[byteToSet] = byte(ibs[dec1])
	}
	return testCase
}

// **** Set Interesting Word ****
type intWordSetter []int

func (iws intWordSetter) name() string { return "SetWI" }
func (iws intWordSetter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < 2 {
		return
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, tcLen - 1, nil},
		decisionSpec{"intWordChoice", 0, len(iws), nil},
		decisionSpec{bocStr, 0, 2, nil},
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}
	return contract
}
func (iws intWordSetter) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		wordToSet := decisions[3*i]
		intWord := iws[decisions[3*i+1]]
		byte0 := byte(intWord)
		byte1 := byte(intWord >> 8)

		if decisions[3*i+2] == 0 { // Big Endian
			testCase[wordToSet] = byte0
			testCase[wordToSet+1] = byte1

		} else { // Little Endian
			testCase[wordToSet] = byte1
			testCase[wordToSet+1] = byte0
		}
	}

	return testCase
}

// **** Set Interesting Double Word ****
type intDWordSetter []int

func (idws intDWordSetter) name() string { return "SetDWI" }
func (idws intDWordSetter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < 4 {
		return
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, tcLen - 3, nil},
		decisionSpec{"intDWordChoice", 0, len(idws), nil},
		decisionSpec{bocStr, 0, 2, nil},
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}
	return contract
}
func (idws intDWordSetter) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dWordToSet := decisions[3*i]
		intWord := idws[decisions[3*i+1]]
		byte0 := byte(intWord)
		byte1 := byte(intWord >> 8)
		byte2 := byte(intWord >> 16)
		byte3 := byte(intWord >> 24)

		if decisions[3*i+2] == 0 { // Big Endian
			testCase[dWordToSet] = byte0
			testCase[dWordToSet+1] = byte1
			testCase[dWordToSet+2] = byte2
			testCase[dWordToSet+3] = byte3

		} else { // Little Endian
			testCase[dWordToSet] = byte3
			testCase[dWordToSet+1] = byte2
			testCase[dWordToSet+2] = byte1
			testCase[dWordToSet+3] = byte0
		}
	}

	return testCase
}

// ************************************
// **** Basic Arithmetic Operators ****
// Addition and Subtractions.
// At the byte, word and double word levels.
//
// Put them in common so we have a single interface and it's easier to
// modify/maintain.

type arithMut struct {
	add      bool // If false, then sub
	level    int  // 0=byte, 1=word, 2=dword
	arithMax int  // Constant from AFL ATM, but could be learned...

	// Six operators: one for all (add, level) combinaisons.
	// Should be faster than one function that does all but with many if/else-s.
	operator func([]int, []byte) []byte
}

var amLvlNames = [...]string{"B", "W", "DW"}

func makeArithMut(add bool, level int) (am arithMut) {
	if level > 2 {
		log.Printf("%d is an invalid level for the arithmetic mutator.\n", level)
		return
	}

	am.add = add
	am.level = level
	am.arithMax = 35

	if level == 0 && add {
		am.operator = addByteAM
	} else if level == 0 && !add {
		am.operator = subByteAM
	} else if level == 1 && add {
		am.operator = addWordAM
	} else if level == 1 && !add {
		am.operator = subWordAM
	} else if level == 2 && add {
		am.operator = addDWordAM
	} else if level == 2 && !add {
		am.operator = subDWordAM
	}

	return am
}

func (am arithMut) name() (str string) {
	if am.add {
		str = "Add"
	} else {
		str = "Sub"
	}
	str += amLvlNames[am.level]
	return str
}

func (am arithMut) getMutContract(tcLen int) (contract mutationContract) {
	max := tcLen
	if am.level == 1 {
		max--
	} else if am.level == 2 {
		max -= 3
	}

	if max < 1 {
		return
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, max, nil},
		decisionSpec{"arithVal", 1, am.arithMax + 1, nil},
	}
	if am.level > 0 {
		model = append(model, decisionSpec{bocStr, 0, 2, nil})
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}
	return contract
}

func (am arithMut) mutate(decisions []int, testCase []byte) []byte {
	// See maker to know which function it is :P
	return am.operator(decisions, testCase)
}
func addByteAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		byteToSet := dec0
		testCase[byteToSet] += byte(dec1)
	}
	return testCase
}
func subByteAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		byteToSet := dec0
		testCase[byteToSet] -= byte(dec1)
	}
	return testCase
}
func addWordAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		subSlice := testCase[decisions[3*i] : decisions[3*i]+2]
		val := uint16(decisions[3*i+1])
		byteOrder := getByteOrder(decisions[3*i+2])

		word := byteOrder.Uint16(subSlice)
		word += val
		byteOrder.PutUint16(subSlice, word)
	}
	return testCase
}
func subWordAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		subSlice := testCase[decisions[3*i] : decisions[3*i]+2]
		val := uint16(decisions[3*i+1])
		byteOrder := getByteOrder(decisions[3*i+2])

		word := byteOrder.Uint16(subSlice)
		word -= val
		byteOrder.PutUint16(subSlice, word)
	}
	return testCase
}
func addDWordAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		subSlice := testCase[decisions[3*i] : decisions[3*i]+4]
		val := uint32(decisions[3*i+1])
		byteOrder := getByteOrder(decisions[3*i+2])

		dword := byteOrder.Uint32(subSlice)
		dword += val
		byteOrder.PutUint32(subSlice, dword)
	}
	return testCase
}
func subDWordAM(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		subSlice := testCase[decisions[3*i] : decisions[3*i]+4]
		val := uint32(decisions[3*i+1])
		byteOrder := getByteOrder(decisions[3*i+2])

		dword := byteOrder.Uint32(subSlice)
		dword -= val
		byteOrder.PutUint32(subSlice, dword)
	}
	return testCase
}

func getByteOrder(dec int) binary.ByteOrder {
	if dec == 0 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// *************************
// **** Set Random Byte ****
type randByter struct{}

func (rb randByter) name() string { return "RandB" }
func (rb randByter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < 1 {
		return
	}

	contract.ok = true
	model := []decisionSpec{
		decisionSpec{bcStr, 0, tcLen, nil},
		decisionSpec{"randByte", 1, 255, nil},
	}
	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}

	return contract
}
func (rb randByter) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		testCase[dec0] ^= byte(dec1)
	}
	return testCase
}

// ********************************
// **** Common Block Decisions ****
// This decisions has to be taken by all/most block mutators (insert, delete and
// overwrite).

// ** Chose Block Length **
func makeChoseBlkSpec(maxLen int, firstDecIndex int) []decisionSpec {
	specs := make([]decisionSpec, 2)
	specs[0] = decisionSpec{"choseBlockLen1", 0, 33, nil}
	specs[1].decisionType = "choseBlockLen2"

	specs[1].dependency = func(rSrc *rand.Rand, decisions []int) (blkLen int) {
		minMax := minMaxs[decisions[firstDecIndex]/10]

		var min, max int
		if minMax[0] >= maxLen {
			min = 1
		} else {
			min = minMax[0]
		}
		if minMax[1] > maxLen {
			max = maxLen
		} else {
			max = minMax[1]
		}

		if max-min+1 < 1 {
			return min
		}
		blkLen = min + rSrc.Intn(max-min+1)

		return blkLen
	}

	return specs
}

// ** Chose a Constant **
func makeChoseCst(tcLen int) []decisionSpec {
	return []decisionSpec{
		decisionSpec{"getCstHow", 0, 2, nil},
		decisionSpec{"getCstTC", 0, tcLen, nil},
		decisionSpec{"getCstRand", 0, 0x100, nil},
	}
}
func getCst(testCase []byte, decisions []int) byte {
	if decisions[0] == 0 && len(testCase) != 0 {
		return testCase[decisions[1]]
	}
	return byte(decisions[2])
}

// **** Overwrite block ****
// Overwrite with a constant.
// Otherwise (if false), overwrite with another chunk of the input.
type overwriter bool

func (ow overwriter) name() (str string) {
	str = "Ow"
	if ow {
		str += "Cst"
	} else {
		str += "Chk"
	}
	return str
}

// Specification layout:
// 0-1: Block length choice.
// 2-3: Copy from/to.
// 4-6: Constant choice.
func (ow overwriter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < 2 {
		return
	}

	contract.ok = true

	// 1. Chose how much to overwrite
	contract.specs = makeChoseBlkSpec(tcLen-1, 0)

	// 2. Chose where to copy from and to. This depends on value from step 1.
	choseCpyLoc := func(rSrc *rand.Rand, decisions []int) int {
		return rSrc.Intn(tcLen - decisions[1])
	}
	// From:
	contract.specs = append(contract.specs, decisionSpec{
		decisionType: "owCopyFrom", dependency: choseCpyLoc})
	// To:
	contract.specs = append(contract.specs, decisionSpec{
		decisionType: "owCopyTo", dependency: choseCpyLoc})

	// If overwriting with a constant:
	// (Still do it in all cases in case two previous decisions (where to copy
	// from and to) are the same.
	// 3. Chose to overwrite with a constant from the input or just a any cst.
	contract.specs = append(contract.specs, makeChoseCst(tcLen)...)

	return contract
}

func (ow overwriter) mutate(decisions []int, testCase []byte) []byte {
	blkLen, copyFrom, copyTo := decisions[1], decisions[2], decisions[3]

	if !ow && copyFrom != copyTo { // Overwrite with another chunk
		for i := 0; i < blkLen; i++ {
			testCase[copyTo+i] = testCase[copyFrom+i]
		}

	} else {
		cstVal := getCst(testCase, decisions[4:])
		for i := 0; i < blkLen; i++ {
			testCase[copyTo+i] = cstVal
		}
	}

	return testCase
}

// **********************
// **** Insert Block ****
// If true clone from another part of the test case.
// Otherwise, pick a constant a make the block out of it.
type inserter bool

func (i inserter) name() (str string) {
	str = "Ins"
	if i {
		str += "Cl"
	} else {
		str += "Cst"
	}
	return str
}

// Layout:
// 0: Where is the inserted block going to be.
//
// If insert a constant:
// 1-2: block lenght choice.
// 3-5: constant value choice.
//
// If clone a block from the test case:
// 1-2: block length choice (slightly differ from above).
// 3: Where to copy from.
func (i inserter) getMutContract(tcLen int) (contract mutationContract) {
	contract.ok = true
	contract.changeLen = func(decisions []int, tcLen int) int {
		return tcLen + decisions[2]
	}

	contract.specs = append(contract.specs, decisionSpec{"insertTo", 0, tcLen, nil})

	insCst := !i || tcLen == 0
	if insCst {
		contract.specs = append(contract.specs,
			makeChoseBlkSpec(blkXL, len(contract.specs))...)
		contract.specs = append(contract.specs, makeChoseCst(tcLen)...)

	} else {
		contract.specs = append(contract.specs,
			makeChoseBlkSpec(tcLen, len(contract.specs))...)
		contract.specs = append(contract.specs, decisionSpec{
			decisionType: "insertFrom",
			dependency: func(rSrc *rand.Rand, decisions []int) int {
				blockLen := decisions[2]
				if blockLen == tcLen {
					return 0
				}
				return rSrc.Intn(tcLen - blockLen)
			},
		})
	}

	return contract
}

func (i inserter) mutate(decisions []int, testCase []byte) []byte {
	insCst := !i || len(testCase) == 0
	insTo := decisions[0]
	blockLen := decisions[2]

	tcLen := len(testCase)
	testCase = append(testCase, make([]byte, blockLen)...)
	// Shift right to make place for insertion
	for i := len(testCase) - 1; i >= insTo+blockLen; i-- {
		testCase[i] = testCase[i-blockLen]
	}

	if insCst {
		cstVal := getCst(testCase, decisions[3:])
		for i := insTo; i < insTo+blockLen; i++ {
			testCase[i] = cstVal
		}

	} else {
		copyFrom := decisions[3]
		if copyFrom > insTo {
			copyFrom += blockLen
		}
		for i := 0; i < blockLen; i++ {
			if copyFrom+i == insTo {
				copyFrom += blockLen
			} else if copyFrom+i >= len(testCase) {
				log.Fatalf("org tcLen: %d, tcLen: %d, copyFrom: %d, copyFrom+i: %d"+
					", insTo: %d, blockLen: %d\n",
					tcLen, len(testCase), decisions[3], copyFrom+i, insTo, blockLen)
			}
			testCase[insTo+i] = testCase[copyFrom+i]
		}
	}

	return testCase
}

// ***********************
// **** Block Deleter ****
type deleter struct{}

func (deleter) name() string { return "DelBlk" }

// Layout:
// 0-1: length of block to delete.
// 2: where to delete from.
func (deleter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < 2 {
		return
	}

	contract.ok = true
	contract.changeLen = func(decisions []int, tcLen int) int {
		return tcLen - decisions[1]
	}

	contract.specs = makeChoseBlkSpec(tcLen-1, 0)
	contract.specs = append(contract.specs, decisionSpec{
		decisionType: "deleteFrom",
		dependency: func(rSrc *rand.Rand, decisions []int) int {
			blockLen := decisions[1]
			if tcLen == blockLen {
				return 0
			}
			return rSrc.Intn(tcLen - blockLen)
		},
	})

	return contract
}

func (deleter) mutate(decisions []int, testCase []byte) []byte {
	blockLen, delFrom := decisions[1], decisions[2]
	for i := delFrom + blockLen; i < len(testCase); i++ {
		testCase[i-blockLen] = testCase[i]
	}
	testCase = testCase[:len(testCase)-blockLen]
	return testCase
}

// ******************************************
// ******* Dictionnary-based Function *******

type dictWordIns [][]byte

func (dictWordIns) name() string { return "DctIns" }

func (dwi dictWordIns) getMutContract(tcLen int) (contract mutationContract) {
	contract.ok = true
	contract.changeLen = func(decisions []int, tcLen int) int {
		return tcLen + len(dwi[decisions[0]])
	}

	contract.specs = append(contract.specs, decisionSpec{
		"dictWChoice", 0, len(dwi), nil})
	contract.specs = append(contract.specs, decisionSpec{
		"insDictWTo", 0, tcLen, nil})

	return contract
}

func (dwi dictWordIns) mutate(decisions []int, testCase []byte) []byte {
	word := dwi[decisions[0]]
	insTo := decisions[1]

	testCase = append(testCase, make([]byte, len(word))...)
	for i := len(testCase) - 1; i >= insTo+len(word); i-- {
		testCase[i] = testCase[i-len(word)]
	}

	for i, v := range word {
		testCase[insTo+i] = v
	}

	return testCase
}

// *************

type dictWordOverwriter struct {
	dictWords  [][]byte
	maxWordLen int
}

func makeDictWordOverwiter(dictWords [][]byte) (dwo dictWordOverwriter) {
	dwo.dictWords = dictWords
	for _, w := range dictWords {
		if len(w) > dwo.maxWordLen {
			dwo.maxWordLen = len(w)
		}
	}
	return dwo
}

func (dictWordOverwriter) name() string { return "DctOw" }

func (dwo dictWordOverwriter) getMutContract(tcLen int) (contract mutationContract) {
	if tcLen < dwo.maxWordLen {
		return
	}
	contract.ok = true

	model := []decisionSpec{
		decisionSpec{"dictWChoice", 0, len(dwo.dictWords), nil},

		// Here we may missing some possibilities depending on the longest word.
		// Assuming all words are of more or less the same lenght.  Otherwise
		// would need function for it... which is possible but preferable to
		// avoid when possible.
		decisionSpec{"writeDictWTo", 0, tcLen - dwo.maxWordLen, nil},
	}

	for range make([]struct{}, simpleRepeat) {
		contract.specs = append(contract.specs, model...)
	}

	return contract
}

func (dwo dictWordOverwriter) mutate(decisions []int, testCase []byte) []byte {
	for i := range make([]struct{}, simpleRepeat) {
		dec0, dec1 := decisions[2*i], decisions[2*i+1]
		word := dwo.dictWords[dec0]
		writeTo := dec1
		for j, v := range word {
			testCase[writeTo+j] = v
		}
	}
	return testCase
}
