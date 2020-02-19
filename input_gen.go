package main

import (
	"fmt"
	"log"

	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	versiHash   uint64 = 0xa641cf0bffbf6477
	crosserHash uint64 = 0x5b0b4a3bc6a19b88
)

var (
	_ inputGen = new(mutateGen)
	_ versiGen = versiGen{v: new(verse)}
)

type inputGen interface {
	generate() ([]byte, []decisionReport)
	// Printing stuff at the end of each round: debug...
	epilogue(execs uint, hash uint64)
}

// *****************************************************************************
// ********************** Mutation-based Input Generator ***********************

type mutateGen struct {
	m           mutator
	getSeedCopy func() ([]byte, int)

	// For update
	getSeedLen func() int
	seedLen    int
	seedMutMan seedMutationManager
	dictWords  [][]byte

	hash uint64 //debug
}

func (roundArgs *rndArgs) makeMutateGen(seedMutMan seedMutationManager) *mutateGen {
	seedPt := roundArgs.seedPt
	m := makeBasicMutator(
		roundArgs.put.rSrc,
		roundArgs.put.dictWords,
		seedMutMan,
		roundArgs.stackMu,
		len(seedPt.input),
	)

	return &mutateGen{
		m:           m,
		getSeedCopy: seedPt.getInputCopy,
		//
		getSeedLen: func() int { return len(seedPt.input) },
		seedLen:    len(seedPt.input),
		seedMutMan: seedMutMan,
		dictWords:  roundArgs.put.dictWords,
		hash:       seedPt.hash,
	}
}

func (mg *mutateGen) generate() ([]byte, []decisionReport) {
	seedCopy, l := mg.getSeedCopy()
	if l != mg.seedLen {
		newLen := l
		mg.seedLen = newLen
		mg.m = makeBasicMutator(
			mg.m.rSrc,
			mg.dictWords,
			mg.seedMutMan,
			mg.m.stackMu,
			newLen,
		)
	}

	testCase, mutRep := mg.m.mutate(seedCopy)
	return testCase, mutRep
}

func (mg *mutateGen) epilogue(execs uint, hash uint64) {}

// *****************************************************************************
// ********************* Versifier-based Input Generator ***********************

type versiGen struct {
	v *verse
}

func makeVersiGen(v *verse) versiGen {
	// Make a new versifier instance with another random source (for concurency).
	return versiGen{v: &verse{
		blocks:   v.blocks,
		allNodes: v.allNodes,
		r:        newPCG(),
	}}
}

func (vg versiGen) generate() ([]byte, []decisionReport) {
	return vg.v.rhyme(), []decisionReport{}
}
func (versiGen) epilogue(uint, uint64) {}

// *****************************************************************************
// *****************************************************************************
// ************************ Crossover Input Generator **************************
// AFL calls it splicing.
// Unlike the other input generators, this generator is implemented here.

const minCrossGenInputN = 10

type crossGen struct {
	mtx    sync.RWMutex
	inputs map[uint64]crossGenIn

	// Radamsa
	inCnt    int // Counter to name inputs
	radamMan *radamManager
}
type crossGenIn struct {
	input []byte
	name  string
}

func newCrossGen() *crossGen {
	var dirPath string
	var radamMan *radamManager
	if isRadamsa && unicore {
		// @TODO: clean this directory at the end of the campaign.
		dirPath = filepath.Join("/tmp", fmt.Sprintf("tmp-radam-%x", rand.Uint64()))
		err := os.Mkdir(dirPath, 0755)
		if err != nil {
			log.Printf("Couldn't setup Radamsa directory: %v.\n", err)
			dirPath = ""
		} else {
			radamMan = &radamManager{dirPath: dirPath}
		}
	}
	//
	return &crossGen{
		inputs:   make(map[uint64]crossGenIn),
		radamMan: radamMan,
	}
}

func (cg *crossGen) newSeed(seedPt *seedT) {
	if !useCrosser {
		return
	}

	hash := seedPt.hash
	input := make([]byte, len(seedPt.input))
	copy(input, seedPt.input)

	go func(hash uint64, input []byte) {
		if len(input) < 5 {
			return
		}
		cg.mtx.Lock()
		name := fmt.Sprintf("%04d", cg.inCnt)
		cg.inCnt++
		cg.inputs[hash] = crossGenIn{
			input: input,
			name:  name,
		}
		cg.mtx.Unlock()
		if cg.radamMan != nil {
			cg.radamMan.newSeed(input, name, len(cg.inputs))
		}
	}(hash, input)
}
func (cg *crossGen) cullSeeds(toRem []uint64) {
	if !useCrosser {
		return
	}

	cg.mtx.Lock()
	for _, hash := range toRem {
		if _, ok := cg.inputs[hash]; ok {
			if cg.radamMan != nil {
				cg.radamMan.deleteIn(cg.inputs[hash].name)
			}
			delete(cg.inputs, hash)
		}
	}
	cg.mtx.Unlock()
}
func (cg *crossGen) isReady() (is bool) {
	cg.mtx.RLock()
	if len(cg.inputs) >= minCrossGenInputN {
		is = true
	}
	cg.mtx.RUnlock()
	return is
}

func (cg *crossGen) generate() ([]byte, []decisionReport) {
	var tc []byte
	if cg.radamMan != nil && cg.radamMan.usable && rand.Intn(5) == 0 {
		var ok bool
		ok, tc = cg.radamGen()
		if !ok {
			tc = cg.crossGen()
		}
	} else {
		tc = cg.crossGen()
	}
	return tc, []decisionReport{}
}

// ******************************* Crossover Generation ************************

func (cg *crossGen) crossGen() []byte {
	cg.mtx.RLock()
	if len(cg.inputs) < minCrossGenInputN {
		panic("Crossover called without enough seed.")
	}

	// ** 1. Chose the inputs to cross **
	var in1, in2 []byte
	var i int
	for _, cgIn := range cg.inputs {
		// Totally relying on the random behavior of hashmap... As they said not to :/
		switch i {
		case 0:
			in1 = cgIn.input
		case 1:
			in2 = cgIn.input
		default:
			break
		}
		i++
	}

	// ** 2. Do the crossing **
	mLen := len(in1)
	if len(in2) < mLen {
		mLen = len(in2)
	}
	if mLen == 0 {
		log.Printf("in1: %d, i2: %d\n", len(in1), len(in2))
		panic("Zero length")
	}
	start, end := -1, -1
	for pos := 0; pos < mLen; pos++ {
		if in1[pos] != in2[pos] {
			if start == -1 {
				start = pos
			}
			end = pos
		}
	}
	if start < 0 || end < 2 || start == end {
		log.Printf("Crossover calls itself: start=%d end=%d mLen=%d.\n", start, end, mLen)
		cg.mtx.RUnlock()
		return cg.crossGen()
	}
	//
	splitAt, diff := start, end-start
	if diff > 1 {
		splitAt += rand.Intn(diff)
	}
	newIn := make([]byte, splitAt, len(in2))
	copy(newIn, in1[:splitAt])
	newIn = append(newIn, in2[splitAt:]...)

	// @TODO: Could report which seed has been the best to splice with.
	// That would require another way to index the inputs. Or at least some
	// additional structure to do the weighted random choice.
	cg.mtx.RUnlock()
	if len(newIn) == 0 {
		panic("Crossover returned empty test case")
	}
	return newIn
}

func (cg *crossGen) epilogue(uint, uint64) {}

// ******************************** Radamsa ************************************

const (
	radamName      = "radamsa"
	radamReqN      = 100
	radamSpeedBump = time.Minute
)

var isRadamsa bool

func init() {
	var radamPath string
	if path, err := exec.LookPath(radamName); err == nil {
		radamPath = path
	} else if _, err := os.Stat("./" + radamName); err == nil {
		radamPath = "./" + radamName
	}

	if len(radamPath) > 0 {
		fmt.Printf("Radamsa found at: %s, using it.\n", radamPath)
		isRadamsa = true
	}
}

type radamManager struct {
	inputs [][]byte
	usable bool

	mtx     sync.Mutex
	dirPath string // To keep inputs in.
}

func (radamMan *radamManager) newSeed(input []byte, name string, inputN int) {
	path := filepath.Join(radamMan.dirPath, name)
	err := ioutil.WriteFile(path, input, 0644)
	if err != nil {
		log.Printf("Couldn't write a Radamsa file: %v.\n", err)
		return
	}

	radamMan.mtx.Lock()
	if !radamMan.usable && inputN >= minCrossGenInputN {
		radamMan.usable = true
		ok, inputs := getRadamIn(radamMan.dirPath, radamReqN)
		if ok {
			radamMan.inputs = inputs
		}
		radamMan.mtx.Unlock()
		return
	}
	radamMan.mtx.Unlock()
}

func (radamMan *radamManager) deleteIn(name string) {
	path := filepath.Join(radamMan.dirPath, name)
	radamMan.mtx.Lock()
	err := os.Remove(path)
	if err != nil {
		log.Printf("Couldn't remove a Radamsa input: %v.\n", err)
	}
	radamMan.mtx.Unlock()
}

func (cg *crossGen) radamGen() (bool, []byte) { return cg.radamGenC(0) }
func (cg *crossGen) radamGenC(callN int) (ok bool, tc []byte) {
	cg.radamMan.mtx.Lock()
	ins := cg.radamMan.inputs
	if len(ins) == 0 { // Refill if needed
		var ok bool
		ok, ins = getRadamIn(cg.radamMan.dirPath, radamReqN)
		if !ok {
			cg.radamMan.mtx.Unlock()
			return ok, tc
		}
	}
	//
	tc = ins[len(ins)-1]
	cg.radamMan.inputs = ins[:len(ins)-1]
	cg.radamMan.mtx.Unlock()
	if len(tc) > 2e5 {
		if callN < 5 {
			return cg.radamGenC(callN + 1)
		} else {
			return true, cg.crossGen()
		}
	}
	ok = true
	return ok, tc
}

func getRadamIn(inDirPath string, inputN int) (ok bool, inputs [][]byte) {
	// ** I - Call Radamsa **
	outfile := filepath.Join("/tmp", fmt.Sprintf("%x", rand.Uint64()))
	cmd := exec.Command(radamName, "-r", inDirPath,
		"-n", fmt.Sprintf("%d", inputN), "-o", outfile+"%04n")
	//
	err := cmd.Run()
	if err != nil {
		log.Printf("Couldn't get inputs from Radamsa: %v.\n", err)
		return
	}

	// ** II - Read&Remove Radamsa production **
	inputs = make([][]byte, inputN)
	for i := range inputs {
		path := fmt.Sprintf("%s%04d", outfile, i+1)
		inputs[i], err = ioutil.ReadFile(path)
		if err != nil {
			log.Printf("Couldn't read Radamsa %dth input: %v.\n", i, err)
		}
		os.Remove(path)
	}

	ok = true
	return ok, inputs
}
