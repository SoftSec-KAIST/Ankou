package main

import (
	"math"
	"reflect"
	"sync"
	"unsafe"
)

// ****** Trick to speed up logarithm... ******
var (
	logVals       [0x100]float64
	logDiffVals   [0x100][0x100]float32
	logSqDiffVals [0x100][0x100]float64
)

func init() {
	logReg := math.Log(regulizer)
	// Skip the first because it's strictly zero. Don't want some residual
	// value.
	for i := 1; i < 0x100; i++ {
		log := math.Log(float64(i)+regulizer) - logReg
		logVals[i] = log
	}

	for i := range logDiffVals {
		for j := i + 1; j < 0x100; j++ {
			tmp := logVals[j] - logVals[i]
			logDiffVals[i][j] = float32(tmp)
			logDiffVals[j][i] = logDiffVals[i][j]

			logSqDiffVals[i][j] = tmp * tmp
			logSqDiffVals[j][i] = logSqDiffVals[i][j]
		}
	}
}

// *****************************************************************************
// ************************** Executions Analysis ******************************

// ********************************
// ******** Short Analysis ********

// shortAnal makes a very short analysis to see if this execution was
// interesting and is worth sending to the receiver.
// 'short analysis' = hashing and comparing to a 'local hash' store.
// 'local' = only accessed by this fork server.
type tcHashes struct {
	frkSrvPt   *frkSrv
	chFnd      chan<- finding
	execHashes localHashesT

	allMutReps map[uint64][]decisionReport
	dc         distCalculator
}

func makeTCHashes(frkSrvPt *frkSrv, roundArgs *rndArgs) tcHashes {
	return tcHashes{
		frkSrvPt:   frkSrvPt,
		chFnd:      roundArgs.chFnd,
		execHashes: roundArgs.execHashes,

		allMutReps: make(map[uint64][]decisionReport),
		dc:         roundArgs.dc,
	}
}

func (th *tcHashes) shortAnal(runInfo runMetaData, testCase []byte,
	mutRep []decisionReport) {

	th.frkSrvPt.setState("Short anal")
	traceBits := th.frkSrvPt.traceBits
	hash := hashTrBits(traceBits)

	if hash == runInfo.orig.hash { // Triggered same path as the seed it's coming from.
		th.frkSrvPt.rndRep.loopNb++
		if doSelfTrim && len(testCase) < len(runInfo.orig.input) {
			runInfo.orig.newInput(testCase)
		}
		return
	}

	// With the information we have *locally*, does it look new?
	newE := th.execHashes.newHash(hash)
	if !newE {
		return
	}

	// ** It looks new **
	// First prepare the objects.
	pf := newPoolFreeer(func() {})
	seed := seedT{info: runInfo, hash: hash, pf: pf}
	//seed.setTraceBits(th.frkSrvPt.traceBitPool)
	seed.traceBits = make([]byte, len(traceBits))
	copy(seed.traceBits, traceBits)
	newFinding := finding{
		seedPt:   &seed,
		testCase: testCase,
		put:      *th.frkSrvPt,
	}

	// Then, compute distance for mutation report.
	if useStacking {
		dist := th.dc.calcDist(runInfo.orig.traceBits, seed.traceBits)
		for i := range mutRep {
			mutRep[i].reward = dist
		}
		th.allMutReps[hash] = mutRep
	}

	// Now send it.
	th.chFnd <- newFinding
	th.frkSrvPt.setState("End anal")
}

func (th *tcHashes) report(rndRep *rndReport) {
	rndRep.allMutReports = th.allMutReps
}

// ****************************************************************
// ****************** Local execution hashes **********************

type localHashesT map[uint64]struct{}

func (lh localHashesT) newHash(hash uint64) bool {
	if _, ok := lh[hash]; ok {
		return false
	}
	lh[hash] = struct{}{}
	return true
}

// *****************************************************************************
// ************************** AFL crash Analyzer  ******************************

type aflCrashAnalyzer struct {
	mtx *sync.RWMutex

	tupUnion, tupIntersect map[tupleT]struct{}
}

func makeAFLCrashAnalyzer() (aca aflCrashAnalyzer) {
	aca.mtx = new(sync.RWMutex)
	aca.tupUnion = make(map[tupleT]struct{})
	aca.tupIntersect = make(map[tupleT]struct{})
	return aca
}

func (aca aflCrashAnalyzer) longAnal(point ExecPoint, floor float64) float64 {
	isCrash := aca.isCrash(point)
	if isCrash {
		return floor + 0.1
	}
	return 0
}

func (aca aflCrashAnalyzer) isCrash(point ExecPoint) bool {
	var accepted, ok bool
	tuples := toTuples(point.getTrace())
	tMap := make(map[tupleT]struct{})

	aca.mtx.RLock()
	for _, t := range tuples {
		tMap[t] = struct{}{}
		if _, ok = aca.tupUnion[t]; !ok {
			accepted = true
			break
		}
	}
	if !accepted {
		for t := range aca.tupIntersect {
			if _, ok = tMap[t]; !ok {
				accepted = true
				break
			}
		}
	}
	aca.mtx.RUnlock()

	if !accepted {
		return false
	}

	accepted = false
	aca.mtx.Lock()

	// This is the first case to get accepted. Init intersection.
	if len(aca.tupUnion) == 0 {
		for _, t := range tuples {
			aca.tupIntersect[t] = struct{}{}
		}
	}

	for _, t := range tuples {
		tMap[t] = struct{}{}
		if _, ok = aca.tupUnion[t]; !ok {
			accepted = true
			aca.tupUnion[t] = struct{}{}
		}
	}

	for t := range aca.tupIntersect {
		if _, ok = tMap[t]; !ok {
			accepted = true
			delete(aca.tupIntersect, t)
		}
	}
	aca.mtx.Unlock()

	return true
}

// *****************************************************************************
// ****************************** Seed Distance ********************************

func calcDist(tr0, tr1 []byte) (dist float64) {
	for i := range tr0 {
		if tr0[i] == tr1[i] {
			continue
		}
		dist += logSqDiffVals[tr0[i]][tr1[i]]
	}
	//
	dist = math.Sqrt(dist)
	return dist
}

// *****************************************************************************
// ****************************** Distance Calculator **************************
// For distance computation speed optimization.
// No need to go over all the branches. Going over the ones we know are already
// reached is enough.

type distCalculator []int

func makeDistCalculator(seedPts seedList) (dc distCalculator) {
	if len(seedPts) == 0 {
		return
	}

	for i := range seedPts[0].traceBits {
		for _, seedPt := range seedPts {
			if seedPt.traceBits[i] > 0 {
				dc = append(dc, i)
				break
			}
		}
	}

	return dc
}

func (dc distCalculator) calcDist(tr0, tr1 []byte) (dist float64) {
	if len(tr0) == 0 {
		return norm(tr1)
	} else if len(tr1) == 0 {
		return norm(tr0)
	}

	for _, i := range dc {
		if tr0[i] == tr1[i] {
			continue
		}

		dist += logSqDiffVals[tr0[i]][tr1[i]]
	}

	dist = math.Sqrt(dist)
	return dist
}
func norm(tr []byte) (norm float64) {
	if len(tr) == 0 {
		return norm
	}
	for _, t := range tr {
		norm += logVals[t] * logVals[t]
	}
	norm = math.Sqrt(norm)
	return norm
}

// *****************
// *** Interface ***
type distCalcGetter interface{ getDistCalc() distCalculator }
type defaultDistCalcGetter struct{ dc distCalculator }

func (ddcg defaultDistCalcGetter) getDistCalc() distCalculator { return ddcg.dc }

func makeDefaultDistCalculator() distCalcGetter {
	dc := make(distCalculator, mapSize)
	for i := range dc {
		dc[i] = i
	}
	return defaultDistCalcGetter{dc}
}

/******************************************************************************/
/****************************** Global Score **********************************/
// Recompute the global score as to be independent of the order seeds were
// introduced.

const (
	// base: we are in base 2 (computers...)
	// msb: most significant bit. So far, each branch hit count is on 8 bits.
	base  float64 = 2
	msb   float64 = 8
	endBr         = 1 << uint(msb)
)

func scoreGlb(glbTrace [][]byte, maxLvl int) (score float64) {
	// start and end of a branch hit count in log space.
	lvlScores := make([]float64, maxLvl+1)
	bounds := make([][]float64, maxLvl+1)

	lvlScores[0] = math.Log((endBr + regulizer) / regulizer)

	for i := 1; i < maxLvl+1; i++ {
		partitionNb := 1 << uint(i)
		bounds[i] = make([]float64, partitionNb)
		for j := range bounds[i] {
			bounds[i][j] = math.Pow(2, float64(j+1)*msb/float64(partitionNb))
		}

		tmp := (endBr + regulizer) / (bounds[i][partitionNb-2] + regulizer)
		lvlScores[i] = math.Log(tmp)
	}

	if false {
		dbgPr("lvlScores: %.3v\n", lvlScores)
		dbgPr("bounds: %.3v\n", bounds)
	}

	for i := range glbTrace {
		if len(glbTrace[i]) > 0 {
			score += lvlScores[0]
			score += updateScore(glbTrace[i], 0, 2, 1, lvlScores, bounds)
		}
	}

	return score
}

func updateScore(branch []byte, startBound, endBound, lvl int,
	lvlScores []float64, bounds [][]float64) (score float64) {

	if lvl == len(bounds) {
		return score
	}

	var startBrI int // start branch index
	var minBr float64
	if startBound > 0 {
		minBr = bounds[lvl][startBound-1]
	}

	// For debug
	var accepted []byte
	origMinBr := minBr

	for i := startBound; i < endBound; i++ {
		end := bounds[lvl][i] + 0.1 // Borns are inclusive
		for j := startBrI; j < len(branch); j++ {
			hitC := float64(branch[j])
			if hitC < minBr {
				startBrI = j
				continue
			}

			if hitC < end {
				score += lvlScores[lvl]
				score += updateScore(branch[startBrI:], 2*i, 2*(i+1), lvl+1,
					lvlScores, bounds)

				if debug {
					accepted = append(accepted, branch[j]) // branch[j]=hitC
				}

				startBrI = j
				minBr = end
				break
			}
		}
	}

	if false {
		dbgPr("branch: %v\tlvl: %d minBr: %.2f\tbounds: %v\n", branch, lvl,
			origMinBr, bounds[lvl][startBound:endBound])
		dbgPr("accepted: %v\n", accepted)
	}

	return score
}

// This insertion is quite slow and could be optimized
func traceInsert(values []byte, newVal byte) (ret []byte) {
	var index int
	ret = make([]byte, len(values)+1)

	for i, v := range values {
		if v == newVal {
			index = i
			break
		}
		ret[i] = v
	}
	ret[index] = newVal
	for i := index + 1; i < len(values)+1; i++ {
		ret[i] = values[i-1]
	}

	return ret
}

// *****************************************************************************
// ****************************** AFL Tuples ***********************************

type tupleT uint32

func toTuples(trace []byte) (tuples []tupleT) {
	var log2 int
	var tupleI tupleT

	for branch, tupleV := range trace {
		if tupleV == 0 {
			continue
		}
		_, log2 = math.Frexp(float64(tupleV))
		tupleI = hitCountLog2Max*tupleT(branch) + tupleT(log2)
		tuples = append(tuples, tupleI)
	}
	return tuples
}

// *****************************************************************************
// ******************************* Custom Hash *********************************
// From AFL. Standard hash functions are too slow.
// MurmurHash3?

const (
	hashSeed      = 0xa5b35705 // Nothing to do with fuzzing seeds...
	mapSize64 int = mapSize >> 3

	loopMult1  uint64 = 0x87c37b91114253d5
	loopMult2  uint64 = 0x4cf5ad432745937f
	loopMult3         = 5
	loopAdd           = 0x52dce729
	loopShift1        = 31
	loopShift2        = 27

	endMult1 uint64 = 0xff51afd7ed558ccd
	endMult2 uint64 = 0xc4ceb9fe1a85ec53
	endShift        = 33
)

func rol(x uint64, shift uint) uint64 {
	return ((x << shift) | (x >> (64 - shift)))
}

func hashTrBits(traceBits []byte) (hash uint64) {
	//data := (*[mapSize64]uint64)(unsafe.Pointer(traceBitPt))
	// Unsafe but fast conversion. @TODO: maybe we could do that only once.
	const uint64Size = 8
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&traceBits))
	header.Len /= uint64Size
	header.Cap /= uint64Size
	data := *(*[]uint64)(unsafe.Pointer(&header))

	hash = hashSeed ^ mapSize // ??

	for i := range data {
		k := data[i]
		k *= loopMult1
		k = rol(k, loopShift1)
		k *= loopMult2

		hash ^= k
		hash = rol(hash, loopShift2)
		hash = hash*5 + loopAdd
	}

	hash ^= hash >> endShift
	hash *= endMult1
	hash ^= hash >> endShift
	hash *= endMult2
	hash ^= hash >> endShift

	return hash
}
