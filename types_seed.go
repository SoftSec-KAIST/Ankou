package main

import (
	"fmt"
	"log"

	"math"
	"sort"
	"sync"
	"syscall"
	"time"
)

/******************************************************************************/
/****************************** Seed Management *******************************/
/******************************************************************************/

type runMetaData struct {
	// execution information
	pid     uint32
	status  uint32
	sig     syscall.Signal
	hanged  bool
	crashed bool
	err     error

	// fuzzing information
	orig  *seedT
	depth uint
}

type seedT struct {
	inputMtx  sync.RWMutex // Mutex on seed input because gets replace sometimes
	input     []byte
	info      runMetaData
	execNb    uint
	traceBits []byte

	// Collected Data
	trSize     uint
	hangNb     uint
	roundNb    int
	execTime   float64 // (in us)
	calibrated bool
	initDist   float64

	// Generated Data
	hash uint64
	//
	score   float64
	pcaFeat *pcaFeatures

	// Selection info for printing
	selInfo []float64

	// (Memory) Pool usage
	pf *poolFreer
}

type seedList []*seedT
type seedMap map[uint64]*seedT

func (seedPts seedList) toSeedMap() (sm seedMap) {
	sm = make(seedMap)
	for _, seedPt := range seedPts {
		sm[seedPt.hash] = seedPt
	}
	return sm
}
func (sm seedMap) toSeedList() (seedPts seedList) {
	seedPts = make(seedList, len(sm))
	var i int
	for _, seedPt := range sm {
		seedPts[i] = seedPt
		i++
	}
	return seedPts
}

// ****** init ******

func makeSeed(seedPt *seedT, testCase []byte) {
	seedPt.input = make([]byte, len(testCase))
	copy(seedPt.input, testCase)
}

func makeEmptySeed(put frkSrv) (seed seedT) {
	makeSeed(&seed, []byte{})

	runInfo, err := runTarget(put, seed.input, execTimeOut,
		makeNullKillerChan(), true)
	if err != nil {
		log.Printf("No seed as input and default seed could not execute: %v\n",
			err)
		seed.traceBits = make([]byte, mapSize)
	}
	seed.info = runInfo
	seed.hash = hashTrBits(put.traceBits)
	seed.execTime = 1000

	return
}

func (seedPt *seedT) setTrSize() {
	var trSize uint
	for _, hitCount := range seedPt.traceBits {
		if hitCount != 0 {
			trSize++
		}
	}
	seedPt.trSize = trSize
}

// ** copy: a util for deep copy of a seedList **
func (seedPts seedList) cpy() (cpyList seedList) {
	cpyList = make(seedList, len(seedPts))
	copy(cpyList, seedPts)
	return cpyList
}

// *******************
// ** Sub Selection ** (for distance regression)

func (seedPts seedList) alreadyExecuted() (subSeedPts seedList) {
	for _, seedPt := range seedPts {
		if seedPt.execNb > 0 {
			continue
		}
		subSeedPts = append(subSeedPts, seedPt)
	}
	return subSeedPts
}

// *****************************************************************************
// ****************************** Tree Pruning *********************************
// When using the PCA-Learner for fitness, it often happens that some seed are
// the result of seeds that are no longer in the seed list. Thus, since all
// seeds point to their parents, this seed is kept "invisibly" in memory.
//
// Need to make seed stop pointing towards those invisible parents so that the
// garbage collector get their memory back (especially the input and the trace).

func pruneSeedTree(seedPts seedList) {
	seedMap := seedPts.toSeedMap()
	goNext := func(seedPt *seedT) bool {
		if seedPt == nil {
			return false // If nil, stop, nowhere to go.
		}
		_, ok := seedMap[seedPt.hash]
		// If in the list, stop, found suitable origin, otherwise, go on searching.
		return !ok
	}

	for _, seedPt := range seedPts {
		orig := seedPt.info.orig
		for goNext(orig) {
			orig = orig.info.orig
		}
		seedPt.info.orig = orig
	}
}

// ***********
// ** Debug **
func printSeedTree(seedPts seedList) {
	seedMap := make(map[uint64]struct{})
	for _, seedPt := range seedPts {
		ptr := seedPt
		for ptr != nil {
			seedMap[ptr.hash] = struct{}{}
			ptr = ptr.info.orig
		}
	}
	fmt.Printf("len(seedPts) = %+v\n", len(seedPts))
	fmt.Printf("#seeds pointed by the 'seed tree': %d\n", len(seedMap))
}

// *****************************************************************************
// ******************************* Input Copy **********************************

func (seedPt *seedT) getInputCopy() (cp []byte, curLen int) {
	seedPt.inputMtx.RLock()
	curLen = len(seedPt.input)
	cp = make([]byte, curLen)
	copy(cp, seedPt.input)
	seedPt.inputMtx.RUnlock()
	return cp, curLen
}

func (seedPt *seedT) newInput(newI []byte) {
	seedPt.inputMtx.Lock()
	if len(seedPt.input) > len(newI) {
		seedPt.input = newI
	}
	seedPt.inputMtx.Unlock()
}

// *****************************************************************************
// ******************************* Custom Pool *********************************
// Like a sync.Pool but "custom".
// get is not concurrent safe. Only called from the fork server it is assigned
// to.
// put is concurrent safe. Put back the traceBits in the pool via channel.
//
// Use for copies of AFL shared memory (contain execution trace information;
// hit count for each branch). Also, (plan to) use for inputs.

type bytePool struct {
	pool     [][]byte
	bitsChan chan []byte
	req, ack chan struct{}

	// Debug
	produced int
}

func newBytePool() (bp *bytePool) {
	bp = new(bytePool)
	bp.bitsChan = make(chan []byte, 10)
	bp.req, bp.ack = make(chan struct{}), make(chan struct{})

	go func() {
		var usedBits [][]byte
		var poolSize int
		t := time.Now()

		for {
			select {
			case bits := <-bp.bitsChan:
				usedBits = append(usedBits, bits)
				poolSize++

			case <-bp.req:
				if time.Now().Sub(t) > 10*time.Minute {
					// Sometimes, a very fast seed will make the pool bigger
					// than it needs to be. The reset (should) mitigates the
					// memory over-consumption caused by this kind of seed.
					t = time.Now()
					poolSize, bp.pool = 0, nil
				} else {
					bp.pool = append(bp.pool, usedBits...)
					poolSize = len(bp.pool)
				}
				bp.ack <- struct{}{}
				usedBits = make([][]byte, 0)
			}
		}
	}()

	return bp
}

func (bp *bytePool) get(size int) (bits []byte) {
	if len(bp.pool) == 0 {
		bp.produced++
		return make([]byte, size)
	}

	endI := len(bp.pool) - 1
	bits = bp.pool[endI]

	sizeDiff := size - len(bits)
	if sizeDiff > 0 {
		bits = append(bits, make([]byte, sizeDiff)...)
	} else if sizeDiff < 0 {
		bits = bits[:size]
	}

	bp.pool = bp.pool[:endI]
	if false && len(bits) != size { // Debug
		panic("pool.get: wrong slice size")
	}
	return bits
}

func (bp *bytePool) put(bits []byte) {
	bp.bitsChan <- bits
}

func (bp *bytePool) retrieve() {
	bp.req <- struct{}{}
	<-bp.ack
}

func makeBPFreeer(pool *bytePool, data []byte) func() {
	return func() {
		pool.put(data)
	}
}

// *************************************
// ******** (Memory) Pool Usage ********
// Seeds are consuming quite a lot of data. sync.Pool can partially make the
// allocation of memory faster by enabling re-usage of buffers.
// However, sadly, that impies reference counting...

type poolFreer struct {
	freeWG sync.WaitGroup
	freeer func()
}

func (pf *poolFreer) done() { pf.add(-1) }
func (pf *poolFreer) add(delta int) {
	if pf != nil {
		pf.freeWG.Add(delta)
	}
}

func (seedPt *seedT) appendFreeer(freeer func()) {
	if seedPt.pf == nil {
		seedPt.pf = newPoolFreeer(freeer)
	} else {
		seedPt.pf.addFreeer(freeer)
	}
}

func newPoolFreeer(freeer func()) (pf *poolFreer) {
	pf = new(poolFreer)

	pf.freeer = freeer
	pf.freeWG.Add(1)

	go func(pf *poolFreer) {
		pf.freeWG.Wait()
		pf.freeer()
	}(pf)

	return pf
}

func (pf *poolFreer) addFreeer(freeer func()) {
	oldFreeer := pf.freeer
	pf.freeer = func() {
		oldFreeer()
		freeer()
	}
}

func (seedPt *seedT) clean() {
	if seedPt.pf != nil {
		seedPt.pf.done()
	}
}

func (seedPt *seedT) setTraceBits(bp *bytePool) {
	seedPt.traceBits = bp.get(mapSize)
	freeer := makeBPFreeer(bp, seedPt.traceBits)
	seedPt.appendFreeer(freeer)
}

// **********************
// ****** Timeout *******
const timeoutUpperLimit = 100 * time.Millisecond

func (seedPt *seedT) setExecTime(rawExec rawExecutor) {
	seedPt.execTime = 1000000 * float64(seedPt.roundNb) / float64(seedPt.execNb)
	if seedPt.calibrated {
		return
	}

	if rawExec == nil { // Cannot do anything anyway.
		return
	}
	hangRate := float64(seedPt.execNb) / float64(seedPt.hangNb)
	if hangRate > 10 {
		return
	}

	// ** Calibrate **
	// This takes a while and potentially blocks the whole fuzzing session.
	// Don't care much because:
	// - should not happen much
	// - benchmarks are unicore...
	// If want to optimize, should do no calibration and just do the main
	// fuzzing with raw execution and note the execution time. (@TODO)

	//dbgPr("Seed %x (len:%d) has too many hangs (rate:%.1f).\n",
	//	seedPt.hash, len(seedPt.input), hangRate)
	var execDurs []time.Duration
	var execCnt int
	seedPt.calibrated = true

	timeout := seedPt.timeout()
	for execCnt < 10 {
		state := rawExec.exec(seedPt.input, timeout)
		if state == nil {
			continue
		}
		execDurs = append(execDurs, state.UserTime()+state.SystemTime())
		execCnt++
	}

	mean, sig := timeStats(execDurs)
	dbgPr("Time stats, mean: %v\tvariance: %v\n", mean, sig)
	newTimeout := ((5 * mean) / 4) + 2*sig
	if newTimeout < 100*time.Microsecond { // Don't believe
		newTimeout = timeoutUpperLimit / 5
	}
	seedPt.execTime = float64(newTimeout / time.Microsecond)
}

func timeStats(durs []time.Duration) (mean, sig time.Duration) {
	for _, dur := range durs {
		mean += dur
	}
	mean /= time.Duration(len(durs))

	for _, dur := range durs {
		sig += (dur - mean) * (dur - mean)
	}
	sig = time.Duration(math.Sqrt(float64(sig / time.Duration(len(durs)))))

	return mean, sig
}

// What we are doing is more or less based on a Poisson estimation with Gamma
// prior.
// Would have to study more the Poisson CDF to get guarantess on the confidence
// interval. (Lazy :( )
func (seedPt *seedT) timeout() (maxTime time.Duration) {
	if seedPt.roundNb == 0 {
		return execTimeOut
	}
	if seedPt.calibrated {
		return time.Duration(seedPt.execTime) * time.Microsecond
	}

	// Taking in account mutation time.
	const cstTime = 200 * time.Microsecond
	maxTime = 3 * time.Duration(seedPt.execTime) * time.Microsecond
	maxTime += cstTime

	if maxTime > timeoutUpperLimit {
		maxTime = timeoutUpperLimit
	}

	//dbgPr("timeout = %+v\n", maxTime)
	return maxTime
}

// ****** Seed Factors ******
// Seed factor is the way we transmit "expert knowledge".
// Impact when seed would have about the same score otherwise.

func (seedPts seedList) getFileSizeMean() (mean float64) {
	if len(seedPts) == 0 {
		return 100
	}

	var totLen int
	for _, seedPt := range seedPts {
		totLen += len(seedPt.input)
	}
	mean = float64(totLen) / float64(len(seedPts))
	return mean
}

func (seedPts seedList) getExecTimeMean() (mean float64) {
	if len(seedPts) == 0 {
		return 1000
	}

	for _, seedPt := range seedPts {
		mean += seedPt.execTime
	}
	mean /= float64(len(seedPts))
	return mean
}

func (seedPts seedList) getTrSizeMean() (mean float64) {
	var tot uint
	for _, seedPt := range seedPts {
		tot += seedPt.trSize
	}
	mean = float64(tot) / float64(len(seedPts))
	return mean
}

func (seedPt *seedT) getFactor(avgExecTime, avgTr float64) (fact float64) {
	fact = avgExecTime / seedPt.execTime
	fact *= float64(seedPt.trSize) / avgTr
	fact *= fact
	return fact
}

// ****** Sorting *******

func (seedPts seedList) scoreSort() {
	sort.Slice(seedPts, func(i, j int) bool {
		return seedPts[i].score > seedPts[j].score
	})
}

func (seedPts seedList) sortExec() {
	sort.Slice(seedPts, func(i, j int) bool {
		execNb1 := seedPts[i].execNb
		execNb2 := seedPts[j].execNb
		if execNb1 != execNb2 {
			return execNb1 > execNb2
		}
		return seedPts[i].score > seedPts[j].score
	})
}

// Debug function
// Take an external seed as argument. Return whether or not this seed is already
// in the seed list.
func (seedPts seedList) isIn(extSeedPt *seedT) bool {
	for _, seedPt := range seedPts {
		if seedPt != nil && seedPt.hash == extSeedPt.hash {
			return true
		}
	}
	return false
}

// *****************************************************************************
// ******************************** Printing ***********************************

func (seedPt *seedT) strings() (strs [][2]string) {

	strs = append(strs, [2]string{"hash", fmt.Sprintf("%x", seedPt.hash)})
	inputStr := [2]string{"len", fmt.Sprintf("%d", len(seedPt.input))}
	strs = append(strs, inputStr)
	strs = append(strs, [2]string{"traceSize", fmt.Sprintf("%d", seedPt.trSize)})
	strs = append(strs, [2]string{"execTime", fmt.Sprintf("%.1f", seedPt.execTime)})
	strs = append(strs, [2]string{"round", fmt.Sprintf("%d", seedPt.roundNb)})

	if selType == pcaWmoSel {
		strs = append(strs, [2]string{"Score", fmt.Sprintf("%.2f", seedPt.score)})
	}

	return
}

func (seedPt *seedT) String() (str string) {
	strs := seedPt.strings()

	str = fmt.Sprintf("{%s=%s", strs[0][0], strs[0][1])
	for i := 1; i < len(strs); i++ {
		str = fmt.Sprintf("%s\t%s=%s", str, strs[i][0], strs[i][1])
	}
	str = fmt.Sprintf("%s}", str)

	return
}
