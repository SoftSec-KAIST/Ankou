package main

import (
	"fmt"

	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
)

/******************************************************************************/
/******************************* Various Types ********************************/
/******************************************************************************/

const (
	fileSizeMax = 1 << 19 // 1M, as AFL.
	mapSizePow2 = 16
	mapSize     = 1 << mapSizePow2

	// RoundTimeout is the duration of a fuzzing round. This is equivalent to
	// the *energy* describe in AFLFast.
	//
	// Theoritically, the lower the RoundTimeout is, the more granular the
	// choice made by the seed scheduler. However, it has to be high enough to
	// amortize the cost of the inter-round analysis.
	RoundTimeout = time.Second
	gainWindow   = 100

	// regulizer: if a new branch is discovered, it does not have an infinite
	// value that would be hard to handle. It still has a much higher value
	// than all other cases.
	regulizer float64 = 0.1

	almostZero  float64 = 1.0 / (1 << 30)
	execTimeOut         = 20 * time.Millisecond

	seedTableMax = 25

	hitCountLog2Max = 8

	// If use new:
	doSelfTrim = true

	// Selection types
	randSel = iota + 1
	pcaWmoSel

	// Input generation by other methods than mutation.
	useVersifier = true
	useCrosser   = true
	useStacking  = true

	// Rate regualtion: in case throughput is too high to use PCA
	useRateReg = true

	// ***************************************
	// *** Test/Debug/Experimental options ***

	// For experiments:
	noPCAstart     = false // Deactivate PCA (meaning, using branch coverage only).
	doFullDistTest = false // Compute distance without PCA.

	// Benchmark each mutation function time (in avg, with seed of different
	// length).
	doBenchMut = false
)

var (
	selType = 0

	// Synchronization to wait before starting new round.
	// Makes thing a bit different when on one core to be sure we are working
	// the same way AFL does.
	unicore = false

	// Whether add new seeds to the seed pool.
	// Basis of greybox-box fuzzing and evolutionnary algorithm. Just
	// deactivated for some experiments.
	evolutivePool = true

	verbose    = false
	debug      = false
	printChart = false
)

/******************************************************************************/
/**************************** Miscellanious types *****************************/

// *****************************************************************************
// Crash contains the Input for which this a bug in the analyzed program was
// discovered and the error it got, so that the script can replay this bug later
// on.
type Crash struct {
	In        []byte
	traceBits []byte
	HashVal   uint64
	err       error
}

// PUT structure contains all the info about the current fuzzing session.
type PUT struct {
	// *** Fuzzer Setup ***
	progName string
	puts     []frkSrv
	rawExec  rawExecutor

	seedSelector selector

	// *** Fuzzer "live" data collection ***

	seedPts      seedList
	refreshFloor float64
	rndDiff      uint

	crashes   map[uint64]Crash
	seedLoops map[uint64]uint // cf. AFL Fast.

	totalRoundNb uint
	totalHangs   uint

	nbHash int
}

func newGlbData(frkSrvNb int, baseName string, args Arguments) *PUT {
	var glbData PUT
	glbData.progName = baseName
	glbData.refreshFloor = math.Inf(+1)

	glbData.puts = make([]frkSrv, frkSrvNb)
	dictWords := makeDictWords(args.DictPath)
	for i := range glbData.puts {
		glbData.puts[i].rSrc = rand.New(rand.NewSource(rand.Int63()))
		glbData.puts[i].dictWords = dictWords
	}

	glbData.crashes = make(map[uint64]Crash)
	glbData.seedLoops = make(map[uint64]uint)

	switch selType {
	case randSel:
		glbData.seedSelector = makeRandomSel(&glbData)
	case pcaWmoSel:
		glbData.seedSelector = newPcaWmoSel(&glbData)
	}

	return &glbData
}

// *****************************************************************************
// frkSrv have the necessery elements to run the program and get coverage
// information. One thread assiociated with one CPU.
type frkSrv struct {
	rndChan chan func()

	name        string
	stateChan   chan string
	blockedChan chan struct{}
	debugTimer  *time.Timer

	ctlPipeW  *os.File
	stPipeR   *os.File
	traceBits []byte
	shmID     uintptr
	pid       int
	tcWriter  putWriter // test case writer: io.Writer + clean interfaces.

	traceBitPool *bytePool // Pool of AFL shared memory
	rndRep       *rndReport

	// Passed to be used at each round.
	rSrc      *rand.Rand // Random source
	dictWords [][]byte   // AFL style dictionnary
}

// *****************************************************************************
// ************************** Communication Types ******************************
// *****************************************************************************

// ***** Round arguments *****

type rndArgs struct {
	seedPt *seedT

	// Arguments common to all rounds.
	wg    *sync.WaitGroup
	chFnd chan<- finding
	put   *frkSrv

	// Local Hash
	hashLife   int
	execHashes localHashesT

	// For input generation
	ig inputGen
	dc distCalculator
	//
	stackMu float64
	//
	versifier *verse
	crosser   *crossGen
}

func makeFrkSrvArgs(glbDataPt *PUT, wg *sync.WaitGroup, chFnd chan<- finding,
	versifier *verse, crosser *crossGen) (args []rndArgs) {

	args = make([]rndArgs, len(glbDataPt.puts))
	for i := range args {
		args[i].wg = wg
		args[i].chFnd = chFnd
		args[i].put = &(glbDataPt.puts[i])
		args[i].execHashes = make(localHashesT)
		//
		args[i].versifier = versifier
		args[i].crosser = crosser
	}

	return args
}

func (roundArgs *rndArgs) makeRoundFunc(seedMutRecs seedMutationRecords) func() {

	if roundArgs.hashLife == 2000 { // Reset every ~30min
		roundArgs.execHashes = make(localHashesT)
	}
	roundArgs.hashLife++

	roundArgs.put.traceBitPool.retrieve()

	if hash := roundArgs.seedPt.hash; hash == versiHash {
		if len(roundArgs.versifier.blocks) == 0 {
			panic("Trying to used uninitialized verisifier")
		}
		roundArgs.ig = makeVersiGen(roundArgs.versifier)
	} else if hash == crosserHash {
		roundArgs.ig = roundArgs.crosser
	} else {
		if hash != seedMutRecs.hash {
			if seedMutRecs.hash == 0 {
				fmt.Printf("seedMutRecs = %+v\n", seedMutRecs)
			}
			panic(fmt.Sprintf("Hash problem in roundArgs: 0x%x v. 0x%x",
				hash, seedMutRecs.hash))
		}
		roundArgs.stackMu = seedMutRecs.stackSRec.genStackMu()
		roundArgs.ig = roundArgs.makeMutateGen(seedMutRecs.mutMan)
	}

	return func() { roundArgs.runOneRound() }
}

func resetFrkSrvArgsHashes(args []rndArgs) {
	for i := range args {
		args[i].execHashes = make(localHashesT)
		args[i].hashLife = 0
	}
}

// *************
// *** Debug ***
func showPools(args []rndArgs) {
	if !debug {
		return
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"index", "pool_size", "produced"})

	var totSize, totProduced int
	for i, arg := range args {
		bp := arg.put.traceBitPool
		totSize += len(bp.pool)
		totProduced += bp.produced
		table.Append([]string{
			fmt.Sprintf("%d", i),
			fmt.Sprintf("%d", len(bp.pool)),
			fmt.Sprintf("%d", bp.produced),
		})
	}
	table.Append([]string{
		"total", fmt.Sprintf("%d", totSize), fmt.Sprintf("%d", totProduced),
	})

	table.Render()
}

// *****************************************************************************
// ***** Round Report ******
// Report sent by each fork server at the end of a fuzzing round to the seed
// manager to describe what happened.

type rndReport struct { // Per round report
	// Used by the seedManager to update seed information
	execs  uint
	hangs  uint
	loopNb uint

	// Used by the main fuzzing loop to update information of the mutation
	// managers of each seed.
	allMutReports map[uint64][]decisionReport
	stackMu       float64
}

func (rep *rndReport) zero() {
	rep.execs = 0
	rep.hangs = 0
	rep.loopNb = 0
}

// *****************************************************************************
// ***** Receiver and Seed Manager Communication Channels *****
// Channels created by the "central" fuzzing loop to setup the receiver and the
// seed manager communications (with and between them).

type seedManChans struct {
	// Sync with the fuzzing routine
	selected chan seedList
	reqSeeds chan struct{}
	ackSeeds chan struct{}

	// Sync with the receiver (now via the distance computing routine).
	newSeedCh   chan *seedT // single new seed
	crashChan   chan *seedT
	reqSeedPts  <-chan struct{} // Send copy of seed list
	seedPtsChan chan<- seedList
	recInfoChan <-chan string // Get info to print from receiver.

	// Reset/culling
	cullCh <-chan []uint64 // Get hash list of seeds to be kept.

	versifier *verse
	crosser   *crossGen
}

// Channel given to the receiver so the fuzzing routine can synchronize with
// the receiver.
type recChans struct {
	// Sync with the fuzzing routine
	reqClear chan struct{}
	ackClear chan distCalcGetter

	// Sync with the seed manager
	reqSeedPts  chan<- struct{}
	seedPtsChan <-chan seedList
	recInfoChan chan<- string // Send info to print to seedManager.

	// Reset/culling
	seedManCullCh chan []uint64
}

type resetter interface{ info() (bool, []uint64) }

func makeComChans(frkSrvNb int) (seedsCom seedManChans, analCom recChans) {
	reqSeedPts := make(chan struct{})
	seedPtsChan := make(chan seedList)
	recInfoChan := make(chan string, 1)

	seedsCom.selected = make(chan seedList)
	seedsCom.reqSeeds = make(chan struct{})
	seedsCom.ackSeeds = make(chan struct{})
	seedsCom.newSeedCh = make(chan *seedT, 10*frkSrvNb)
	seedsCom.crashChan = make(chan *seedT, 10)
	seedsCom.reqSeedPts = reqSeedPts
	seedsCom.seedPtsChan = seedPtsChan
	seedsCom.recInfoChan = recInfoChan
	seedsCom.versifier = &verse{r: newPCG()}
	seedsCom.crosser = newCrossGen()

	analCom.reqClear = make(chan struct{})
	analCom.ackClear = make(chan distCalcGetter)
	analCom.reqSeedPts = reqSeedPts
	analCom.seedPtsChan = seedPtsChan
	analCom.recInfoChan = recInfoChan

	// Reset/culling
	cullChan := make(chan []uint64, 1)
	seedsCom.cullCh = cullChan
	analCom.seedManCullCh = cullChan

	return seedsCom, analCom
}

func (analCom recChans) getSeedList() (seedPts seedList) {
	analCom.reqSeedPts <- struct{}{}
	seedPts = <-analCom.seedPtsChan
	return seedPts
}

type finding struct {
	seedPt    *seedT
	testCase  []byte
	put       frkSrv
	replaying bool
}

// *****************************************************************************
// ***************************** Execution Point *******************************

// ExecPoint is an execution point. In practive it's a seed (from the fuzzer
// internals) or it's an inputTrace created for further analysis (e.g.
// clustering, triaging).
type ExecPoint interface { // Seed or traceInput
	Hash() uint64
	Input() []byte
	getTrace() []byte
}

// 'Simplest' type to respect interface.
type inputTrace struct {
	input     []byte
	traceBits []byte
	hash      uint64
	crashed   bool
}

// *** Interface compliance ***
// *seedMetaData and inputTrace satisfy execPoint interface.

func (tr inputTrace) getTrace() []byte { return tr.traceBits }
func (tr inputTrace) Hash() uint64     { return tr.hash }
func (tr inputTrace) Input() []byte    { return tr.input }
func (seedPt *seedT) getTrace() []byte { return seedPt.traceBits }
func (seedPt *seedT) Hash() uint64     { return seedPt.hash }
func (seedPt *seedT) Input() []byte    { return seedPt.input }
func (c Crash) Input() []byte          { return c.In }
func (c Crash) Hash() uint64           { return c.HashVal }
func (c Crash) getTrace() []byte       { return c.traceBits }

// That's where generic would be nice...
func traceToEP(traces []inputTrace) (list []ExecPoint) {
	for _, trace := range traces {
		list = append(list, trace)
	}
	return list
}
func (seedPts seedList) toEP() (list []ExecPoint) {
	for _, seedPt := range seedPts {
		list = append(list, seedPt)
	}
	return list
}

// ***** 'sub interfaces' *****
type tracer interface{ getTrace() []byte }
type hashed interface{ Hash() uint64 }

type traceBytes []byte

func (trb traceBytes) getTrace() []byte { return trb }

// *****************************************************************************
// *****************************************************************************

func (args Arguments) String() (str string) {
	var in string
	if args.Stdin {
		in = "stdin"
	} else {
		in = "file"
	}

	cmd := fmt.Sprintf("%s", args.Argv)
	if len(cmd) > 1 {
		cmd = cmd[1 : len(cmd)-1]
	}
	str = fmt.Sprintf("{Cmd (input:%s): %s %s\n", in, args.Target, cmd)

	var seeds []string
	for _, path := range args.Seeds {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		seeds = append(seeds, fmt.Sprintf("%s", filepath.Base(path)))
	}
	seedsStr := ""
	first := true
	for _, seed := range seeds {
		if first {
			first = false
			seedsStr = seed
		} else {
			seedsStr = fmt.Sprintf("%s, %s", seedsStr, seed)
		}
	}
	seedsStr = fmt.Sprintf("Seeds: {%s}\n", seedsStr)
	str += seedsStr

	str += fmt.Sprintf("FrkSrv nb:%d, Nb Round:%d, Verbose:%t, sel: %s}",
		args.FrkSrvNb, args.NbRound, args.Verbose, args.SelAlg)

	return str
}
