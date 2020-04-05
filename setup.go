package main

import (
	"fmt"
	"log"

	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// *****************************************************************************
// ******************************* Setup Functions *****************************
// *****************************************************************************

// *****************************************************************************
// *************************** Command Line Interface **************************

// Arguments are expected to be provided by the user (see CLI help for more info).
type Arguments struct {
	// To run application
	Target string
	Argv   []string
	Stdin  bool
	FileIn bool

	// Fuzzing options
	Seeds    []string
	FrkSrvNb int
	SelAlg   string
	NbRound  int
	DictPath string

	// Others
	Verbose bool
	SaveDir string
}

// Parse is the command line interface implementation.
func Parse() (args Arguments) {
	var seeds, argv, roundStr string
	flag.StringVar(&args.Target, "app", "", "Fuzz target: AFL instrumented binary path")
	flag.StringVar(&argv, "args", "",
		"App arguments. Must be quoted. @@ for file fuzzing.\n"+
			"If not specified, fuzzed in standard input.")

	flag.StringVar(&seeds, "i", "", "Input directory with seeds, or seed files.\n"+
		"If multiple, comma separated, no space.")
	flag.StringVar(&args.SaveDir, "o", "", "Output directory (crashes and discovered seeds).")
	flag.StringVar(&roundStr, "dur", "", "Time to fuzz (default is infinite)")
	flag.StringVar(&args.SelAlg, "select", "rand", "Seed selection algorithm: WMO or random ")
	flag.StringVar(&args.DictPath, "dict", "", "Fuzzer dictionary (see AFL doc for format)")

	flag.IntVar(&args.FrkSrvNb, "threads", 1, "Number of threads "+
		"(i.e. number of fork servers)")

	var debugOption bool
	flag.BoolVar(&debugOption, "debug", false, "Print debug information")

	// *********************
	// ****** Parsing ******
	flag.Parse()
	if len(args.Target) == 0 {
		flag.Usage()
		fmt.Println("")
		log.Fatalf("app parameter is mandatory\n")
	}

	if len(argv) > 0 {
		args.Argv = parseArgs(argv)
	}
	if len(seeds) > 0 {
		args.Seeds = strings.Split(seeds, ",")
	}

	debug = debugOption
	args.Verbose = !debug
	printChart = args.Verbose

	fuzzDur, err := time.ParseDuration(roundStr)
	if err != nil {
		log.Printf("Invalid fuzz duration: %v.\n", err)
		args.NbRound = -1
	} else {
		args.NbRound = int(fuzzDur / RoundTimeout)
	}

	if debug {
		for i, arg := range args.Argv {
			log.Printf("args[%d]: %s\n", i, arg)
		}
	}

	return
}

func parseArgs(argv string) (args []string) {
	splits := strings.Split(argv, " ")
	for _, arg := range splits {
		if len(arg) > 0 {
			args = append(args, arg)
		}
	}

	// Detect quotes
	var isQuote bool
	var startIndex, endIndex int
	for i, arg := range args {
		if arg[0] == '\'' {
			isQuote = true
			startIndex = i
			break
		}
	}
	if !isQuote || startIndex == len(args)-1 {
		return args
	}

	for i, arg := range args[startIndex+1:] {
		endChar := arg[len(arg)-1]
		if endChar == '\'' {
			endIndex = i + startIndex + 1
			break
		}
	}
	if endIndex <= startIndex {
		return args
	}

	var mergedArgs []string
	if startIndex > 0 {
		mergedArgs = make([]string, startIndex)
		copy(mergedArgs, args[:startIndex])
	}
	mergedArgs = append(mergedArgs, strings.Join(args[startIndex:endIndex+1], " "))
	if endIndex+1 < len(args) {
		mergedArgs = append(mergedArgs, args[endIndex+1:]...)
	}
	return mergedArgs
}

const affEnv = "NO_AFFINITY"

// Called by 'startFuzzing', the main fuzzing function. This way Arguments can
// be parsed from CLI, or send by script (e.g. evalfuzz) and then treated here.
func postParse(argsPt *Arguments) {
	argsPt.Argv = append([]string{argsPt.Target}, argsPt.Argv...)
	verbose = argsPt.Verbose

	if argsPt.FrkSrvNb > runtime.NumCPU() {
		log.Fatalf("Cannot have more fork server than avalaible CPUs.")
	}

	for _, arg := range argsPt.Argv {
		if isFileIn(arg) > 0 {
			argsPt.FileIn = true
		}
	}
	if argsPt.FileIn {
		dbgPr("Input using file.\n")
	} else {
		dbgPr("Input using stdin.\n")
	}

	argsPt.Stdin = !argsPt.FileIn

	selAlg := strings.ToLower(argsPt.SelAlg)
	if selAlg[0] == 'r' {
		selType = randSel
	} else if selAlg[0] == 'w' {
		selType = pcaWmoSel
	} else {
		log.Fatal("Need to chose a seed selection algorithm")
	}

	if argsPt.FrkSrvNb == 1 {
		unicore = true
	}

	var oldProcs int
	if unicore && os.Getenv(affEnv) != "1" {
		oldProcs = runtime.GOMAXPROCS(1)
		time.Sleep(50 * time.Millisecond)
		lockProcessCPU()
	} else if false {
		oldProcs = runtime.GOMAXPROCS(2 * argsPt.FrkSrvNb)
	}
	dbgPr("oldProcs = %+v\n", oldProcs)
}

// ***** Initial Seeds Loading *****

func loadSeeds(args Arguments) (givenSeeds [][]byte) {
	// Read from file directly given
	for _, path := range args.Seeds {
		if len(path) == 0 {
			continue
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			log.Printf("Error while reading %s stats: %v\n", path, err)
			continue
		}

		if !fileInfo.IsDir() { // Seed file
			if ok := checkFile(fileInfo); !ok {
				continue
			}

			input, err := ioutil.ReadFile(path)
			if err != nil {
				continue
			}
			givenSeeds = append(givenSeeds, input)

		} else { // Seed directory
			inputs, err := loadDir(path)
			if err != nil {
				log.Fatalf("Error while reading seed directory: %v\n", err)
			}
			givenSeeds = append(givenSeeds, inputs...)
		}
	}

	return givenSeeds
}

func loadDir(path string) (inputs [][]byte, err error) {
	dirFiles, err := ioutil.ReadDir(path)
	if err != nil {
		return inputs, err
	}

	for _, file := range dirFiles {
		if ok := checkFile(file); !ok {
			continue
		}

		fileName := filepath.Join(path, file.Name())
		input, err := ioutil.ReadFile(fileName)
		if err != nil {
			return inputs, err
		}
		inputs = append(inputs, input)
	}

	return inputs, err
}

func checkFile(file os.FileInfo) bool {
	if file.IsDir() { // Could do recursive calls to handle directories?
		return false
	}

	// Not sure what's going to happen if I start loading huge files (megas)
	// here. Probably better not doing so.
	if file.Size() > fileSizeMax {
		log.Printf("%s exceeding file size: %d.\n", file.Name(), file.Size())
		return false
	}
	return true
}

/******************************************************************************/
/********************************* init variables *****************************/

func initFuzzing(target string, frkSrvNb int, givenSeeds [][]byte,
	args Arguments) (glbDataPt *PUT) {

	if frkSrvNb < 1 {
		log.Println("If you want to fuzz something, " +
			"you should probably start at least one fork server.")
		return
	}

	glbDataPt = startFrkSrvs(target, frkSrvNb, args)

	// Really need that test considering we already test frkSrvNb and errors in
	// called functions are fatal?
	if len(glbDataPt.puts) < 1 {
		return
	}

	// **** Running all seeds ****
	unfilteredSeedPts := runInputs(glbDataPt.puts, givenSeeds)

	var listMtx sync.Mutex // Mutex on seed slice.
	var seedPts seedList
	var wg sync.WaitGroup
	seedMap := make(map[uint64]struct{})

	for _, seedPt := range unfilteredSeedPts {
		wg.Add(1)
		go analyzeNewSeeds(glbDataPt, seedPt, &seedPts, seedMap, &listMtx, &wg)
	}
	wg.Wait()

	// If there is no valuable seed, go with an empty seed.
	if len(seedPts) == 0 {
		put := glbDataPt.puts[0]
		seed := makeEmptySeed(put)
		seedPts = seedList{&seed}
	}

	glbDataPt.seedPts = seedPts
	return glbDataPt
}

func analyzeNewSeeds(glbDataPt *PUT, seedPt *seedT, seedPtsPt *seedList,
	seedMap map[uint64]struct{}, listMtx *sync.Mutex, wg *sync.WaitGroup) {

	defer wg.Done()

	if seedPt.info.crashed {
		fmt.Println("Please do no provide crashing seeds.")
		return
	}

	seedPt.setTrSize()
	// Accept all seeds, except if have the exact same hash as another one.
	listMtx.Lock()

	if _, ok := seedMap[seedPt.hash]; ok {
		listMtx.Unlock()
		return
	}
	seedMap[seedPt.hash] = struct{}{}

	// Add seed to the list
	*seedPtsPt = append(*seedPtsPt, seedPt)
	listMtx.Unlock()
}

func startFrkSrvs(target string, frkSrvNb int, args Arguments) (glbDataPt *PUT) {
	if sHand == nil {
		StopSoon = make(chan struct{}, sHandBufSize)
		sHand = &signalHandler{}
	}
	sHand.addFrkSrvNb(frkSrvNb)

	baseName := filepath.Base(target)
	glbDataPt = newGlbData(frkSrvNb, baseName, args)
	glbDataPt.rawExec = makeRawExec(target, args)

	usedCPUs := GetUsedCPUs()
	startPUTChan := make(chan bool)
	for i := 0; i < frkSrvNb; i++ {
		go glbDataPt.puts[i].startFrkSrv(target, args, startPUTChan, usedCPUs)
		succeded := <-startPUTChan
		if !succeded {
			log.Print("Problem in starting frk srv")
			initProblem = true
			return
		}

		name := fmt.Sprintf("%s-%d", baseName, i)
		glbDataPt.puts[i].name = name
		if debug {
			fmt.Printf("Started %s.\n", name)
		}
	}

	return glbDataPt
}

func endFuzzing(glbDataPt *PUT) {
	puts := glbDataPt.puts
	initMtx.Lock()
	sHand.addFrkSrvNb(-len(puts))
	initMtx.Unlock()
	//
	for i := range puts {
		puts[i].destroy()
	}

	glbRnds = []float64{}
	glbGains = []float64{}

	if len(puts) == 0 {
		return
	}

	if useStep1bench && debug {
		close(step1MutTChan)
		step1MutWG.Wait()
	}
}

/******************************************************************************/
/***************************** Fork Server methods ****************************/

func (put *frkSrv) startFrkSrv(target string, args Arguments,
	startPUTChan chan<- bool, usedCPUs []bool) {

	var origSet unix.CPUSet
	if !unicore {
		origSet = lockRoutine(usedCPUs)
	}

	// Make a copy of argv because prepareProcAttr modifies it if the PUT
	// input is a file.
	frkSrvArgs := args
	argv := make([]string, len(args.Argv))
	copy(argv, args.Argv)
	frkSrvArgs.Argv = argv

	put.shmID, put.traceBits = setupShm()
	var procAttr *syscall.ProcAttr
	procAttr, put.tcWriter = prepareProcAttr(put.shmID, frkSrvArgs)
	put.ctlPipeW, put.stPipeR, put.pid = initForkserver(target, procAttr, frkSrvArgs)

	if put.ctlPipeW == nil || put.stPipeR == nil {
		startPUTChan <- false
		return
	}

	put.rndRep = new(rndReport)
	put.rndChan = make(chan func())
	put.traceBitPool = newBytePool()

	if debug {
		put.handleStates()
	}

	startPUTChan <- true

	// PUT created. Start listening
	for f := range put.rndChan {
		f()
	}

	// Closing. Clearing CPU set by rebinding to all.
	// Do I really need to do this? This thread should die.
	if !unicore {
		err := unix.SchedSetaffinity(0, &origSet)
		if err != nil {
			log.Printf("Could not clear PUT CPU set: %v.\n", err)
		}
	}

	if put.stateChan != nil { // if debug...
		close(put.stateChan)
	}
}

func (put *frkSrv) startDebugTimer(timeout time.Duration) {
	if debug {
		put.debugTimer = time.AfterFunc(2*timeout, func() { put.blocked() })
	}
}
func (put *frkSrv) stopDebugTimer() {
	if debug {
		put.debugTimer.Stop()
	}
}

func (put *frkSrv) handleStates() {
	put.stateChan = make(chan string, 1)
	put.blockedChan = make(chan struct{})

	go func(put *frkSrv) {
		state := "init"
		for put.stateChan != nil {
			select {
			case newState, ok := <-put.stateChan:
				if !ok {
					put.stateChan = nil
				}
				state = newState

			case <-put.blockedChan:
				fmt.Printf("\n!!!Forkserver %s is blocked!!!!\n", put.name)
				fmt.Printf("Current state: %s\n", state)
				fmt.Println("")
			}
		}
	}(put)
}

func (put *frkSrv) setState(str string) {
	if debug && put.stateChan != nil {
		put.stateChan <- str
	}
}

func (put *frkSrv) blocked() {
	if debug {
		put.blockedChan <- struct{}{}
	}
}

func (put *frkSrv) destroy() {
	killAllChildren(put.pid)
	proc, err := os.FindProcess(put.pid)
	if err != nil {
		log.Printf("Could not get fork server process %d: %v.\n", put.pid, err)
	} else {
		err = proc.Kill()
		if err != nil {
			log.Printf("Could not kill fork server: %v.\n", err)
		} else if debug {
			log.Printf("Killed frk srv (pid=%d).\n", put.pid)
		}
	}

	closeShm(put.shmID)
	if put.rndChan != nil {
		close(put.rndChan)
	}

	put.tcWriter.clean()
}

func kill(pid int) { // For debug
	cmd := exec.Command("bash", "-c", "kill", "-9", fmt.Sprintf("%d", pid))
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		log.Printf("Couldn't kill pid=%d: %v.\n", pid, err)
	}
}
func procps(pid int) { // For debug
	cmd := exec.Command("ps", "-ejH", fmt.Sprintf("%d", pid))
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		log.Printf("Error while ps-ing?: %v.\n", err)
	}
}

func killAllChildren(pid int) {
	children := listChildren(pid)
	for _, childPid := range children {
		killAllChildren(childPid)
		proc, err := os.FindProcess(childPid)
		if err != nil {
			log.Printf("Could not find child proc (pid=%d): %v.\n", childPid, err)
			continue
		}
		proc.Kill() // Don't care much if it fails...
	}
}

func listChildren(pid int) (childrenPids []int) {
	pidStr := fmt.Sprintf("%d", pid)
	childrenPath := filepath.Join("/proc", pidStr, "task", pidStr, "children")
	childrenStr, err := ioutil.ReadFile(childrenPath)
	if err != nil {
		log.Printf("Could not read children of %d: %v.\n", pid, err)
		return
	}

	childList := strings.Split(string(childrenStr), " ")
	for _, child := range childList {
		if len(child) == 0 {
			continue
		}
		childPid, err := strconv.Atoi(child)
		if err != nil {
			log.Print(err)
			continue
		}
		childrenPids = append(childrenPids, childPid)
	}

	return childrenPids
}
