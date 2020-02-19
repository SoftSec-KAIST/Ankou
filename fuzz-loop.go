package main

import (
	"fmt"
	"log"

	"encoding/binary"
	"math/rand"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/buger/goterm"
)

var (
	// Making it global so can maybe export it and reproduce the run (assuming
	// PUT is deterministic).
	randSeed    int64
	initMtx     sync.Mutex
	initProblem bool
)

func init() {
	randSeed = time.Now().UTC().UnixNano()
	rand.Seed(randSeed)
}

func main() {
	args := Parse()
	StartFuzz(args, nil)
}

// StartFuzz is the main function. Expects fuzzing arguments, fuzz for the
// specified duration (or until interrupted) and return a report on the fuzzing.
func StartFuzz(args Arguments, endFuzzChan chan struct{}) (endRep EndReport) {
	if endFuzzChan == nil {
		endFuzzChan = stopSHand
	}

	initMtx.Lock()
	initProblem = false
	postParse(&args)
	givenSeeds := loadSeeds(args)
	glbDataPt := initFuzzing(args.Target, args.FrkSrvNb, givenSeeds, args)

	if initProblem {
		log.Println("!!! Problem at initialization. Cannot fuzz :( !!!")
		return endRep
	}

	initMtx.Unlock()

	reporter := makeReporter(args.Target, args.SaveDir, glbDataPt.seedPts)
	fuzzing(glbDataPt, reporter, args.NbRound)

	endFuzzing(glbDataPt)

	if doBenchMut {
		benchHash(glbDataPt.seedPts)
		benchMutDict = glbDataPt.puts[0].dictWords
	}

	if len(glbDataPt.puts) > 0 {
		endRep = endReporting(glbDataPt)
		if verbose || debug {
			report(glbDataPt, endRep)
		}
	}

	endRep.Stopped = sHand.wasInterrupted()
	log.Print("Fuzz end.")
	return endRep
}

// *****************************************************************************
// ***************************** Run Fuzz Functions ****************************
// *****************************************************************************

func fuzzing(glbDataPt *PUT, reporter reporterT, nbRound int) {
	// *****************************************
	// **** I - Fuzzing Loop Initialization ****

	puts := glbDataPt.puts
	if len(puts) == 0 || nbRound == 0 {
		// Cannot fuzz without a fork server
		return
	}

	// Channel where fork servers send execution that they ('personnaly') did
	// not see before.
	chFnd := make(chan finding, 20000)
	// Synchronization between this routine, the seedManager and the receiver.
	wg := sync.WaitGroup{}
	seedsCom, analCom := makeComChans(len(puts))

	go seedManT{seedManChans: seedsCom}.seedManager(glbDataPt, reporter, &wg)
	rec := makePCAReceiver(glbDataPt, analCom, seedsCom.newSeedCh,
		seedsCom.crashChan, chFnd, &wg)
	go rec.receive(reporter)

	glbGenMan := make(globalGeneratorManager)

	goterm.Clear()
	var infiniteFuzz bool
	if nbRound < 0 {
		infiniteFuzz = true
	}

	frkServerArgs := makeFrkSrvArgs(glbDataPt, &wg, chFnd,
		seedsCom.versifier, seedsCom.crosser)

	// ***************************
	// **** II - Fuzzing Loop ****
	// The reason we exist :-)

	for roundNb := 0; roundNb <= nbRound || infiniteFuzz; roundNb++ {
		select {
		case <-StopSoon:
			StopSoon <- struct{}{}
			analCom.reqClear <- struct{}{}
			<-analCom.ackClear
			roundNb = nbRound
			infiniteFuzz = false
			break

		default:
			// Contact receiver.
			analCom.reqClear <- struct{}{}
			// Wait for all test cases from the previous rounds to be finished
			// being processed.
			// Do some work in the meantime.
			for _, rndArgs := range frkServerArgs {
				glbGenMan.update(rndArgs)
			}
			received := <-analCom.ackClear
			dc := received.getDistCalc()
			if r, ok := received.(resetter); ok {
				reset, toRem := r.info()
				if reset {
					resetFrkSrvArgsHashes(frkServerArgs)
				}
				for _, hash := range toRem {
					delete(glbGenMan, hash)
				}
			}

			// Send request to get new seeds to fuzz.
			seedsCom.reqSeeds <- struct{}{}
			selection := <-seedsCom.selected // Receive the seeds to fuzz.

			//showPools(frkServerArgs)

			wg.Add(len(selection))
			for i, seedPt := range selection {
				seedMutRecs := glbGenMan.getSeedMutRecs(seedPt)

				frkServerArgs[i].seedPt = seedPt
				frkServerArgs[i].dc = dc
				rndFunc := frkServerArgs[i].makeRoundFunc(seedMutRecs)
				puts[i].rndChan <- rndFunc
			}

			seedsCom.ackSeeds <- struct{}{}
			wg.Wait()
		}
	}
	goterm.Clear()

	// ************************
	// **** III - Epilogue ****

	wg.Add(1) // Close receiver
	close(chFnd)
	wg.Wait()

	wg.Add(1) // Close seed manager.
	close(seedsCom.reqSeeds)
	wg.Wait()

	glbDataPt.nbHash = rec.getExecMapLen()
}

func makeRoundTimer() (killerChan chan func(), fuzzTimeout chan struct{}) {
	killerChan = make(chan func(), 1) // Buffer so this is non blocking.
	timeOutChan := time.After(RoundTimeout)
	fuzzTimeout = make(chan struct{}, 1)

	go func() {
		kill := func() {}

		var timedOut, done bool
		for !timedOut {
			select {
			case <-timeOutChan:
				kill()
				fuzzTimeout <- struct{}{}
				done = true

			case newKill, ok := <-killerChan:
				if !ok {
					timedOut = true
					break
				}
				kill = newKill

				if done {
					//dbgPr("Receiving killer after timeout.\n")
					kill()
				}
			}
		}
	}()

	return killerChan, fuzzTimeout
}

func makeNullKillerChan() (killerChan chan func()) {
	killerChan = make(chan func(), 10)
	go func() {
		for range killerChan {
		}
	}()
	return killerChan
}

func (roundArgs *rndArgs) runOneRound() {
	var fuzzTimeout chan struct{}

	frkSrvPt := roundArgs.put
	seedPt := roundArgs.seedPt
	ig := roundArgs.ig
	frkSrvPt.rndRep.zero()

	// Test cases hashes. First (short) analysis pass done locally.
	th := makeTCHashes(frkSrvPt, roundArgs)
	locC := new(localMeta)
	timeout := seedPt.timeout()

	locC.killerChan, fuzzTimeout = makeRoundTimer()

	continueFuzzing := true
	for continueFuzzing {
		select {
		case <-fuzzTimeout:
			continueFuzzing = false
		case <-StopSoon:
			StopSoon <- struct{}{}
			continueFuzzing = false

		default:
			testCase, mutRep := ig.generate()
			if len(testCase) == 0 { // Don't execute empty test cases.
				continue
			}

			select { // In case interrupted while mutating.
			case <-fuzzTimeout:
				continueFuzzing = false
				locC.free()
				continue
			default:
			}

			frkSrvPt.startDebugTimer(timeout)
			runInfo, err := runTarget(*frkSrvPt, testCase, timeout, locC.killerChan, true)
			frkSrvPt.rndRep.execs++

			if runInfo.sig == 9 {
				frkSrvPt.rndRep.hangs++
				runInfo.crashed = false
				if err != nil {
					locC.free()
					frkSrvPt.stopDebugTimer()
					continue
				}
			} else if err != nil { // Missing crash here?
				log.Printf("runTarget err = %+v\n", err)
			}

			// Record creation history information
			runInfo.orig = seedPt
			runInfo.depth = seedPt.info.depth + 1
			runInfo.err = err

			// Analysis done on all executions.
			th.shortAnal(runInfo, testCase, mutRep)

			frkSrvPt.stopDebugTimer()
		}
	}

	close(locC.killerChan)
	locC.killerChan = nil

	th.report(frkSrvPt.rndRep)
	ig.epilogue(frkSrvPt.rndRep.execs, seedPt.hash)

	roundArgs.wg.Done()
}

/********************* Run PUT *******************/

// In practice, these are constants. Only read.
var helloChildA = [4]byte{0, 0, 0, 0}
var helloChildS = helloChildA[:]

func runTarget(put frkSrv, testCase []byte, timeout time.Duration,
	killerChan chan func(), first bool) (runInfo runMetaData, err error) {

	put.setState("Init run")
	ctlPipeW := put.ctlPipeW
	stPipeR := put.stPipeR
	zeroShm(put.traceBits)

	if len(testCase) > 0 {
		put.setState(fmt.Sprintf("Write (len: %d)", len(testCase)))
		_, err = put.tcWriter.Write(testCase)
		if err != nil {
			log.Printf("Could not write testCase: %v\n", err)
			return runInfo, err
		}
	} else {
		fmt.Println("Empty testCase.")
	}

	// Start running
	put.setState("Start run")
	_, err = ctlPipeW.Write(helloChildS)
	if err != nil {
		log.Printf("Problem when writing in control pipe: %v\n", err)
		return runInfo, err
	}
	encodedWorkpid := make([]byte, 4)
	_, err = stPipeR.Read(encodedWorkpid)
	if err != nil {
		log.Printf("Problem when reading the status pipe: %v\n", err)
		return runInfo, err
	}
	runInfo.pid = binary.LittleEndian.Uint32(encodedWorkpid)

	// Start timer
	timer := setExecTimer(timeout, int(runInfo.pid))
	killerChan <- func() { killPid(int(runInfo.pid)) }

	// Wait for result
	put.setState("Wait")
	encodedStatus := make([]byte, 4)
	_, err = stPipeR.Read(encodedStatus)
	if err != nil {
		log.Printf("Problem while reading status.\n")
	}
	runInfo.status = binary.LittleEndian.Uint32(encodedStatus)
	runInfo.sig, runInfo.crashed =
		checkStatus(syscall.WaitStatus(runInfo.status))
	put.setState("Done running")

	if runInfo.sig == os.Kill && first {
		// If hanged, try again, once.
		runInfo, err = runTarget(put, testCase, timeout/2, killerChan, false)
	}

	// Stop all timers on place on the execution.
	killerChan <- func() {}
	if !timer.Stop() && runInfo.sig == os.Kill && err == nil {
		runInfo.hanged = true
		errString := fmt.Sprintf("child (pid=%d) hanged", runInfo.pid)
		err = fmt.Errorf(errString)
	}

	put.setState("End runTarget")
	return runInfo, err
}

func setExecTimer(d time.Duration, pid int) (timer *time.Timer) {
	// Ideally, this would be a timer with the launch process CPU time rather
	// than real time. @TODO, but this does not seem possible to do from here.
	// We are grand-pa of running proc so we don't get information. Would have
	// to modify the fork server if I really wanted to do it.
	timer = time.AfterFunc(d, func() {
		p, err := os.FindProcess(pid)
		if err != nil {
			log.Printf("Could not find process (pid=%d): %v\n", pid, err)
			return
		}

		// What if there are child process and such? Might need to be
		// more careful doing this. AFL also just kills though.
		err = p.Kill()

		if err != nil {
			// @TODO: Not sure how to handle a problem in killing the child
			// process. So far only happened when there was a race and child
			// process normally terminated before we killed it.
			//
			// This happens quite often actually :( Are we missing bugs?

			dbgPr("Could not kill process (pid=%d): %v\n", pid, err)
		}
	})

	return timer
}

func killPid(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("Could not find process (pid=%d): %v\n", pid, err)
		return
	}

	// What if there are child process and such? Might need to be
	// more careful doing this. AFL also just kills though.
	err = p.Kill()

	if err != nil {
		// @TODO: Not sure how to handle a problem in killing the child
		// process. So far only happened when there was a race and child
		// process normally terminated before we killed it.
		//
		// This happens quite often actually :( Are we missing bugs?

		dbgPr("Could not kill process (pid=%d): %v\n", pid, err)
	}
}

func checkStatus(status syscall.WaitStatus) (sig syscall.Signal, crashed bool) {
	if status.Signaled() {
		crashed = true
		sig = status.Signal()
	} else if usesMsan && status.ExitStatus() == msanError {
		crashed = true
	}
	return sig, crashed
}

// runInputs outside of the round structure (e.g. for initial seeds).
// Returned seed are not analyzed.
func runInputs(puts []frkSrv, inputs [][]byte) (seedPts seedList) {
	var wg sync.WaitGroup
	var mtx sync.Mutex
	inputChan := make(chan []byte, len(puts)*10)
	killerChan := makeNullKillerChan()

	for _, put := range puts {
		wg.Add(1)
		go func(put frkSrv) {
			for input := range inputChan {
				startRun := time.Now()
				runInfo, err := runTarget(put, input, time.Second, killerChan, true)

				endRun := time.Now()
				runTime := endRun.Sub(startRun)
				// What is done for other seeds
				// Just for initialization. Number we put does not really matter
				// much because the rating is all comparative... Could matter if we
				// have a lot of seeds.
				execTime := float64(runTime / time.Microsecond)

				seed := seedT{info: runInfo, execTime: execTime}
				makeSeed(&seed, input)
				seed.traceBits = make([]byte, len(put.traceBits))
				copy(seed.traceBits, put.traceBits)
				seed.hash = hashTrBits(put.traceBits)

				if err != nil {
					log.Printf("Error runnint seed: %v (t=%v).\n", err, runTime)
					continue
				}

				mtx.Lock()
				seedPts = append(seedPts, &seed)
				mtx.Unlock()
			}
			wg.Done()
		}(put)
	}

	for _, in := range inputs {
		inputChan <- in
	}
	close(inputChan)

	wg.Wait()

	fmt.Printf("len(inputs) = %+v\n", len(inputs))
	fmt.Printf("len(seedPts) = %+v\n", len(seedPts))
	return seedPts
}
