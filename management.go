package main

import (
	"fmt"

	"math/rand"
	"sync"
)

type analyzerI interface {
	// Called for all new test cases (with new hash).
	isFit(seed *seedT, orgHash uint64) bool
	// Called at the end of each round.
	roundEnd()

	distCalcGetter

	cull([]uint64)

	// Verbose and/or debug
	makeRecStatus() recStatus
	epilogue(progName string)
	String() string
}

var _ analyzerI = new(pcaAnalyzer)

// *****************************************************************************
// ****************************** PCA Receiver *********************************
// Receiver made for the PCA-Learner as a fitness function. This is the second
// iteration of the receiver. Many things were tried with the first one, so it
// was getting too messy.

type tcPCAReceiver struct {
	waitAnals  *sync.WaitGroup
	execHashes map[uint64]struct{}

	newSeedChan  chan<- *seedT
	mainThreadWG *sync.WaitGroup
	chFnd        <-chan finding
	analCom      recChans

	// Crash analysis
	crashChan chan<- *seedT
	crashAnal aflCrashAnalyzer

	// Seed analysis based on PCA
	analyzer analyzerI

	// Reset/cull seeds channel.
	pcaCullCh chan []uint64

	frkSrvNb int
	round    int
	progName string
}

func (rec tcPCAReceiver) getExecMapLen() int { return len(rec.execHashes) }

type recClearer struct {
	distCalcGetter
	wasReset bool
	toRem    []uint64
}

func (rc recClearer) info() (bool, []uint64) { return rc.wasReset, rc.toRem }

func makePCAReceiver(glbDataPt *PUT, analCom recChans, newSeedChan,
	crashChan chan<- *seedT, chFnd <-chan finding, wg *sync.WaitGroup) (
	rec tcPCAReceiver) {

	rec.progName = glbDataPt.progName
	rec.frkSrvNb = len(glbDataPt.puts)
	rec.waitAnals = new(sync.WaitGroup)
	rec.execHashes = make(map[uint64]struct{})
	rec.newSeedChan = newSeedChan
	rec.analCom = analCom
	rec.chFnd = chFnd
	rec.mainThreadWG = wg

	rec.crashChan = crashChan
	rec.crashAnal = makeAFLCrashAnalyzer()

	rec.pcaCullCh = make(chan []uint64, 1)

	rec.analyzer = newPCAAnalyzer(rec.analCom.getSeedList(), rec.pcaCullCh, rec.frkSrvNb)

	return rec
}

func (rec tcPCAReceiver) receive(reporter reporterT) {
	var roundFindings []finding
	var wasReset bool
	var toRemSend []uint64

	for rec.chFnd != nil {
		select {
		case newFinding, ok := <-rec.chFnd:
			if !ok {
				rec.chFnd = nil
				break
			}

			if !unicore {
				rec.newFindingAnalysis(newFinding)
			} else {
				roundFindings = append(roundFindings, newFinding)
			}

		case <-rec.analCom.reqClear:
			for len(rec.chFnd) > 0 { // Make sure we finished anlyzing all test cases.
				newFinding := <-rec.chFnd
				rec.newFindingAnalysis(newFinding)
			}
			if unicore {
				for _, newFinding := range roundFindings {
					rec.newFindingAnalysis(newFinding)
				}
				roundFindings = nil // Reset to zero.
			}
			rec.waitAnals.Wait()

			if (verbose || debug) && len(rec.analCom.recInfoChan) == 0 {
				rec.analCom.recInfoChan <- rec.String() + "\n"
			}
			rec.analyzer.roundEnd()
			rec.analCom.ackClear <- recClearer{
				distCalcGetter: rec.analyzer,
				wasReset:       wasReset,
				toRem:          toRemSend,
			}
			wasReset = false
			toRemSend = nil
			//
			var statRec statusRecorder = rec.analyzer
			if rand.Intn(csvWritingPeriod) == 0 {
				reporter.logCSV(recName, statRec.makeRecStatus())
			}

			rec.round++

		case toRem := <-rec.pcaCullCh:
			rec.execHashes = make(map[uint64]struct{})
			rec.analyzer.cull(toRem)
			rec.analCom.seedManCullCh <- toRem
			//
			// Will send to main fuzzing loop.
			wasReset = true
			toRemSend = append(toRemSend, toRem...)
		}
	}

	if false {
		rec.analyzer.epilogue(rec.progName)
	}
	fmt.Println("End of receiving routine.")

	rec.mainThreadWG.Done()
}

func (rec *tcPCAReceiver) newFindingAnalysis(newFinding finding) {
	newSeedPt := newFinding.seedPt
	if _, ok := rec.execHashes[newSeedPt.hash]; ok { // Already observed
		newSeedPt.clean()
		return
	}
	rec.execHashes[newSeedPt.hash] = struct{}{}

	if newSeedPt.info.crashed {
		rec.waitAnals.Add(1)
		newSeedPt.pf.add(1)
		go func() {
			if rec.crashAnal.isCrash(newSeedPt) {
				newSeedPt.setTrSize()
				makeSeed(newSeedPt, newFinding.testCase)
				rec.crashChan <- newSeedPt
			} else {
				newSeedPt.clean()
			}
			rec.waitAnals.Done()
		}()
	}

	rec.waitAnals.Add(1)
	go func() {
		var orgHash uint64
		orig := newSeedPt.info.orig
		if orig != nil {
			orgHash = orig.hash
		}
		//
		if rec.analyzer.isFit(newSeedPt, orgHash) {
			newSeedPt.setTrSize()
			makeSeed(newSeedPt, newFinding.testCase)
			rec.newSeedChan <- newSeedPt
		} else {
			newSeedPt.clean()
		}

		rec.waitAnals.Done()
	}()
}

// ** Visualization **
func (rec tcPCAReceiver) String() (str string) { return rec.analyzer.String() }

// *****************************************************************************
// ***************************** Seed Manager **********************************
// *****************************************************************************
// The seed manager is in charge of:
// - Maintain the seed and crash list
// - Record information from last round
// - Chose seeds for next round
// - Since this routine is in charge of the seed list, other cannot read it.
//   So sends a copy of the seed list upon request.
// - Also, if we use a model and we are training, update the model when a new
//   one is sent. (Probably going to remove that.)

type seedManT struct {
	seedManChans

	previousSeedPts seedList
	roundNb         int
	stoppedFuzz     bool

	covMap     map[int]struct{}
	verseQueue [][]byte // To update versifier. Emptied once processed.
}

func (seedMan seedManT) seedManager(glbDataPt *PUT, reporter reporterT,
	wg *sync.WaitGroup) {

	var oldSeeds seedList
	seedMan.covMap = make(map[int]struct{})
	seedSelector := glbDataPt.seedSelector
	if useVersifier {
		seedSelector = makeVersiSelector(len(glbDataPt.puts), seedSelector,
			seedMan.versifier, seedMan.crosser)
	}
	selection := seedSelector.seedSelect(glbDataPt.seedPts)
	glbInfo := new(infoRecord)

	for !seedMan.stoppedFuzz {
		select {
		case newCrash := <-seedMan.crashChan:
			glbDataPt.crashes[newCrash.hash] =
				Crash{
					In:        newCrash.input,
					traceBits: newCrash.traceBits,
					HashVal:   newCrash.hash,
					err:       newCrash.info.err,
				}
			go reporter.repCrash(glbDataPt.crashes[newCrash.hash])

		case newSeedPt := <-seedMan.newSeedCh:
			if seedMan.hasNewCov(newSeedPt.traceBits) {
				go reporter.repSeed(newSeedPt)
				seedMan.verseQueue = append(seedMan.verseQueue, newSeedPt.input)
			}
			seedMan.crosser.newSeed(newSeedPt)
			if !evolutivePool {
				continue
			}

			// Set exec time as parent one. Wrong but for initialization.
			// Otherwise, have to calibrate for all new seeds.
			newSeedPt.execTime = newSeedPt.info.orig.execTime
			glbDataPt.seedPts = append(glbDataPt.seedPts, newSeedPt)
			//checkSeedPts(glbDataPt.seedPts)

		// Send a copy of the seed list to the routine in charge of computing
		// distance between seeds.
		case <-seedMan.reqSeedPts:
			seedMan.seedPtsChan <- glbDataPt.seedPts.cpy()

		case toRem := <-seedMan.cullCh:
			for len(seedMan.newSeedCh) > 0 { // Empty the seed queue.
				newSeedPt := <-seedMan.newSeedCh
				newSeedPt.execTime = newSeedPt.info.orig.execTime
				glbDataPt.seedPts = append(glbDataPt.seedPts, newSeedPt)
			}
			go seedMan.crosser.cullSeeds(toRem)
			if culler, ok := seedSelector.(culler); ok {
				culler.cull(toRem)
			}
			glbDataPt.seedPts, oldSeeds = cullSeedList(glbDataPt.seedPts, oldSeeds, toRem)
			pruneSeedTree(glbDataPt.seedPts)

		// Main fuzzing loop request seeds.
		case _, ok := <-seedMan.reqSeeds:
			if !ok {
				seedMan.stoppedFuzz = true
				break
			}

			seedMan.updateVerse()
			seedMan.verseQueue = nil
			glbInfo.endRoundRecording(seedMan.previousSeedPts, glbDataPt)

			copiedSeedPts := make(seedList, len(selection))
			copy(copiedSeedPts, selection)
			if !unicore {
				// If only access to one core, wants more synchronization
				// between the (unique) fork server we have and the seed
				// manager. In this case, making the fork server wait does not
				// waste any ressource.
				seedMan.selected <- copiedSeedPts
				<-seedMan.ackSeeds
			}

			// Actualise seed selection. But will need the previous set to
			// record info that is currently being fuzzed.
			seedMan.previousSeedPts = selection
			oldSeeds = cleanOldSeeds(oldSeeds)
			selection = seedSelector.seedSelect(glbDataPt.seedPts)
			if unicore {
				seedMan.selected <- copiedSeedPts
				<-seedMan.ackSeeds
			}

			if verbose || debug {
				var extraStr string
				if len(seedMan.recInfoChan) > 0 {
					extraStr = <-seedMan.recInfoChan
				}

				if verbose {
					glbInfo.printStatus(
						seedMan.roundNb, glbDataPt, extraStr, selection)
					seedMan.roundNb++
				}
			}
			if rand.Intn(csvWritingPeriod) == 0 {
				reporter.logCSV(smName, makeSMStatus(glbDataPt.seedPts, glbInfo.execNb))
			}
		}
	}

	wg.Done()
}

func (seedMan seedManT) hasNewCov(trace []byte) (has bool) {
	for i, tr := range trace {
		if tr > 0 {
			if _, ok := seedMan.covMap[i]; !ok {
				has = true
				seedMan.covMap[i] = struct{}{}
			}
		}
	}
	return has
}

func (seedMan seedManT) updateVerse() {
	if !useVersifier {
		return
	}

	var wg sync.WaitGroup
	newVerses := make([]*verse, len(seedMan.verseQueue))

	wg.Add(len(seedMan.verseQueue))
	for i, input := range seedMan.verseQueue {
		go func(i int, input []byte) {

			newVerses[i] = buildVerse(input)

			wg.Done()
		}(i, input)
	}
	wg.Wait()

	for _, v := range newVerses {
		if v == nil {
			continue
		}
		//
		seedMan.versifier.blocks = append(seedMan.versifier.blocks,
			v.blocks...)
		seedMan.versifier.allNodes = append(seedMan.versifier.allNodes,
			v.allNodes...)
	}
}

func cullSeedList(seedPts, os seedList, toRem []uint64) (newList, oldSeeds seedList) {
	oldSeeds = os
	hashmap := make(map[uint64]struct{})
	for _, hash := range toRem {
		hashmap[hash] = struct{}{}
	}
	for _, seedPt := range seedPts {
		if _, ok := hashmap[seedPt.hash]; !ok {
			newList = append(newList, seedPt)
		} else {
			oldSeeds = append(oldSeeds, seedPt)
		}
	}
	return newList, oldSeeds
}
func cleanOldSeeds(oldSeeds seedList) seedList {
	for _, seedPt := range oldSeeds {
		//seedPt.input = nil
		seedPt.traceBits = nil
	}
	return nil
}

// *************
// For debug. Check if seed list has two seeds with the same hash.
func checkSeedPts(seedPts seedList) {
	if !debug {
		return
	}

	seedCnt := make(map[uint64]uint)
	for _, seedPt := range seedPts {
		seedCnt[seedPt.hash] = 0
	}
	for _, seedPt := range seedPts {
		seedCnt[seedPt.hash]++
	}

	doubleSeed := make(map[uint64]struct{})
	for hash, cnt := range seedCnt {
		if cnt > 1 {
			doubleSeed[hash] = struct{}{}
		}
	}
	if len(doubleSeed) > 0 {
		panic(fmt.Sprintf("Exists double seeds: %d", len(doubleSeed)))
	}
}
func checkSeedCull(seedPts seedList, toRem []uint64, beforeLen int) {
	if len(seedPts)+len(toRem) != beforeLen {
		fmt.Printf("len(seedPts) = %+v\n", len(seedPts))
		fmt.Printf("len(toRem) = %+v\n", len(toRem))
		fmt.Printf("beforeLen = %+v\n", beforeLen)
		panic("wrong culling")
	}
}

/******************************************************************************/
/************************** End of round recording ****************************/

type infoRecord struct {
	execNb  uint
	roundNb uint
}

func (i *infoRecord) throughput() float64 {
	return float64(i.execNb) / float64(i.roundNb)
}

func (glbInfo *infoRecord) endRoundRecording(selection seedList, glbDataPt *PUT) {
	if len(selection) == 0 {
		return
	}

	puts := glbDataPt.puts
	glbDataPt.totalHangs = 0

	for i, seedPt := range selection {
		rndRep := puts[i].rndRep

		// Recording seed features from last round.
		seedPt.roundNb++
		seedPt.execNb += rndRep.execs
		seedPt.hangNb += rndRep.hangs
		seedPt.cntLoops(glbDataPt.seedLoops, rndRep.loopNb)
		seedPt.setExecTime(glbDataPt.rawExec)
		//
		glbInfo.execNb += rndRep.execs
		glbInfo.roundNb++

		// Updating 'global' fuzzing state.
		glbDataPt.totalHangs += rndRep.hangs
		glbDataPt.totalRoundNb++
	}
}

// count loops; i.e. number of time a mutated seed trigger the exact same path
// in the programm as a seed.
func (seedPt *seedT) cntLoops(seedLoops map[uint64]uint, seedLoopNb uint) {
	if _, ok := seedLoops[seedPt.hash]; ok {
		seedLoops[seedPt.hash] += seedLoopNb
	} else {
		seedLoops[seedPt.hash] = seedLoopNb
	}
}

// ***************** Util ******************
// ******* MultiThreaded Wait Group ********
// Work around the fact that cannot wait from different threads.
type multiWG struct {
	wg       *sync.WaitGroup
	req, ack chan struct{}
	newAdd   chan struct{}
}

func makeMultiWG() (mwg multiWG) {
	mwg.wg = new(sync.WaitGroup)
	mwg.req = make(chan struct{})
	mwg.ack = make(chan struct{})
	mwg.newAdd = make(chan struct{})

	go func() {
		var needToWait bool

		for {
			select {
			case <-mwg.req:
				if needToWait {
					mwg.wg.Wait()
					needToWait = false
				}
				mwg.ack <- struct{}{}

			case <-mwg.newAdd:
				needToWait = true
			}
		}
	}()

	return mwg
}

func (mwg multiWG) add(delta int) { mwg.wg.Add(delta) }
func (mwg multiWG) done() {
	mwg.newAdd <- struct{}{}
	mwg.wg.Done()
}
func (mwg multiWG) wait() {
	mwg.req <- struct{}{}
	<-mwg.ack
}
