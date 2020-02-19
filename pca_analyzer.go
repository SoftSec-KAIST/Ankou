package main

import (
	"fmt"
	"log"

	"math"
	"math/rand"
	"sync"
)

// *****************************************************************************
// ******************* PCA Based seed test case analysis ***********************

type pcaAnalyzer struct {
	mtx    sync.RWMutex
	brMap  map[int]struct{}
	brList []int

	pl *pcaLearner

	// Internal seed copy
	seedsMtx         *sync.Mutex
	seedPts          *seedList
	acceptedSeedHist []int

	// Communication with seed manager: PCA features
	featMtx sync.Mutex
	feats   map[uint64]*pcaFeatures

	// Reset/cull seeds channel.
	pcaCullCh chan []uint64

	frkSrvNb int
}

func newPCAAnalyzer(seedPts seedList, pcaCullCh chan []uint64, frkSrvNb int) (
	pcaA *pcaAnalyzer) {

	pcaA = new(pcaAnalyzer)
	pcaA.brMap = make(map[int]struct{})

	pcaA.seedsMtx = new(sync.Mutex)
	pcaA.seedPts = new(seedList)
	*pcaA.seedPts = seedPts

	pcaA.feats = make(map[uint64]*pcaFeatures)
	for _, seedPt := range seedPts {
		feat := new(pcaFeatures)
		seedPt.pcaFeat = feat
		pcaA.feats[seedPt.hash] = feat
	}

	pcaA.pcaCullCh = pcaCullCh
	pcaA.frkSrvNb = frkSrvNb

	return pcaA
}

func (pcaA *pcaAnalyzer) isFit(seed *seedT, orgHash uint64) bool {
	var ok, newBranch, pcaAccepted bool
	var traceBits []byte = seed.getTrace()

	// Check if it has new branch.
	pcaA.mtx.RLock()
	for i, tr := range traceBits {
		if tr > 0 {
			if _, ok = pcaA.brMap[i]; !ok {
				newBranch = true
				break
			}
		}
	}
	pcaA.mtx.RUnlock()

	// If no new branch, see if the PCA Live Tester "finds" it new.
	if !newBranch {
		if pcaA.pl != nil {
			// pcaLiveAnalyzer handles its own concurrency; so we can return
			// directly after call no matter the result (accepted or not).
			pcaAccepted = pcaA.pl.newObs(traceBits, orgHash)
			// !!! For test !!!!
			// If want to make the PCA-Learner a "static" observer".
			//pcaAccepted = false
		}
		if !pcaAccepted && !newBranch {
			return false
		}
	}
	newBranch = false

	pcaA.mtx.Lock()
	// Unfortunately, if we want everyone to be able to read before we get
	// the write lock, we have to do this scoring twice.
	for i, tr := range traceBits {
		if tr > 0 {
			if _, ok = pcaA.brMap[i]; !ok {
				newBranch = true
				pcaA.brMap[i] = struct{}{}
				pcaA.brList = append(pcaA.brList, i)
			}
		}
	}
	pcaA.mtx.Unlock()

	// Accepted because new branch and not because because PCA, so need to tell
	// the PCA-Learner this input will be added to the seed pool.
	if !pcaAccepted && pcaA.pl != nil {
		if newBranch {
			pcaA.pl.addNewSeed(traceBits)
		}
	}

	if newBranch && pcaA.pl == nil {
		// Just need to keep track of seeds until PCA initialization.
		pcaA.seedsMtx.Lock()
		*pcaA.seedPts = append(*pcaA.seedPts, seed)
		pcaA.seedsMtx.Unlock()
	}

	res := newBranch || pcaAccepted
	if res {
		pcaA.newPCAFeatures(seed)
	}
	return res
}

// pcaAnalyzer complies with the distCalcGetter interface.
func (pcaA *pcaAnalyzer) getDistCalc() distCalculator {
	if len(pcaA.brList) > 0 {
		return distCalculator(pcaA.brList)
	}
	// Not initilized yet
	return makeDefaultDistCalculator().getDistCalc()
}

// *****************************************************************************
// ************************** Interface Compliance *****************************

func (pcaA *pcaAnalyzer) roundEnd() {
	pcaA.updateFeats()
	pcaA.mayStartPCA()
}

func (pcaA *pcaAnalyzer) epilogue(progName string) {
	if pcaA.pl != nil {
		pcaA.pl.epilogue(progName)
	}
}

func (pcaA *pcaAnalyzer) String() (str string) {
	pcaA.mtx.RLock()
	edgeN := float64(len(pcaA.brList))
	str = fmt.Sprintf("#edges: %.3v (%.02f%%)", edgeN, 100*edgeN/mapSize)
	//
	if pcaA.pl != nil {
		str += fmt.Sprintf(" - %s", pcaA.pl.String())
	}
	pcaA.mtx.RUnlock()
	//
	return str
}

// *****************************************************************************
// ************************* PCA Learner Initiatlization ***********************

func (pcaA *pcaAnalyzer) mayStartPCA() {
	if pcaA.pl != nil {
		return
	}

	seedAcptRate := pcaA.updateSeedNHistory()
	if !noPCAstart && seedAcptRate < .1 && len(*pcaA.seedPts) > pcaSubDim {
		ok, pl := newPCALearner(*pcaA.seedPts, pcaA.pcaCullCh, pcaA.frkSrvNb)
		if ok {
			pcaA.pl = pl
			*pcaA.seedPts = nil // Don't need to keep track of seeds anymore.
		}
	}

	dbgPr("Len of receiver seed list: %d.\n", len(*pcaA.seedPts))
}

func (pcaA *pcaAnalyzer) updateSeedNHistory() (rate float64) {
	const histLenMax = 500
	n := len(*pcaA.seedPts)
	for i := 0; i < pcaA.frkSrvNb; i++ {
		pcaA.acceptedSeedHist = append(pcaA.acceptedSeedHist, n)
	}

	histLen := len(pcaA.acceptedSeedHist)
	if histLen > histLenMax { // After init, always shorten the slice.
		pcaA.acceptedSeedHist = pcaA.acceptedSeedHist[histLen-histLenMax:]
		histLen = histLenMax
		//
		// Randomly reset the slice so it doesn't get too long. All truncunted
		// part is kept in memory otherwise.
		if rand.Intn(1000) == 0 {
			tmp := make([]int, len(pcaA.acceptedSeedHist))
			copy(tmp, pcaA.acceptedSeedHist)
			pcaA.acceptedSeedHist = tmp
		}
	}

	rate = 1
	if histLen < histLenMax {
		return rate
	}

	rate = float64(pcaA.acceptedSeedHist[histLen-1] - pcaA.acceptedSeedHist[0])
	rate /= float64(histLen)
	if n > 0 {
		rate /= float64(n) / histLenMax
	}
	return rate
}

// *****************************************************************************
// ******************** Communication for seed selection ***********************

// Features of a seed from the PCA that are relevant for seed selection.
type pcaFeatures struct {
	set bool

	minD       float64
	complement bool
	extra      float64
	d2         float64
}

func (pcaA *pcaAnalyzer) newPCAFeatures(seedPt *seedT) {
	if selType != pcaWmoSel {
		return
	}
	feat := new(pcaFeatures)
	seedPt.pcaFeat = feat
	pcaA.featMtx.Lock()
	pcaA.feats[seedPt.hash] = feat
	pcaA.featMtx.Unlock()
}
func (pcaA *pcaAnalyzer) cull(toRem []uint64) { pcaA.cullFeats(toRem) }
func (pcaA *pcaAnalyzer) cullFeats(toRem []uint64) {
	if selType != pcaWmoSel {
		return
	}
	pcaA.featMtx.Lock()
	for _, hash := range toRem {
		delete(pcaA.feats, hash)
	}
	pcaA.featMtx.Unlock()
}

func (pcaA *pcaAnalyzer) updateFeats() {
	if selType != pcaWmoSel {
		return
	}
	pl := pcaA.pl
	if pl == nil || !pl.converged {
		return
	}

	safeSqrt := func(a float64) float64 {
		if a < almostZero {
			return 0
		}
		return math.Sqrt(a)
	}

	pcaA.featMtx.Lock()
	pl.basisMtx.Lock()

	for _, pheno := range pl.phenos {
		hash := pheno.hash
		feat, ok := pcaA.feats[hash]
		if !ok {
			log.Printf("Seed in phenotypes but not in feature map (hash=0x%x).\n", hash)
			feat = new(pcaFeatures)
			pcaA.feats[hash] = feat
		}
		if pheno.extra < 0 {
			pheno.extra = pheno.sqNorm - doSqSum(pheno.proj)
			if pheno.extra < 0 {
				pheno.extra = 0
			}
		}
		//
		*feat = pcaFeatures{
			set:        true,
			minD:       pheno.minD,
			complement: false,
			extra:      safeSqrt(pheno.extra),
			d2:         safeSqrt(calcD2(pheno.proj, pl.vars)),
		}
	}
	//
	for _, pheno := range pl.covComp {
		hash := pheno.hash
		feat, ok := pcaA.feats[hash]
		if !ok {
			log.Printf("Seed in complement but not in feature map (hash=0x%x).\n", hash)
			feat = new(pcaFeatures)
			pcaA.feats[hash] = feat
		}
		if pheno.extra < 0 {
			pheno.extra = pheno.sqNorm - doSqSum(pheno.proj)
			if pheno.extra < 0 {
				pheno.extra = 0
			}
		}
		//
		*feat = pcaFeatures{
			set:        true,
			minD:       0,
			complement: true,
			extra:      safeSqrt(pheno.extra),
			d2:         safeSqrt(calcD2(pheno.proj, pl.vars)),
		}
	}

	pl.basisMtx.Unlock()
	pcaA.featMtx.Unlock()
}
func calcD2(proj []float64, vars []float64) (d2 float64) {
	if len(proj) > len(vars) {
		proj = proj[:len(vars)]
	}
	if len(proj) <= d2Q {
		return d2
	}
	//
	for i, p := range proj {
		d2 += p * p / vars[i]
	}
	return d2
}
