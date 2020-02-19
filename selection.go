package main

import (
	"log"

	"math"
	"math/rand"
)

// Seed selection algorithm.
type selector interface {
	seedSelect(seedList) seedList
}

// Interface implemented by seed selection algorithm if it accepts seeds to be
// removed.
type culler interface {
	cull([]uint64)
}

var (
	_ selector = new(pcaWmoSelector)
	_ selector = randomSelector{}

	_ culler = new(versiSelector)
)

// *****************************************************************************
// *************************** Versified Selector ******************************
// Add the versifier on top of another selector.
//
// Ideally, would have a metric to select between different strategies
// (mutation, versifier, slicing) and optimize for it. But ATM, cannot find one
// I'm happy with. So, hard-wire the versifier on top of another selector.

type versiSelector struct {
	frkSrvNb int
	sel      selector

	// Versifier
	versiSeed *seedT
	versifier *verse

	// Crosser
	crosserSeed *seedT
	crosser     *crossGen
}

func makeVersiSelector(frkSrvNb int, sel selector, v *verse, c *crossGen) selector {
	versiSeed := &seedT{hash: versiHash, execTime: 1e4}
	makeSeed(versiSeed, nil)
	crosserSeed := &seedT{hash: crosserHash, execTime: 1e4}
	makeSeed(crosserSeed, nil)

	return versiSelector{
		frkSrvNb: frkSrvNb,
		sel:      sel,
		//
		versiSeed: versiSeed,
		versifier: v,
		//
		crosserSeed: crosserSeed,
		crosser:     c,
	}
}

func (vs versiSelector) seedSelect(seedPts seedList) (
	selection seedList) {

	useVerse := len(vs.versifier.blocks) > 0
	useCross := vs.crosser.isReady()
	//
	if (useVerse || useCross) && rand.Intn(7) == 0 {
		selection = make(seedList, vs.frkSrvNb)
		if useVerse && useCross {
			for i := range selection {
				if rand.Intn(3) == 0 {
					selection[i] = vs.versiSeed
				} else {
					selection[i] = vs.crosserSeed
				}
			}
		} else if useVerse {
			for i := range selection {
				selection[i] = vs.versiSeed
			}
		} else { // useCross == true
			for i := range selection {
				selection[i] = vs.crosserSeed
			}
		}

	} else {
		selection = vs.sel.seedSelect(seedPts)
	}

	return selection
}

func (vs versiSelector) cull(toRem []uint64) {
	if culler, ok := vs.sel.(culler); ok {
		culler.cull(toRem)
	}
}

// *****************************************************************************
// ************************* PCA Weighted Multi-Objective **********************

type pcaWmoSelector struct {
	frkSrvNb int
}

func newPcaWmoSel(glbDataPt *PUT) *pcaWmoSelector {
	return &pcaWmoSelector{frkSrvNb: len(glbDataPt.puts)}
}

func (sel *pcaWmoSelector) seedSelect(seedPts seedList) (selection seedList) {
	type seedInfo struct {
		score, cumScore float64
		seedPt          *seedT
		feat            *pcaFeatures
	}

	var infos []seedInfo
	var noInfoSeeds seedList
	var maxMinD, maxExtra, maxD2, maxN float64
	for _, seedPt := range seedPts {
		feat := seedPt.pcaFeat
		if feat == nil || !feat.set {
			noInfoSeeds = append(noInfoSeeds, seedPt)
			continue
		}
		//
		if !feat.complement && feat.minD > maxMinD {
			maxMinD = feat.minD
		}
		if feat.extra > maxExtra {
			maxExtra = feat.extra
		}
		if feat.d2 > maxD2 {
			maxD2 = feat.d2
		}
		if n := float64(seedPt.roundNb); n-.1 > maxN {
			maxN = n
		}
		infos = append(infos, seedInfo{seedPt: seedPt, feat: feat})
	}
	//
	if len(infos) < 10 || len(infos) < (9*len(seedPts))/10 {
		//log.Printf("Only %d/%d seeds with PCA features.\n", len(infos), len(seedPts))
		return uniRandSel(seedPts, sel.frkSrvNb)
	}
	if maxN < almostZero {
		maxN++
	}

	var cumScore float64
	for i, info := range infos {
		f := info.feat
		infos[i].score = (f.extra / maxExtra) + (f.d2 / maxD2) +
			(3 * (maxN - float64(info.seedPt.roundNb)) / maxN)
		if f.complement {
			infos[i].score++
		} else {
			infos[i].score += 2 * f.minD / maxMinD
		}
		infos[i].seedPt.score = infos[i].score
		if math.IsNaN(infos[i].score) {
			log.Printf("NaN score for infos[%d], feat: %+v.\n", i, f)
		}
		// Here, potentially, an exponentail on the score.
		infos[i].cumScore = cumScore
		cumScore += infos[i].score
	}
	//
	if math.IsNaN(cumScore) {
		log.Printf("NaN Score: maxMinD=%.3v, maxExtra=%.3v, maxD2=%.3v, maxN=%.3v.\n",
			maxMinD, maxExtra, maxD2, maxN)
		return uniRandSel(seedPts, sel.frkSrvNb)
	}
	//
	selection = make(seedList, sel.frkSrvNb)
	for i := range selection {
		n := rand.Intn(len(seedPts))
		if len(noInfoSeeds) != 0 && n < len(noInfoSeeds) {
			selection[i] = noInfoSeeds[rand.Intn(len(noInfoSeeds))]
			continue
		}
		//
		r := cumScore * rand.Float64()
		for _, info := range infos {
			if r > info.cumScore {
				selection[i] = info.seedPt
				break
			}
		}
		if selection[i] == nil {
			log.Printf("nil selection. r=%.3v, cumScore=%.3v, lastInfoS=%.3v.\n",
				r, cumScore, infos[len(infos)-1].cumScore)
		}
	}

	for _, seedPt := range selection { // Check
		if seedPt == nil {
			panic("PCA WMO chose a nil seed")
		}
	}

	seedPts.scoreSort()
	return selection
}

// *****************************************************************************
// ************************** Seed Random Sel **********************************

type randomSelector struct{ frkSrvNb int }

func makeRandomSel(glbDataPt *PUT) (sel randomSelector) {
	sel.frkSrvNb = len(glbDataPt.puts)
	return sel
}
func (sel randomSelector) seedSelect(seedPts seedList) seedList {
	return uniRandSel(seedPts, sel.frkSrvNb)
}

func uniRandSel(seedPts seedList, frkSrvNb int) (selection seedList) {
	selection = make(seedList, frkSrvNb)
	for i := range selection {
		index := rand.Intn(len(seedPts))
		selection[i] = seedPts[index]
	}
	return selection
}
