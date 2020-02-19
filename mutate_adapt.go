package main

import (
	"fmt"

	"math"
	"math/rand"
	"sort"
)

// *****************************************************************************
// **************************** Mutation Adaptation ****************************

var adaptiveDecisions = make(map[string]struct{})

type rewardRecord struct{ avg, n float64 }
type seedMutationManager map[string][]rewardRecord
type seedMutationRecords struct { // Manager + extra info needed
	mutMan seedMutationManager
	// Map of hash this seeds triggered. To ensure not counting twice the same.
	hashMap map[uint64]struct{}
	//
	// Special distributions (other are discrete: Bernouilli scheme):
	stackSRec *stackSizeRewards
	//
	hash uint64 // Debug
}
type globalGeneratorManager map[uint64]seedMutationRecords

func makeSeedMutRec(seedLen int, hash uint64, getSeedLen func() int) seedMutationRecords {
	if hash == 0 {
		panic("nil hash??")
	}
	//
	return seedMutationRecords{
		mutMan:    make(seedMutationManager),
		hashMap:   make(map[uint64]struct{}),
		stackSRec: newStackSizeReward(),
		hash:      hash,
	}
}

func (glbGenMan globalGeneratorManager) getSeedMutRecs(
	seedPt *seedT) seedMutationRecords {

	hash := seedPt.hash
	if hash == versiHash || hash == crosserHash {
		return seedMutationRecords{}
	}

	seedMutRecs, ok := glbGenMan[hash]
	if !ok {
		seedMutRecs = makeSeedMutRec(len(seedPt.input), hash, func() int {
			_, l := seedPt.getInputCopy()
			return l
		})
		glbGenMan[hash] = seedMutRecs
		//
		// Default with parent distribution
		if orig := seedPt.info.orig; orig != nil &&
			orig.hash != versiHash && orig.hash != crosserHash {
			parentMutRecs, ok := glbGenMan[orig.hash]
			if ok {
				seedMutRecs = seedMutRecs.inherit(parentMutRecs)
			}
		}
	}
	return seedMutRecs
}

func (glbGenMan globalGeneratorManager) update(roundArgs rndArgs) {
	// *** I - Setup ***
	if !useStacking {
		return
	}
	seedPt := roundArgs.seedPt
	allMutReports := roundArgs.put.rndRep.allMutReports
	if seedPt == nil {
		return
	}

	// *** II - Mutation Adaptation ***
	seedMutRecs, ok := glbGenMan[seedPt.hash]
	if !ok {
		return
	}
	if seedPt.hash == versiHash || seedPt.hash == crosserHash {
		panic("Versifier||Crossover shouldn't get processed by the glbGenMan")
	}
	seedMutMan := seedMutRecs.mutMan
	for hash, reps := range allMutReports {
		if _, ok := seedMutRecs.hashMap[hash]; ok {
			continue
		}
		seedMutRecs.hashMap[hash] = struct{}{}

		for _, rep := range reps {
			if rep.decisionType == scStr {
				seedMutRecs.stackSRec.update(rep)
				continue
			}
			if _, ok := adaptiveDecisions[rep.decisionType]; !ok {
				continue
			}

			rec, ok := seedMutMan[rep.decisionType]
			decision := rep.decision
			if !ok || decision >= len(rec) {
				lenDiff := decision - len(rec) + 1
				rec = append(rec, make([]rewardRecord, lenDiff)...)
			}

			reward := rep.reward
			tmp := rec[decision].avg*rec[decision].n + reward
			rec[decision].n++
			rec[decision].avg = tmp / rec[decision].n

			seedMutMan[rep.decisionType] = rec
		}
	}

	seedMutRecs.stackSRec.newRound(roundArgs.stackMu, roundArgs.put.rndRep.execs)
}

func (seedMutRecs seedMutationRecords) inherit(parent seedMutationRecords) (
	bis seedMutationRecords) {

	bis.hash = seedMutRecs.hash
	// 1. "Simple" mutation decisions:
	bis.mutMan = make(seedMutationManager)

	// 2. Special Distribution: Mutation stacking:
	bis.stackSRec = parent.stackSRec
	seedMutRecs.stackSRec.m = parent.stackSRec.m

	return bis
}

func recToStr(rewRecs []rewardRecord) string {
	var tot float64
	for _, rec := range rewRecs {
		tot += rec.avg
	}
	pr := make([]float64, len(rewRecs))
	for i, rec := range rewRecs {
		pr[i] = 100 * rec.avg / tot
	}
	return fmt.Sprintf("%.2f", pr)
}

// **********************************************
// ******** Stack size reward record ************
// It needs a special structure.

const (
	stackSizeSig float64 = 1.5
	stackSizeRo  float64 = 1 / (stackSizeSig * stackSizeSig)
)

type stackSizeRewards struct {
	// Normal distribution over mu. Prior over log-normal distribution.
	// See compodium of priors:
	// https://www.johndcook.com/CompendiumOfConjugatePriors.pdf
	m, p float64

	rewRecs []rewardRecord
	rounds  regData // x: exp(stackMu+1); y: #execs.
}

func newStackSizeReward() (ssr *stackSizeRewards) {
	ssr = new(stackSizeRewards)
	ssr.m = 2
	ssr.p = 1
	return ssr
}

func (ssr *stackSizeRewards) genStackMu() (stackMu float64) {
	sig := math.Sqrt(1 / ssr.p)
	stackMu = rand.NormFloat64()*sig + ssr.m
	//dbgPr("stackMu: %.3v (#rounds=%d)\n", stackMu, len(ssr.rounds))
	return stackMu
}

func (ssr *stackSizeRewards) newRound(stackMu float64, execs uint) {
	const sigMeanInfluence = stackSizeSig * stackSizeSig / 2
	expected := 1 + math.Exp(stackMu+sigMeanInfluence)
	ssr.rounds = append(ssr.rounds, regPoint{x: expected, y: float64(execs)})

	// Do regression of round expectation (depending on stackMu) by execs.
	if len(ssr.rounds) < 2 { //Not enough data to do a regression
		return
	}
	a, b, _ := ssr.rounds.regression()

	// Adapt mu and p
	var logDataMean, totW float64
	for i, rec := range ssr.rewRecs {
		if rec.n == 0 {
			continue
		}
		i := float64(i)
		weight := a + b*i
		logDataMean += math.Log(i) * weight * rec.avg
		totW += weight * rec.avg
	}
	logDataMean /= totW

	ssr.m = ssr.m*ssr.p + stackSizeRo*logDataMean
	ssr.p += stackSizeRo
	ssr.m /= ssr.p
	//dbgPr("m: %.3v\tp: %.3v\n", ssr.m, ssr.p)
}

func (ssr *stackSizeRewards) update(rep decisionReport) {
	if rep.decision >= len(ssr.rewRecs) {
		lenDiff := rep.decision - len(ssr.rewRecs) + 1
		ssr.rewRecs = append(ssr.rewRecs, make([]rewardRecord, lenDiff)...)
	}

	tmp := ssr.rewRecs[rep.decision].avg*ssr.rewRecs[rep.decision].n + rep.reward
	ssr.rewRecs[rep.decision].n++
	ssr.rewRecs[rep.decision].avg = tmp / ssr.rewRecs[rep.decision].n
}

// *************
// *** Debug ***
func (glbGenMan globalGeneratorManager) avgExpectedStackN() (avgStackN float64) {
	const sigMeanInfluence = stackSizeSig * stackSizeSig / 2
	var n float64

	for _, seedMutRecs := range glbGenMan {
		stackMu := seedMutRecs.stackSRec.m // Most likely stackMu...
		expected := 1 + math.Exp(stackMu+sigMeanInfluence)
		if expected > 1000 {
			continue
		}
		avgStackN += expected
		n++
	}
	avgStackN /= n

	return avgStackN
}
func (glbGenMan globalGeneratorManager) printDecisionTypes() {
	types := make(map[string]struct{})
	for _, seedMutRecs := range glbGenMan {
		mutMan := seedMutRecs.mutMan
		for decType := range mutMan {
			types[decType] = struct{}{}
		}
	}
	//
	var strs []string
	for decType := range types {
		strs = append(strs, decType)
	}
	sort.Strings(strs)
	fmt.Printf("Mutation decision types:\n%s\n", strs)
}

// ****************************************************************************
// ********************************* Decisions ********************************

type decisionReport struct {
	decisionType string
	decision     int
	reward       float64
}

// *****************************************************************************
// ************************ Simple Linear Regression ***************************
// cf. https://en.wikipedia.org/wiki/Simple_linear_regression
type regPoint struct{ x, y float64 }
type regData []regPoint

// y = a + b*x (+ stdErr*NormFloat64() )
func (rd regData) regression() (a, b, stdErr float64) {
	if len(rd) == 0 { // No data
		return math.NaN(), math.NaN(), math.NaN()
	}

	n := float64(len(rd))
	var meanX, meanY float64

	for _, rp := range rd {
		meanX += rp.x
		meanY += rp.y
	}
	meanX /= n
	meanY /= n

	var bDown, bTop float64
	for _, rp := range rd {
		tmpDown := rp.x - meanX
		tmpDown *= tmpDown
		bDown += tmpDown

		bTop += (rp.x - meanX) * (rp.y - meanY)
	}

	b = bTop / bDown
	a = meanY - b*meanX

	if n <= 2 {
		// No need to compute standard error: it's 0 because not enough data.
		return a, b, stdErr
	}

	for _, rp := range rd {
		espI := rp.y - a - b*rp.x
		stdErr += espI * espI
	}
	stdErr /= n - 2
	stdErr /= bDown
	stdErr = math.Sqrt(stdErr)

	return a, b, stdErr
}
