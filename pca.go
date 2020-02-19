package main

import (
	"fmt"
	"log"

	"math"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"gonum.org/v1/gonum/floats"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat"

	"encoding/csv"
	"path/filepath"
)

const (
	// These constants decides how much dimensions we use to project each
	// sample. In other words, it decides the maximum amount of information is
	// used per sample.
	pcaSubDim    = 20
	pcaMaxDim    = 40
	pcaTryMaxDim = pcaMaxDim + 20
	d2Q          = 5

	// These constants decides
	d1Floor  = 2.5
	sinFloor = 0.7
	minMDDiv = 5
	eMeanFlr = 3 // Minimum mean cumulation to recenter.
	minFloor = 3

	// Maximal number of seeds to use in the initial PCA.
	// For speed (PCA algorithm is in O(n**2)).
	initPCAPhenoN = 1000
	// To trigger of phenotypes/seeds culling. This is the maximum number of seeds
	// accepted in phenotype space (more allowed to grow coverage).
	maxPhenoN = 1000
)

// *****************************************************************************
// ******************************* PCA Learner *********************************
// Two goals:
// 1. Learn a basis of components that is "suitable" for inputs. Meaning, most
//    of the variance is in the space defined by this basis.
// 2. Using this basis, detecting "outsiders" inputs (i.e. fitness function).
//
// Basis learning implies:
// a. Keeping track of the covariances and means of each component.
// b. If an input does not project well on the basis, add it to the basis.
//
// Design of the structure usage is:
// - newObs is going to do *read*-only operations.
// - All writes are done by the listening goroutine.

type pcaLearner struct {
	basisMtx sync.RWMutex // Mutex on component basis. Also protect seed list.

	// Basis: projection = (trace - centers) * projector
	centers   [mapSize]float64
	projector *mat.Dense

	// Indicate whether or not the PCA-Learner has converged to a stable basis
	// to "accurately" describe the observed samples.
	// This is just an initialization parameter. Once it converges, the
	// PCA-Learner is going to be used to select new seeds, hence modifying the
	// observed distribution of samples (thus making the basis less adapted and
	// accurate).
	converged bool
	// Distance floor: if a test case minimum distance to seeds is above this
	// floor, then it is considered an outsider. Called "in" because in the
	// space defined by the basis.
	dFloor float64
	// "Out Floor": if the extra space norm of a phenotype is above this floor,
	// then it used (via Gram-Schmidt) as a new component.
	oFloor float64

	// Statistics
	statChan         chan pcaSample
	vars, stds       []float64
	totVar, extraVar float64
	// For reporting: the variances ("vars") above has a higher bound.
	trueVars []float64

	// Phenotype correspond to the seed used by the mutators and that are
	// schedule. From the point of view of the fitness module (i.e. here), they
	// are "phenotype" (behaviour expression measured via AFL bitmap, here
	// called trace), that correspond to their "genetype" (the input,
	// represented as a slice of bytes).
	//
	// Divided in three sets:
	// 1. Phenotypes defining what we "cover" in the space defined by the basis
	// learned by the PCA-Learner.
	phenos []phenotype
	// 2. The complement used by the alternative part of the fitness function.
	// ATM, this is branch coverage. We don't want to lose access to any branch.
	// Could also be AFL tuple, but afraid that'd be too much seeds to handle.
	covComp []phenotype
	// 3. Phenotypes that should be thrown away soon. Throwing them away one by
	// one (as they come) would be expensive because we have to make sure we
	// don't lose any coverage while doing so.
	phenoTrash []phenotype

	// Throughput/rate regulation
	// Have a regulator local to the listener. It sets the rate.
	rate int

	// Reset/cull
	cullCh chan []uint64

	// Debug
	reqDebugInfo chan string // Request to the listener routine.
	endDebug     chan struct{}
	//
	startT time.Time
	adjs   []pcaAdjusment
}

type phenotype struct {
	trace  []byte
	sqNorm float64   // Square of the norm of the original vector.
	proj   []float64 // Projection on current basis.
	extra  float64   // Extra space value: norm of what's not projected.
	hash   uint64

	// Minimum distance data: to keep track of how we "cover" the space.
	// The PCA-Learner dFloor is then set the minimum intra-distance of the
	// phenotypes.
	minD      float64
	closeHash uint64 // Corresponding phenotype hash for identification.
}

// Log type.
type pcaAdjusment struct {
	t             time.Duration
	nbPC, phenoN  int
	dFloor        float64
	centeringNorm float64
	convCrit      float64
	converged     bool
	//
	extra     float64
	extraCrit float64
}

func newPCALearner(seedPts seedList, cullCh chan []uint64, frkSrvNb int) (
	ok bool, pl *pcaLearner) {

	pl = new(pcaLearner)
	if len(seedPts) == 0 {
		return ok, pl
	}
	pl.cullCh = cullCh

	// ** 1. Seeds into the right format. **
	seedMat := mat.NewDense(len(seedPts), mapSize, nil)
	for i, seedPt := range seedPts {
		for j, tr := range seedPt.traceBits {
			seedMat.Set(i, j, logVals[tr])
		}
	}

	// ** 2. Center **
	for i := 0; i < mapSize; i++ {
		col := mat.Col(nil, i, seedMat)
		m := stat.Mean(col, nil)
		pl.centers[i] = m
		floats.AddConst(-m, col)
		seedMat.SetCol(i, col)
	}
	//
	pl.phenos = make([]phenotype, len(seedPts))
	for i := range pl.phenos {
		pl.phenos[i].trace = seedPts[i].traceBits
		org := seedMat.RawRowView(i)
		for _, p := range org {
			pl.phenos[i].sqNorm += p * p
		}
	}

	// ** 3. PCA **
	pcaMat := seedMat
	if len(seedPts) > initPCAPhenoN {
		pcaMat = mat.NewDense(initPCAPhenoN, mapSize, nil)
		perm := rand.Perm(len(seedPts))[:initPCAPhenoN]
		for pcaI, seedI := range perm {
			pcaMat.SetRow(pcaI, seedMat.RawRowView(seedI))
		}
	}
	//
	var pc stat.PC
	ok = pc.PrincipalComponents(pcaMat, nil)
	if !ok {
		return ok, pl
	}

	// ** 4. Prepare structure **
	// a. projector
	vecs := new(mat.Dense)
	pc.VectorsTo(vecs)
	pl.projector = mat.DenseCopyOf(vecs.Slice(0, mapSize, 0, pcaSubDim))
	// b. seed projections
	projections := new(mat.Dense)
	projections.Mul(seedMat, pl.projector)
	traceN, _ := projections.Dims()
	for i := 0; i < traceN; i++ {
		projOrg := mat.Row(nil, i, projections)
		pl.phenos[i].proj = make([]float64, len(projOrg))
		copy(pl.phenos[i].proj, projOrg)
		pl.phenos[i].extra = pl.phenos[i].sqNorm
		pl.phenos[i].extra -= doSqSum(pl.phenos[i].proj)
		pl.phenos[i].hash = seedPts[i].hash
	}

	// ** 5. Statistics Initialization **
	pl.dFloor = minFloor
	//
	pl.vars = pc.VarsTo(nil)
	pl.stds = make([]float64, pcaSubDim)
	for i, v := range pl.vars {
		pl.totVar += v
		if i < pcaSubDim {
			pl.stds[i] = math.Sqrt(v)
		} else {
			pl.extraVar += v
		}
	}
	if len(pl.vars) > pcaSubDim {
		pl.vars = pl.vars[:pcaSubDim]
	}
	pl.oFloor = math.Sqrt(d1Floor * pl.extraVar)

	// Start statistic collecting routine.
	pl.statChan = make(chan pcaSample, 1000)
	pl.reqDebugInfo = make(chan string)
	pl.endDebug = make(chan struct{})
	go pl.listenStats(frkSrvNb)

	pl.startT = time.Now() // For collecting debug info.

	return ok, pl
}

// To call on all executed inputs.
func (pl *pcaLearner) newObs(trace []byte, orgHash uint64) bool {
	pl.basisMtx.RLock()

	// ** 0. Rate Regulation **
	// If receive too many observation, skip some.
	if useRateReg && pl.rate > throughputThreshold {
		random := rand.Intn(pl.rate)
		if random >= throughputThreshold {
			pl.basisMtx.RUnlock()
			return false
		}
	}

	// ** 1. Project the trace **
	var v, sqNorm float64
	obs := mat.NewDense(1, mapSize, nil)
	for i, tr := range trace {
		v = logVals[tr] - pl.centers[i]
		sqNorm += v * v
		obs.Set(0, i, v)
	}
	//
	projection := new(mat.Dense)
	projection.Mul(obs, pl.projector)
	rawProj := projection.RawRowView(0)

	// ** 2. Record stats on basis components **
	sample := pl.makeSampleAnalysis(trace, rawProj, sqNorm)
	// Important to release lock before sending because the listening routine
	// may ask a writing lock and that statChan may be full.
	pl.basisMtx.RUnlock()
	if sample.in || sample.out {
		sample.hash = hashTrBits(trace)
	}
	pl.statChan <- sample

	// First filtering step. We know this sample is not an outsider.
	// Otherwise, send to the listener for further analysis.
	if !sample.in && !sample.out {
		return false
	}

	// This input is an considered outsider as a first approximation. Waiting
	// confirmation from the listening routine.
	res := <-sample.resChan
	return res
}

// ******* Data treatment *******

type pcaSample struct {
	proj []float64
	minD float64 // Minimum "real" distance.

	// Outlier characterization
	out, in bool
	resChan chan bool

	// Keep the original trace in case we need to restart the sample analysis.
	trace  []byte
	hash   uint64
	norm   float64
	sqNorm float64 // (Squared norm)

	// Sample statistics.
	extra, sin float64
}

var dummyDist float64

func (pl *pcaLearner) makeSampleAnalysis(trace []byte, proj []float64,
	sqNorm float64) pcaSample {

	// ** 1. Compute Statistics **
	sample := pcaSample{norm: math.Sqrt(sqNorm),
		trace: trace, proj: proj, sqNorm: sqNorm, extra: sqNorm,
		sin: sqNorm, // Equal to square of hypotenuse here.
	}
	for _, v := range proj {
		sample.extra -= v * v
	}
	sample.sin = math.Sqrt(sample.extra / sample.sin) // d1 = square of opposite.
	// @TODO: Shouldn't the out criteria be about the proportion of the vector
	// "out" rather than it's absolute value out?
	if (math.Sqrt(sample.extra) > pl.oFloor || sample.sin > sinFloor) &&
		len(pl.vars) < pcaTryMaxDim {
		// This sample is out of the space defined by the basis.
		// So we already know it's an outsider.
		sample.out = true
		sample.resChan = make(chan bool)
		return sample
	}

	// ** 2. Compare to seeds and see if an outsider. **
	if !pl.converged {
		return sample
	}
	seedN := len(pl.phenos)
	rDists := make([]float64, seedN)
	for i, coor := range proj {
		for j := range rDists {
			line := pl.phenos[j].proj
			if len(proj) > len(line) {
				// Raw projection and seed projection don't match in their
				// number of coordinates.
				str := fmt.Sprintf("(pheno[%d]) Different length: line: %d v."+
					" %d new sample proj", j, len(line), len(proj))
				if false { // Hard debug.
					panic(str)
				} else if i >= len(line) { // Soft debug: just log it.
					log.Printf(str)
					continue
				}
			}

			diff := coor - line[i]
			rDists[j] += diff * diff

			if doFullDistTest {
				dummyDist = calcDist(trace, pl.phenos[j].trace)
			}
		}
	}
	for j := range rDists {
		rDists[j] = math.Sqrt(rDists[j])
	}

	sample.minD = math.MaxFloat64
	for j := range rDists {
		if sample.minD > rDists[j] {
			sample.minD = rDists[j]
		}
	}
	if sample.minD > pl.dFloor {
		sample.in = true
		sample.resChan = make(chan bool)
	}

	return sample
}

var phenoDistToPool func([]float64, int) float64 = realMin

func realMin(dists []float64, skipI int) (min float64) { // Real minimum
	min = dists[0] + dists[1]
	for i, dist := range dists {
		if i == skipI {
			continue
		} else if dist < min {
			min = dist
		}
	}
	return min
}
func softMin(dists []float64, skipI int) (min float64) { // Soft minimum
	var n int
	for i, dist := range dists {
		if i == skipI {
			continue
		}
		n++
		min += math.Exp(-dist)
	}
	min /= float64(n)
	min = -math.Log(min)
	return min
}

// **************** Listener ****************
// Only one allowed to *write* the PCA-Learner state (projector, center,
// and phenotypes).

func (pl *pcaLearner) listenStats(frkSrvNb int) {
	const varUpdatePeriod = 1000
	var (
		sampleN int // How many sample were computed since last mean-variance update.
		// How many period (time reach 1000) have happen since last refactorization.
		periodN int
		totN    int
		bs      = newBasisStats(pl.vars, pl.totVar, len(pl.phenos))
		//
		// How many sample computed sample since last rate regulator tick.
		// Very similar to sampleN except it is not refreshed/reseted at the
		// same time.
		execN        int
		rr, rrTicker = makeRateRegulator(30, frkSrvNb)
	)

	for {
		select {
		case <-rrTicker.C:
			rate := rr.update(execN)
			execN = 0
			//
			pl.basisMtx.Lock()
			pl.rate = rate
			bs.varDiscountF = 1 - 1e-3/float64(rate+1)
			pl.basisMtx.Unlock()

		case sample, ok := <-pl.statChan:
			if !ok {
				return
			}
			if len(sample.proj) > bs.basisSize {
				log.Printf("Projection and different components "+
					"(has %d, should have %d).\n", len(sample.proj), bs.basisSize)
				if sample.resChan != nil {
					sample.resChan <- false
				}
				continue // This can happen just after some compenents where cut.
			}

			sampleN++
			execN++
			bs.newSample(sample)

			updateVar := sampleN >= varUpdatePeriod

			if updateVar || sample.in || sample.out {
				var (
					toRefactor bool
					okFacto    bool
					resetted   bool
					extraMean  float64
					pf         pcaFactorization
				)
				pl.basisMtx.Lock()

				// @TODO: if want to be perfect here, should empty the queue and
				// recompute all samples minMD...
				extraMean, resetted = bs.updateVars(pl)
				if pl.converged && resetted {
					pl.converged = false
				}
				totN += sampleN
				prevPeriodN := periodN
				periodN, sampleN = totN/varUpdatePeriod, 0

				if periodN > prevPeriodN {
					if extraMean > eMeanFlr {
						toRefactor = true
					} else if periodN >= 500 {
						toRefactor = true
					} else if periodN%50 == 0 {
						okFacto, pf = bs.getFactorization()
						if okFacto && pf.convCrit > 0.1 {
							toRefactor = true
						}
					}
				}

				// Process all simple inputs and save probable outliers for
				// later processing.
				if sample.in || sample.out || toRefactor {
					newSampleN, outliers := bs.emptyChannel(sample, pl.statChan)
					newSampleN += pl.processOutliers(outliers, bs)
					sampleN += newSampleN
					execN += newSampleN

					// Nothing to do with the rest; just a good time to update
					// some variables.
					pl.trueVars = bs.getTrueVars()
					alternativeOFlr := math.Sqrt(d1Floor * pl.extraVar)
					pl.oFloor = getExtraCrit(alternativeOFlr, bs.alld1s, pl.rate)

					if toRefactor {
						// Even if may have done this before, do it again in
						// case new component were added when processing
						// outliers.
						okFacto, pf = bs.getFactorization()
						if okFacto {
							pl.reFactorize(bs, pf)
							periodN, totN = 0, 0
							//
							if pl.converged {
								// When refactorize, also re-compute the
								// intra-distances and thus, re-adjust the dFloor.
								pl.dFloor = setPhenoMinDists(pl.phenos)
								if pl.dFloor < minFloor {
									pl.dFloor = minFloor
								}
							}
						}
					}
				}

				pl.basisMtx.Unlock()
			}

		case progName := <-pl.reqDebugInfo:
			// Depends on what's done in the printDebug function, but for now,
			// prefer to play safe and do it under lock with an empty queue.
			pl.basisMtx.Lock()
			for len(pl.statChan) > 0 {
				samp := <-pl.statChan
				if !samp.in && !samp.out {
					sampleN++
					execN++
					bs.newSample(samp)
				}
			}

			pl.printDebug(bs, progName)
			pl.basisMtx.Unlock()
			//bs.mdDistro.printDists()
			pl.endDebug <- struct{}{}
		}
	}
}

func (bs *basisStats) emptyChannel(sample pcaSample, statChan chan pcaSample) (
	sampleN int, outliers []pcaSample) {

	if sample.in || sample.out {
		outliers = []pcaSample{sample}
	}
	for len(statChan) > 0 {
		oSamp := <-statChan
		if oSamp.in || oSamp.out {
			outliers = append(outliers, oSamp)
		} else {
			sampleN++
			bs.newSample(oSamp)
		}
	}

	// @TODO: sort toRequeue with in-s before out-s?

	return sampleN, outliers
}

func (pl *pcaLearner) processOutliers(outliers []pcaSample,
	bs *basisStats) (time int) {

	var isOut bool
	observations := make([]*mat.VecDense, len(outliers))
	for _, sample := range outliers {
		isOut = isOut || sample.out
	}
	if isOut {
		for i, sample := range outliers {
			var v float64
			orgVect := make([]float64, mapSize)
			for i, tr := range sample.trace {
				v = logVals[tr] - pl.centers[i]
				orgVect[i] = v
			}
			observations[i] = mat.NewVecDense(mapSize, orgVect)
		}
	}

	for i, sample := range outliers {
		var oOutliers []pcaSample
		var oObs []*mat.VecDense
		if i < len(outliers)-1 {
			oOutliers = outliers[i+1:]
			oObs = observations[i+1:]
		}

		time++
		bs.newSample(sample)

		if pl.converged && sample.in {
			in := pl.checkNewIn(sample)
			sample.resChan <- in
		} else if len(pl.vars) < pcaTryMaxDim && sample.out {
			sample.resChan <- true
			pl.processOut(sample, oOutliers, oObs, bs)
		} else {
			sample.resChan <- false
		}
	}

	return time
}

func (pl *pcaLearner) processOut(sample pcaSample,
	oOutliers []pcaSample, oObs []*mat.VecDense, bs *basisStats) {

	// ** 1. Preparation **
	var v float64
	proj := sample.proj
	newBasis := mat.NewDense(1, mapSize, nil)
	for i, tr := range sample.trace {
		v = logVals[tr] - pl.centers[i]
		newBasis.Set(0, i, v)
	}

	// ** 2. Gram-Schmidt **
	// Remove the vector components which are already in other vectors.
	subM := mat.NewDense(1, mapSize, nil)
	for i, v := range proj {
		subM.Copy(pl.projector.ColView(i).T())
		subM.Scale(v, subM)
		newBasis.Sub(newBasis, subM)
	}
	// Normalize
	newBasisNorm := mat.Norm(newBasis, 2)
	newBasis.Scale(1/newBasisNorm, newBasis)
	proj = append(proj, newBasisNorm)

	// ** 3. Extends projection of seeds to this new basis **
	newBasisV := newBasis.RowView(0)
	extendProj := func(phenos []phenotype) (mean, variance float64) {
		orgVect := make([]float64, mapSize)
		for i := range phenos {
			// Recompute the vector associated to this phenotype. This is the
			// main computation cost of not keeping it memory. Tradeoff...
			var v, sqNorm float64
			for i, tr := range phenos[i].trace {
				v = logVals[tr] - pl.centers[i]
				sqNorm += v * v
				orgVect[i] = v
			}
			original := mat.NewVecDense(mapSize, orgVect)
			//
			newBV := mat.Dot(original, newBasisV)
			phenos[i].proj = append(phenos[i].proj, newBV)
			if newBV < 1e-5 { // "Orthogonality" is sentive.
				continue
			}
			phenos[i].sqNorm = sqNorm
			phenos[i].extra = sqNorm
			phenos[i].extra -= doSqSum(phenos[i].proj)
			mean += newBV
			variance += newBV * newBV
		}
		return mean, variance
	}
	mean, variance := extendProj(pl.phenos)
	_, _ = extendProj(pl.covComp)
	//
	minDI, minD := getDistToPhenos(proj, pl.phenos)
	pl.phenos = append(pl.phenos, phenotype{
		trace:  sample.trace,
		sqNorm: sample.sqNorm,
		proj:   proj,
		hash:   sample.hash,
		// extra is 0 since we add this trace as a component to the base.
		//
		minD:      minD,
		closeHash: pl.phenos[minDI].hash,
	})
	// Append variance of this basis
	n := float64(len(pl.phenos))
	mean /= n
	variance = (variance / n) - (mean * mean)
	pl.vars = append(pl.vars, variance)
	pl.stds = append(pl.stds, math.Sqrt(variance))
	pl.extraVar -= variance

	// ** 4. Prepare future data collection **
	// a. Extend projector to have this basis
	r, c := pl.projector.Dims()
	augmented := mat.NewDense(r, c+1, nil)
	augmented.Augment(pl.projector, newBasis.T())
	pl.projector = augmented
	// b. Prepare statistic collection
	bs.addCompo(variance, len(pl.phenos))

	// ** End: Re-check if other outliers are still ones. **
	for i := range oOutliers {
		// First add coordinate on new basis.
		newBV := mat.Dot(newBasisV, oObs[i])
		oOutliers[i].proj = append(oOutliers[i].proj, newBV)
		oOutliers[i].extra -= newBV * newBV
		if oOutliers[i].extra > 0 {
			oOutliers[i].sin = math.Sqrt(oOutliers[i].extra) / oOutliers[i].norm
		}

		// If was out, check it still is after adding this component.
		if s := oOutliers[i]; s.out {
			if math.Sqrt(s.extra) < pl.oFloor && s.sin < sinFloor {
				oOutliers[i].out = false
			}
			continue
		} else if !oOutliers[i].in {
			continue
		}

		// If in, as for processIn, need to check to the phenotype we just added
		// does not invalidate that.
		var dist, diff float64
		for j, p := range sample.proj {
			diff = p - oOutliers[i].proj[j]
			dist += diff * diff
		}
		if oOutliers[i].minD > dist {
			oOutliers[i].minD = dist
		}

		if oOutliers[i].minD < pl.dFloor {
			oOutliers[i].in = false
		}
		// @TODO: Since ATM the "in" acceptance criteria depends on the number
		// of components, there is also a possibility that adding a component
		// changed the status of this other sample. However, this could be
		// computationnaly expensive, and don't expect much change.
	}
}

// ***************** Add New Seed *****************
// If a new seed is found, but not by the PCA-Learner.

// To call if new seed is added to the pool but it wasn't detected by the
// PCA-learner as an outsider.
func (pl *pcaLearner) addNewSeed(trace []byte) {
	pl.basisMtx.Lock()

	// ** 1. Project **
	var sqNorm float64
	rawObs := make([]float64, mapSize)
	for i, tr := range trace {
		rawObs[i] = logVals[tr] - pl.centers[i]
		sqNorm += rawObs[i] * rawObs[i]
	}
	//
	obs := mat.NewDense(1, mapSize, rawObs)
	projection := new(mat.Dense)
	projection.Mul(obs, pl.projector)

	// ** 2. Compute Extra **
	var extra float64
	rawProj := projection.RawRowView(0)
	for _, v := range rawObs {
		extra += v * v
	}
	for _, v := range rawProj {
		extra -= v * v
	}

	// ** 3. Check if should be with other phenotypes or with the coverage
	// complement. **
	in := pl.checkNewIn(pcaSample{
		proj:  rawProj,
		hash:  hashTrBits(trace),
		trace: trace,
	})

	if !in {
		pl.covComp = append(pl.covComp, phenotype{
			trace:  trace,
			sqNorm: sqNorm,
			proj:   rawProj,
			extra:  extra,
			hash:   hashTrBits(trace),
		})
	}

	// @TODO: Should empty the listener queue and compare it to this to be sure
	// the samples considered "in" are still so. But hard to do from here.
	// Possibly, could handle with another channel towards the listener, or
	// other communication channel like a boolean...
	// Just going to consider it's going to be culled next if it's a problem.
	pl.basisMtx.Unlock()
}

// *********************************************************
// ******** Visualization and Debug of PCA-Learner *********

func (pl *pcaLearner) String() (str string) {
	if pl == nil {
		return str
	}

	str = fmt.Sprintf("rate: %d", pl.rate)
	str += fmt.Sprintf("\nBasis dim: %d - explained var: %.2f%% (tot=%.3v)"+
		" - dFloor: %.3v", len(pl.vars), 100*(1-pl.extraVar/pl.totVar),
		pl.totVar, pl.dFloor)

	genVar := 1.0
	for _, v := range pl.trueVars {
		genVar *= v
	}
	str += fmt.Sprintf("\ngeneral variance: %.3v - PCA-entropy: %.3v",
		genVar, math.Log(genVar)/8)

	return str
}

func (pl *pcaLearner) epilogue(progName string) {
	pl.reqDebugInfo <- progName
	<-pl.endDebug
}

func (pl *pcaLearner) printDebug(bs *basisStats, progName string) {
	covMat := bs.getCovMat()
	if bs.basisSize < 30 {
		fa := mat.Formatted(covMat, mat.Prefix(""), mat.Squeeze())
		fmt.Printf("\n\nCovariance matrix:\n%.2v\n\n", fa)
	}
	fmt.Printf("bs.basisSize: %d\n", bs.basisSize)
	fmt.Printf("totVar: %.2v - extraVar: %.2v\n", pl.totVar, pl.extraVar)

	const benchN = 20
	var pf pcaFactorization
	var convCrit float64
	start := time.Now()
	for i := range make([]struct{}, benchN) {
		_, pf = bs.getFactorization()
		if i == 0 {
			convCrit = pf.convCrit
		}
	}
	//
	dur := time.Now().Sub(start) / benchN
	fmt.Printf("Convergence criteria: %.3v\n", convCrit)
	fmt.Printf("Factorization duration: %dus.\n", dur/time.Microsecond)

	pl.reFactorize(bs, pf)
	pl.printPCs(bs)

	// ***************
	// ** Do checks **
	// Kinda "unit test" on PCA-learner.
	//
	// Re-do another factorization after this one to check the convergence
	// criteria is 0.
	_, pf = bs.getFactorization()
	if pf.convCrit > .01 {
		fmt.Printf("Second convergence criteria: %.3v\n", pf.convCrit)
	}
	//
	checkProjs(pl.phenos) // Check it's a "regular" rectangle. To Remove later.
	checkExtras(pl.phenos, pl.centers[:])
	checkHashes(pl.phenos)
	// ***************

	printAdjs(pl.adjs)

	fmt.Println("")

	if debug || verbose {
		pl.exportPhenos(progName)
	}
}

func (pl *pcaLearner) benchProj(seedPts seedList) {
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Printf("len(seedPts) = %+v\n", len(seedPts))

	pl.basisMtx.RLock()
	r, c := pl.projector.Dims()
	projector := mat.NewDense(r, c, nil)
	projector.Copy(pl.projector)
	pl.basisMtx.RUnlock()

	var projs [][]float64 // Dummy...
	startT := time.Now()
	for _, seedPt := range seedPts {
		//pl.newObs(seedPt.traceBits)
		//
		obs := mat.NewDense(1, mapSize, nil)
		for i, tr := range seedPt.traceBits {
			obs.Set(0, i, logVals[tr]-pl.centers[i])
		}
		projection := new(mat.Dense)
		projection.Mul(obs, projector)
		projs = append(projs, projection.RawRowView(0))
	}

	dur := time.Now().Sub(startT)
	dur /= time.Duration(len(seedPts))
	fmt.Printf("newObs avg exec time: %+v\n", dur)
	fmt.Printf("len(projs) = %+v\n", len(projs))
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!")
}
func (pl *pcaLearner) printPCs(bs *basisStats) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"", "Variance", "Cum_V"})
	var cumV float64
	fmt.Printf("pl.totVar = %+v\n", pl.totVar)
	for i, v := range pl.vars {
		cumV += v
		table.Append([]string{
			fmt.Sprintf("PC%d", i),
			fmt.Sprintf("%.3v (%.2f%%)", v, 100*v/pl.totVar),
			fmt.Sprintf("%.2f%%", 100*cumV/pl.totVar),
			fmt.Sprintf("%.3v", bs.sampleN[i]),
		})
	}
	table.Append([]string{"Total", fmt.Sprintf("%.3v", pl.totVar), ""})
	table.Render()

	var centerNorm float64
	for _, c := range pl.centers {
		centerNorm += c * c
	}
	centerNorm = math.Sqrt(centerNorm)
	fmt.Printf("centerNorm: %.3v\n", centerNorm)
}
func printAdjs(adjs []pcaAdjusment) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Time", "i", "#PC", "d_flr", "#pheno",
		"recent_norm", "conv_crit", "converged", "extra", "extra_crit"})
	for i, adj := range adjs {
		table.Append([]string{fmt.Sprintf("%v", adj.t), fmt.Sprintf("%d", i),
			fmt.Sprintf("%d", adj.nbPC), fmt.Sprintf("%.3v", adj.dFloor),
			fmt.Sprintf("%d", adj.phenoN),
			fmt.Sprintf("%.3v", adj.centeringNorm),
			fmt.Sprintf("%.3v", adj.convCrit),
			fmt.Sprintf("%t", adj.converged),
			//
			fmt.Sprintf("%.0f", adj.extra),
			fmt.Sprintf("%.2f", adj.extraCrit),
		})
	}
	table.Render()
}

// ***************
// ** For debug **
func checkProjs(phenos []phenotype) {
	lenghts := make([]int, len(phenos))
	for i, pheno := range phenos {
		proj := pheno.proj
		lenghts[i] = len(proj)
	}
	for _, l := range lenghts {
		if l != lenghts[0] {
			panic(fmt.Sprintf("irregulatiry in seedProjs: %v", lenghts))
		}
	}
}
func checkExtras(phenos []phenotype, centers []float64) {
	for i, pheno := range phenos {
		var (
			orgNorm  = sqNormTrace(pheno.trace, centers)
			projNorm = doSqSum(pheno.proj)
			extra    = orgNorm - projNorm
			diff     = extra - pheno.extra
		)
		diff = math.Sqrt(diff * diff) // Absolute value.

		if diff > 5 {
			fmt.Printf("phenos[%d] has wrong extra space value (%.0f v. %.0f).\n",
				i, extra, pheno.extra)
			phenos[i].extra = extra // Since we already have it, correct the data.
		}
	}
}
func checkHashes(phenos []phenotype) {
	for i, pheno := range phenos {
		if pheno.hash == 0 {
			log.Printf("Phenotype %d has a NULL HASH.\n", i)
		}
	}
}
func sqNormTrace(trace []byte, centers []float64) (sqNorm float64) {
	var v float64
	for i, tr := range trace {
		v = logVals[tr] - centers[i]
		sqNorm += v * v
	}
	return sqNorm
}

// *****************************************************************************
// ****************************** Rate Regulation ******************************
// For PUT that allow a very fast throughput (determined by a threshold),
// projecting every execution trace on the PCA basis cost too much relatively to
// the execution time. Thus, only projecting for a random subset of the inputs.
//
// 1. Based on importance sampling, the PCA done is still has valuable as
//    before (since each input is selected _uniformly_).
// 2. The big drawback is that we may not detect an outlier. This trade-off can
//    be balanced using the throughput threshold (the higher, the more we value
//    the impact of the PCA-analysis).
//
// The rateRegulator expects the update methods to be called every time the
// ticker ticks.

const (
	throughputThreshold = 1000
	refreshT            = 200 * time.Millisecond
	timeStep            = time.Second
	subStepN            = int(timeStep / refreshT)
)

type rateRegulator struct {
	maxSteps int
	frkSrvNb int

	subStep  int // Where we are in the current timeStep
	cntIndex int
	counts   []int
}

func makeRateRegulator(maxSteps int, frkSrvNb int) (
	rr rateRegulator, updateTicker *time.Ticker) {

	rr = rateRegulator{
		maxSteps: maxSteps,
		frkSrvNb: frkSrvNb,
		counts:   []int{0},
	}
	updateTicker = time.NewTicker(refreshT)
	return rr, updateTicker
}

func getRate(rate int) int {
	if rate > throughputThreshold {
		return throughputThreshold
	}
	return rate
}

func (rr *rateRegulator) update(execN int) (rate int) {
	rr.subStep++
	if rr.subStep == subStepN {
		rr.subStep = 0
		if len(rr.counts) < rr.maxSteps {
			rr.counts = append(rr.counts, 0)
			rr.cntIndex++
		} else {
			rr.cntIndex = (rr.cntIndex + 1) % rr.maxSteps
			rr.counts[rr.cntIndex] = 0
		}
	}

	rr.counts[rr.cntIndex] += execN
	//dbgPr("[RR] cntIndex : %d - counts: %v\n", rr.cntIndex, rr.counts)

	// Rate computation is slightly wrong since the last step isn't finished
	// yet. Cause an underestimation of the rate. Negligeable if maxSteps is
	// high enough.
	for _, r := range rr.counts {
		rate += r
	}
	rate /= len(rr.counts) * rr.frkSrvNb
	return rate
}

// *****************************************************************************
// **************************** Floor Regulation *******************************

// Check if this sample is really "in", meaning, inside the plane defined by the
// basis, its distance from all other phenotypes is above the dFloor.
//
// If it's "in", then:
// - also adds this sample to the phenotypes list (and possibly some metadata
//   management for its closest phenotype).
// - pops out the phenotype with the lowest distance to the others, and thus
//   update the dFloor.
func (pl *pcaLearner) checkNewIn(sample pcaSample) bool {
	if !pl.converged {
		return false
	}

	// I - recompute minimum distance
	// I.a. Compute distance to phenotypes
	minDI, minD := getDistToPhenos(sample.proj, pl.phenos)
	//
	// I.b. Check if this sample is really "in" by comparing the (newly
	// recomputed) minimum distance to phenotypes with the dFloor.
	if minD < pl.dFloor {
		// After distance recomputation, it appears this sample is not "in"
		// after all (dFloor increased or close seed was accepted).
		return false
	}

	// II - Add this sample to the phenotype list.
	thisHash := sample.hash
	// II.a Push in the list.
	pl.phenos = append(pl.phenos, phenotype{
		trace:  sample.trace,
		sqNorm: sample.sqNorm,
		proj:   sample.proj,
		extra:  sample.extra,
		hash:   thisHash,
		//
		minD:      minD,
		closeHash: pl.phenos[minDI].hash,
	})
	// II.b update the corresponding phenotype min distance if necessary.
	// @TODO: I'm wondering if this is really necessary?
	if minD < pl.phenos[minDI].minD {
		pl.phenos[minDI].closeHash = thisHash
		//
		dists := make([]float64, len(pl.phenos))
		mDists := make([]float64, len(pl.phenos))
		for i := range mDists {
			if i == minDI {
				continue
			}
			for j, p := range pl.phenos[i].proj {
				diff := p - pl.phenos[minDI].proj[j]
				dists[i] += diff * diff
				diff = diff * diff / pl.vars[j]
				mDists[i] += diff
			}
			dists[i], mDists[i] = math.Sqrt(dists[i]), math.Sqrt(mDists[i])
		}
		//
		pl.phenos[minDI].minD = phenoDistToPool(dists, minDI)
	}

	// III - Pop out the lowest phenotype.
	pl.popPheno()

	return true
}

func getDistToPhenos(proj []float64, phenos []phenotype) (minDI int, minD float64) {
	dim := len(proj)

	// 1. Compute all distances.
	dists := make([]float64, len(phenos))
	for i := range dists {
		if len(phenos[i].proj) < dim {
			dists[i] = math.MaxFloat64
			continue
		}
		for j, p := range phenos[i].proj[:dim] {
			diff := p - proj[j]
			diff = diff * diff
			dists[i] += diff
		}
		dists[i] = math.Sqrt(dists[i])
	}

	// 2. Get the minimum distance (and corresponding index.
	minD = dists[0]
	for i, dist := range dists {
		if dist < minD {
			minD = dist
			minDI = i
		}
	}
	minD = phenoDistToPool(dists, -1)

	return minDI, minD
}

func (pl *pcaLearner) popPheno() {
	phenoN := len(pl.phenos)
	if phenoN <= maxPhenoN {
		return // If list of phenos is not at max, no need to pop.
	}

	// a. Pop out the phenotype with the minimum inter-distance, and thus
	// update the dFloor.
	sort.Slice(pl.phenos, func(i, j int) bool {
		return pl.phenos[i].minD > pl.phenos[j].minD
	})
	lastP := pl.phenos[phenoN-1]
	pl.phenos = pl.phenos[:phenoN-1]
	pl.phenoTrash = append(pl.phenoTrash, lastP)
	pl.dFloor = pl.phenos[phenoN-2].minD
	if pl.dFloor < minFloor {
		dbgPr("dFloor is too low (=%.3v), setting to min.\n", pl.dFloor)
		pl.dFloor = minFloor
	}
	// @TODO: If dFloor reduced, could retry all the phenotypes in covComp (and
	// maybe in the trash?).

	// b. Update the phenotypes that had lastP as their closest one.
	for i := range pl.phenos {
		if pl.phenos[i].closeHash != lastP.hash {
			continue
		}
		//
		var closeHash uint64
		minD := pl.phenos[0].minD + pl.phenos[1].minD
		dists := make([]float64, len(pl.phenos))
		for j := range pl.phenos {
			if i == j {
				continue
			}
			//
			var dist float64
			for k, p := range pl.phenos[i].proj {
				if k >= len(pl.phenos[j].proj) {
					break
				}
				diff := p - pl.phenos[j].proj[k]
				dist += diff * diff
			}
			dists[j] = math.Sqrt(dist)
			if dists[j] < minD {
				minD = dists[j]
				closeHash = pl.phenos[j].hash
			}
		}
		//
		pl.phenos[i].minD = phenoDistToPool(dists, i)
		pl.phenos[i].closeHash = closeHash
	}
	if phenoN-1 > maxPhenoN {
		pl.popPheno()
	}

	// c. If phenoTrash list is long enough, process it (throw it but
	// keeping necessary complement).
	if len(pl.phenoTrash) < maxPhenoN/5 {
		// If not enough phenoTrash, don't want to lose the time processing them.
		return
	}
	//
	// c.1. Setting up
	indexes := make([]int, len(pl.phenos))
	for i := range pl.phenos {
		indexes[i] = i
	}
	phenos := append(pl.phenos, pl.covComp...)
	phenos = append(phenos, pl.phenoTrash...)
	// c.2. Getting coverage complement
	covCompIndexes := pl.setCovCompletion(indexes,
		getComplement(indexes, len(phenos)), phenos)
	// c.3. Translate indexes into the relevants sets (phenotypes or hashes)
	var toRem []uint64
	trashIndexes := getComplement(append(indexes, covCompIndexes...), len(phenos))
	for _, i := range trashIndexes {
		toRem = append(toRem, phenos[i].hash)
	}
	//
	var covComp []phenotype
	for _, i := range covCompIndexes {
		covComp = append(covComp, phenos[i])
	}
	pl.covComp = covComp
	// c.4. Finally can trash the elements that were found the be, in fact,
	// useless (are not far enough in the PCA-base map, nor do they bring
	// coverage).
	if len(pl.cullCh) == 1 {
		toRem = append(toRem, <-pl.cullCh...)
	}
	pl.cullCh <- toRem
	pl.phenoTrash = nil
}

// Ensure that by culling, we don't lose the coverage of any branch by culling.
// There are no guarantee that this culling wouldn't leave some seeds out. So:
// 1. Detect, if any, which branch were left out.
// 2. Complete using seeds left out.
func (pl *pcaLearner) setCovCompletion(setIndexes []int, complement []int,
	phenos []phenotype) (covCompIndexes []int) {

	if len(complement) == 0 {
		return covCompIndexes
	}

	var covered [mapSize]bool
	iterN := make([]struct{}, mapSize)
	for _, phenoI := range setIndexes {
		if len(phenos[phenoI].trace) < mapSize {
			continue
		}
		for j := range iterN {
			if !covered[j] && phenos[phenoI].trace[j] > 0 {
				covered[j] = true
			}
		}
	}

	toCover := make([]map[int]int, len(complement))

	for i, phenoI := range complement {
		if len(phenos[phenoI].trace) < mapSize {
			continue
		}
		toCover[i] = make(map[int]int)
		for j := range iterN {
			if !covered[j] && phenos[phenoI].trace[j] > 0 {
				toCover[i][j] = phenoI
			}
		}
	}

	var addedN int

	for {
		// Greedy.
		sort.Slice(toCover, func(i, j int) bool {
			return len(toCover[i]) > len(toCover[j])
		})
		//
		// Random.
		//selectedI := rand.Intn(len(toCover))
		//toCover[0], toCover[selectedI] = toCover[selectedI], toCover[0]

		selected := toCover[0]
		if len(selected) == 0 {
			break
		}
		var phenoI int
		for _, j := range selected {
			phenoI = j
			break
		}
		covCompIndexes = append(covCompIndexes, phenoI)
		addedN++

		if len(toCover) == 1 {
			break
		}
		toCover = toCover[1:]

		for branch := range selected {
			for k := range toCover {
				delete(toCover[k], branch)
			}
		}
	}

	return covCompIndexes
}

func getComplement(set []int, max int) (comp []int) {
	setCopy := make([]int, len(set))
	copy(setCopy, set)
	sort.Ints(setCopy)
	//
	var index int
	for ele := 0; ele < max; ele++ {
		if index < len(setCopy) && setCopy[index] == ele {
			index++
		} else {
			comp = append(comp, ele)
		}
	}
	return comp
}

func setPhenoMinDists(phenos []phenotype) float64 {
	var wg sync.WaitGroup
	phenoN := len(phenos)
	dists := make([]float64, phenoN*phenoN) // index[i, j] = i*phenoN + j

	// I - Compute distances between all phenotypes
	wg.Add(phenoN)
	for i := range phenos {
		go func(i int) {

			for j := i + 1; j < phenoN; j++ {
				index := i*phenoN + j
				for k, p := range phenos[i].proj {
					diff := p - phenos[j].proj[k]
					diff = diff * diff
					dists[index] += diff
				}
				dists[index] = math.Sqrt(dists[index])
				dists[j*phenoN+i] = dists[index] // Make the index symetric.
			}

			wg.Done()
		}(i)
	}
	wg.Wait()

	// II - Compute minimum for all phenotypes
	wg.Add(phenoN)
	for i := range phenos {
		go func(i int) {

			var minDJ int
			iDists := dists[i*phenoN : (i+1)*phenoN]
			minD := iDists[0] + iDists[1]
			for j, dist := range iDists {
				if i == j { // Distance to self doesn't matter.
					continue
				}
				if dist < minD {
					minD = dist
					minDJ = j
				}
			}
			//
			phenos[i].minD = phenoDistToPool(iDists, i)
			phenos[i].closeHash = phenos[minDJ].hash

			wg.Done()
		}(i)
	}
	wg.Wait()

	// III - Set dFloor
	minMinD := phenos[0].minD
	for i := range phenos {
		minD := phenos[i].minD
		if minD < minMinD {
			minMinD = minD
		}
	}
	return minMinD
}

// *****************************************************************************
// ****************************** Exporting ************************************

func (pl *pcaLearner) exportPhenos(progName string) {
	if len(pl.phenos) == 0 {
		log.Print("No phenotype to export.")
		return
	}

	// ** I - Setup **
	timeStr := time.Now().Format(time.RFC3339)
	dirPath := fmt.Sprintf("%s-%s", timeStr, progName)

	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		log.Printf("Could not create folder to export data to: %v.\n", err)
		return
	}

	// ** II - Prepare records to write **
	// A - Serialize phenotype projections into strings
	rPheno := make([][]string, len(pl.phenos)+1)
	basisSize := len(pl.phenos[0].proj)
	colN := basisSize + 2
	rPheno[0] = make([]string, colN)
	for j := 0; j < basisSize; j++ {
		rPheno[0][j] = fmt.Sprintf("PC%d", j)
	}
	rPheno[0][basisSize] = "extra"
	rPheno[0][basisSize+1] = "hash"
	for i, pheno := range pl.phenos {
		rPheno[i+1] = make([]string, colN)
		for j, p := range pheno.proj {
			rPheno[i+1][j] = fmt.Sprintf("%f", p)
		}
		rPheno[i+1][basisSize] = fmt.Sprintf("%f", pheno.extra)
		rPheno[i+1][basisSize+1] = fmt.Sprintf("%x", pheno.hash)
	}

	// B -  Serizalize the projection of seeds
	rProj := make([][]string, mapSize)
	for i := range rProj {
		rProj[i] = make([]string, basisSize)
		for j := range rProj[i] {
			rProj[i][j] = fmt.Sprintf("%f", pl.projector.At(i, j))
		}
	}

	// C - Variances
	rVars := [][]string{[]string{"Name", "Variance"}}
	for i := 0; i < basisSize; i++ {
		rVars = append(rVars, []string{
			fmt.Sprintf("PC%d", i),
			fmt.Sprintf("%f", pl.vars[i]),
		})
	}
	rVars = append(rVars, []string{"extra",
		fmt.Sprintf("%f", pl.extraVar)})

	// ** III - Write CSVs **
	writeCSV(rPheno, dirPath, "pheno.csv")
	writeCSV(rProj, dirPath, "projector.csv")
	writeCSV(rVars, dirPath, "pc_vars.csv")
	fmt.Println("End exportPhenos")
}
func writeCSV(records [][]string, dir, file string) {
	path := filepath.Join(dir, file)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Couldn't open file %s: %v.\n", file, err)
		return
	}

	w := csv.NewWriter(f)
	if err = w.WriteAll(records); err != nil {
		log.Printf("Could not write CSV to %s: %v.\n", file, err)
		return
	}
}
