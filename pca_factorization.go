package main

import (
	"fmt"
	"log"

	"math"
	"os"
	"sort"
	"time"

	// To log basis stats
	"encoding/csv"
	"math/rand"
	"path/filepath"

	"gonum.org/v1/gonum/mat"
)

// Chose amond the two cull function:
// - cullK: K-Mean based clustering. (When this is written, 2019.05.29, this one
//   is not acutally finished. But went far enough to get an idea of its
//   efficiency.)
// - cullD: divisive hierarchical clustering. Built on top of K-Mean.
func (pl *pcaLearner) cull() { pl.cullD() }

// *****************************************************************************
// *************************** PCA Basis Ajustment *****************************
// Re-factoration, re-centering, cutting lowest components.

// Use collected statistics to re-adjust the basis.
func (pl *pcaLearner) reFactorize(bs *basisStats, pf pcaFactorization) {
	// 1. If recentering is to be done. Now is also a good time because
	// the covariance matrix has already been computed and recentering needs to
	// reset bs as well.
	centeringNorm := pl.recenter(bs)

	// 2. Projector for the new basis. Bottleneck.
	pl.projector.Mul(pl.projector, pf.eigVect)

	// 3. Adjust the basisStats structure for the new basis.
	bs.applyFactorization(pf)
	//
	var resetted bool
	_, resetted = bs.updateVars(pl)
	if pl.converged && resetted {
		pl.converged = false
	}

	// 4. Reproject all (seed) traces w/ new projector.
	setNewProj := func(phenos []phenotype) {
		seedProjMatData := make([]float64, len(phenos)*bs.basisSize)
		for i := range phenos {
			proj := phenos[i].proj
			if len(proj) > bs.basisSize {
				proj = proj[:bs.basisSize]
			}
			for j, v := range proj {
				seedProjMatData[i*bs.basisSize+j] = v
			}
		}
		seedProjMat := mat.NewDense(len(phenos), bs.basisSize, seedProjMatData)
		seedProjMat.Mul(seedProjMat, pf.eigVect)
		for i := range phenos {
			proj := seedProjMat.RawRowView(i)
			phenos[i].proj = make([]float64, len(proj))
			copy(phenos[i].proj, proj)
			phenos[i].extra = phenos[i].sqNorm
			phenos[i].extra -= doSqSum(phenos[i].proj)
		}
	}
	setNewProj(pl.phenos)
	if len(pl.covComp) > 0 {
		setNewProj(pl.covComp)
	}

	// 5. Cut component that does not seem useful.
	pl.cutPCs(bs, makeTryPCCutCrit(pl.rate, bs.sampleN))

	// 6. Are we converging?
	// @TODO: For centering norm, instead of being a "hard" floor, it should be
	// a percentage of the center vector norm. Need to study several program for
	// this.
	if !pl.converged && pf.convCrit < .1 && centeringNorm < 10 {
		pl.converged = true
		pl.convergenceCulling()
		//
		// Very important: once culling is done, compute all the distances
		// between the phenotypes and sets the dFloor to the lowest of these
		// distances.
		// @TODO: in theory, if the list of phenos is not yet equal to the
		// maximum list size, then the floor could be set lower (to what?). In
		// practice, the minimum intra-distance is likely to already be very
		// low.
		pl.dFloor = setPhenoMinDists(pl.phenos)
		if pl.dFloor < minFloor {
			pl.dFloor = minFloor
		}
		dbgPr("dFloor initialized at: %.3v.\n", pl.dFloor)
	}
	// 7. Record debug info.
	pl.adjs = append(pl.adjs, pcaAdjusment{
		t:             time.Now().Sub(pl.startT),
		centeringNorm: centeringNorm,
		convCrit:      pf.convCrit,
		nbPC:          bs.basisSize, phenoN: len(pl.phenos),
		dFloor: pl.dFloor, converged: pl.converged,
		//
		extra:     pl.extraVar,
		extraCrit: pl.oFloor,
	})
}

func (pl *pcaLearner) recenter(bs *basisStats) (centeringNorm float64) {
	// 1. Compute the "recentering vector" for components whose mean are too
	// high (in theory, it should always be nil). This recentering vector is in
	// two spaces: the original space and the projected one.
	var (
		projReCentVect = make([]float64, bs.basisSize)
		n, mean        float64
		extraMean      float64
		center         [mapSize]float64
	)
	for i, s := range bs.sums {
		n = float64(bs.sampleN[i])
		if n < .5 {
			continue
		}

		mean = s / n
		// @TODO: Here if mean is large and n is small, we might want to be careful.
		if mean > 1 {
			projReCentVect[i] = mean
			extraMean += mean
		}
	}
	//
	if extraMean < eMeanFlr {
		// No (or "few") non-centered component. Nothing to do.
		return
	}
	//
	//bs.resetSqNorm()
	for i := range center {
		basisVals := pl.projector.RawRowView(i)
		center[i] = linearCombination(basisVals, projReCentVect)
	}
	centerMat := mat.NewVecDense(mapSize, center[:])

	// 2. Apply recentering to phenotypes and pl.centers.
	centeringNorm = mat.Norm(centerMat, 2)
	centeringNorm2 := centeringNorm * centeringNorm
	if math.IsNaN(centeringNorm2) {
		projectorNorm := mat.Norm(pl.projector, 2)
		log.Printf("projectorNorm: %+v\n", projectorNorm)
		log.Print("centeringNorm is NaN")
		return
	}

	for i, m := range projReCentVect {
		if m > 1 {
			bs.sums[i] = 0
		}
	}

	return centeringNorm
}
func linearCombination(vals, weights []float64) (sum float64) {
	if len(vals) != len(weights) {
		panic("Linear combination expects vectors of same lengths")
	}

	for i, v := range vals {
		sum += v * weights[i]
	}

	return sum
}

type cutCritT func(i int, v float64) bool

func defaultCutCrit(i int, v float64) bool { return v < 1 || i >= pcaMaxDim }
func makeTryPCCutCrit(rate int, sampleN []float64) cutCritT {
	// Have maximum 20 extra dimensions just for trial

	return func(i int, v float64) bool {
		if i >= pcaTryMaxDim {
			return true
		} else if sampleN[i] < 10*float64(rate) {
			return false
		}
		return v < 1 || i >= pcaMaxDim
	}
}

func (pl *pcaLearner) cutPCs(bs *basisStats, cutCrit cutCritT) {
	// 1. Chose the PCs to remove
	var cutI int
	for i, v := range pl.vars { // Vars is already sorted.
		if cutCrit(i, v) {
			cutI = i
			break
		}
	}
	if cutI == 0 { // Decided not to cut anything.
		return
	}

	// 2. Apply to PCA-Learner structure.
	// Projector.
	pl.projector = mat.DenseCopyOf(pl.projector.Slice(0, mapSize, 0, cutI))
	// Variances and standard deviations.
	pl.vars, pl.stds = pl.vars[:cutI], pl.stds[:cutI]
	// The seed projection in phenos (careful with the extra).
	for i := range pl.phenos {
		pl.phenos[i].proj = pl.phenos[i].proj[:cutI]
		pl.phenos[i].extra = pl.phenos[i].sqNorm
		pl.phenos[i].extra -= doSqSum(pl.phenos[i].proj)
	}

	// 3. Remove components from the basisStats
	bs.basisSize = cutI
	bs.sampleN = bs.sampleN[:cutI]
	bs.sums = bs.sums[:cutI]
	bs.prodSums = bs.prodSums[:cutI]
	for i := range bs.prodSums {
		bs.prodSums[i] = bs.prodSums[i][:cutI]
	}
}

// ***********
// ** Utils **
func doSqSum(proj []float64) (sum float64) {
	for _, v := range proj {
		sum += v * v
	}
	return sum
}

// *****************************************************************************
// ************ Keep Statistics on each Component of the Basis *****************
// Tool support for PCA-Learner

type basisStats struct {
	basisSize int // Number of component being kept track of.

	sampleN []float64 // How many much data do we have on each components.
	// Sum of x_i and cross product x_i*y_i for covariance (diagonal is sums of
	// x_i square).
	sums     []float64
	prodSums [][]float64

	// To compute the space "total variance"
	sampN     float64
	sqNormSum float64
	// Extra data collection
	forthSum float64 // Sum of norm^4.

	// For debug and such
	alld1s map[int]uint64

	// Variance discount factor.
	varDiscountF float64
}

func newBasisStats(vars []float64, totVar float64, n int) (bs *basisStats) {
	basisSize := len(vars)
	bs = &basisStats{
		basisSize: basisSize,
		sampN:     float64(n),
		sqNormSum: float64(n) * totVar,
		forthSum:  float64(n) * totVar * totVar,
		//
		sampleN:  make([]float64, basisSize),
		sums:     make([]float64, basisSize),
		prodSums: make([][]float64, basisSize),
		alld1s:   make(map[int]uint64),
		//
		varDiscountF: 1 - 1e-5,
	}

	for i, v := range vars {
		bs.sampleN[i] = float64(n)
		bs.prodSums[i] = make([]float64, basisSize)
		bs.prodSums[i][i] = v * bs.sampleN[i]
	}

	return bs
}

func (bs *basisStats) addCompo(variance float64, cnt int) {
	bs.basisSize++
	bs.sampleN = append(bs.sampleN, float64(cnt))
	bs.sums = append(bs.sums, 0)

	for i := range bs.prodSums {
		bs.prodSums[i] = append(bs.prodSums[i], 0)
	}
	n := bs.basisSize
	bs.prodSums = append(bs.prodSums, make([]float64, n))
	bs.prodSums[n-1][n-1] = variance
}

func (bs *basisStats) newSample(sample pcaSample) {
	projs := sample.proj
	for i, p := range projs {
		bs.sampleN[i] = 1 + bs.varDiscountF*bs.sampleN[i]
		bs.sums[i] = p + bs.varDiscountF*bs.sums[i]
	}

	for i, pi := range projs {
		for j := i; j < len(projs); j++ {
			pj := projs[j]
			bs.prodSums[i][j] = pi*pj + bs.varDiscountF*bs.prodSums[i][j]
		}
	}

	bs.sampN = 1 + bs.varDiscountF*bs.sampN
	bs.sqNormSum = sample.sqNorm + bs.varDiscountF*bs.sqNormSum
	bs.forthSum = sample.sqNorm*sample.sqNorm + bs.varDiscountF*bs.forthSum

	// Keep track of the extra space norms.
	// At the beginning, it was just for debug but in the end use it to set the
	// oFloor, which decided when to accept test cases because they are too much
	// out of space.
	d164 := int(math.Sqrt(sample.extra))
	if _, ok := bs.alld1s[d164]; !ok {
		bs.alld1s[d164] = 0
	}
	bs.alld1s[d164]++

	if useBasisStatsLogger {
		bsLogger.logSample(sample)
	}
}

func (bs *basisStats) updateVars(pl *pcaLearner) (
	extraMean float64, resetted bool) {

	var totVar, extraVar float64
	vars, stds, rate := pl.vars, pl.stds, getRate(pl.rate)

	if len(vars) != bs.basisSize {
		panic(fmt.Sprintf("Wrong vars length: %d and basis size is %d,",
			len(vars), bs.basisSize))
	}
	if len(vars) != len(stds) {
		panic("Should have as many variances than standard deviations")
	}

	var mean, spaceVar float64
	for i, s := range bs.sums {
		n := float64(bs.sampleN[i])
		if n < almostZero {
			continue
		}

		mean = s / n
		vars[i] = (bs.prodSums[i][i] / n) - (mean * mean)
		// Uncertainty factor:
		// (Coming from assuming an inverse gamma distribution on variance on a
		// Gaussian with fixed mean. The multiplication by "rate" are hacks.)
		// The "+1" and the "medVar*factor" comes from assuming a prior variance
		// equal to the previous median variance (that happened once).
		factor := float64(rate) / (1 + bs.sampleN[i])
		factor = math.Sqrt(factor)
		factor = vars[i] * factor
		if vars[i] > 2*factor {
			// Use the lower bound to compute the space we are covering
			spaceVar += vars[i] - 2*factor
		}
		// And the higher bound to compute the distances.
		vars[i] += factor
		stds[i] = math.Sqrt(vars[i])
		if mean > 1 {
			extraMean += mean
		}
	}

	totVar = bs.sqNormSum / bs.sampN
	extraVar = totVar - spaceVar

	pl.totVar, pl.extraVar = totVar, extraVar
	return extraMean, resetted
}
func (bs *basisStats) softReset(totVar float64) {
	const lowSampN = 1000
	const resetCst = 3

	if bs.sampN > lowSampN {
		bs.sampN = lowSampN
		bs.sqNormSum = lowSampN * totVar
		bs.forthSum = lowSampN * totVar * totVar
	}

	for i := range bs.sums {
		n := bs.sampleN[i]
		if n < lowSampN {
			continue
		}

		bs.sampleN[i] = lowSampN
		m := bs.sums[i] / n
		bs.sums[i] = m * lowSampN / resetCst
		//
		for j := i; j < bs.basisSize; j++ {
			nIJ := n
			if bs.sampleN[j] < nIJ {
				nIJ = bs.sampleN[j]
				if nIJ < lowSampN {
					continue
				}
			}
			prodMean := bs.prodSums[i][j] / nIJ
			bs.prodSums[i][j] = prodMean * nIJ / resetCst
		}
	}
}

// Get variances of all components without a lower/higher bound: for reporting.
func (bs *basisStats) getTrueVars() (vars []float64) {
	vars = make([]float64, bs.basisSize)
	for i, s := range bs.sums {
		n := float64(bs.sampleN[i])
		if n < almostZero {
			continue
		}

		mean := s / n
		vars[i] = (bs.prodSums[i][i] / n) - (mean * mean)
	}
	return vars
}

// Get the "extra criteria" to accept a phenotype as "out" (and thus set it as a
// component to try out).
func getExtraCrit(oFloor float64, alld1s map[int]uint64, rate int) float64 {
	//const targetThreshold = .999

	var max int
	for i := range alld1s {
		if i > max {
			max = i
		}
	}

	var tot uint64
	extraDs := make([]uint64, max+1)
	for i, v := range alld1s {
		if i <= 0 {
			continue
		}
		extraDs[i] = v
		tot += v
	}

	if tot < 1e3 { // Initialization.
		return oFloor
	}
	targetThreshold := 1 - (1 / float64(100*rate))

	var cum uint64
	threshold := uint64(float64(tot) * targetThreshold)
	for i, v := range extraDs {
		cum += v
		if cum >= threshold {
			return float64(i)
		}
	}

	return float64(max)
}

// ****************************
// **** Basis Stats Logger ****
// Should be used only when debugging, live it'd cost too much.
//
// Shouldn't be used with several instance at the same time b/c goes toward a
// fixed file.

const useBasisStatsLogger = false

type bsLoggerT struct {
	w      *csv.Writer
	startT time.Time
}

var (
	bsLogFile = "basis_stats_log.csv"
	bsLogger  bsLoggerT
)

func initBSLogger(dir string) {
	if !useBasisStatsLogger {
		return
	}

	if len(dir) > 0 {
		bsLogFile = filepath.Join(dir, bsLogFile)
	}
	f, err := os.Create(bsLogFile)
	if err != nil {
		log.Printf("Couldn't create basisStats logger: %v.\n", err)
		return
	}
	bsLogger = bsLoggerT{w: csv.NewWriter(f), startT: time.Now()}
	err = bsLogger.w.Write([]string{
		"time", "event", "projs", "extra", "min_d",
	})
	if err != nil {
		bsLogger = bsLoggerT{}
		log.Printf("Couldn't log basis stats header: %v.\n", err)
		return
	}
}

func (bsl bsLoggerT) logSample(sample pcaSample) {
	if !useBasisStatsLogger || bsl.w == nil {
		return
	}
	//
	bsl.w.Write([]string{
		fmt.Sprintf("%d", time.Now().Sub(bsl.startT)/time.Millisecond),
		"SAMPLE",
		fmt.Sprintf("%f", sample.proj),
		fmt.Sprintf("%f", sample.extra),
		fmt.Sprintf("%f", sample.minD),
	})
	//
	if rand.Intn(100) != 0 {
		return
	}
	bsl.w.Flush()
	if err := bsl.w.Error(); err != nil {
		log.Printf("Problem logging basis stats: %v.\n", err)
	}
}

func (bsl bsLoggerT) logRefact() {
	if !useBasisStatsLogger || bsl.w == nil {
		return
	}
	//
	const zStr = "0.000000"
	bsl.w.Write([]string{
		fmt.Sprintf("%d", time.Now().Sub(bsl.startT)/time.Millisecond),
		"REFACTORIZATION", "[]", zStr, zStr, zStr,
	})
}

// *****************************************************************************
// ******************************* Refactoring *********************************
// (Refactoring the basis, not the code :P.)

// Factorization of covariance on basis of PCA.
//
// Ideally, the PCA will be correct and the covariance matrix would be diagonal
// matrix. Unfortunately, we are always reasonning from incomplete data, and
// thus, regularly need to adjust the basis in light of recently collected data.
type pcaFactorization struct {
	covMat   *mat.SymDense // Coverariance matrix
	eigVal   []float64     // Variance
	eigVect  *mat.Dense    // Eigenvectors
	convCrit float64       // Convergence criteria
}

func (bs *basisStats) getFactorization() (ok bool, pf pcaFactorization) {
	covMat := bs.getCovMat()

	var eigsym mat.EigenSym
	ok = eigsym.Factorize(covMat, true)
	if !ok {
		log.Print("Could not factorize covariance mat.")
		return ok, pf
	}

	ev := new(mat.Dense)
	eigsym.VectorsTo(ev)

	// Permutatate eigenvector so they are not in increasing order.
	var (
		unorderedVars = eigsym.Values(nil)
		n             = len(unorderedVars)
		vars          = make([]float64, n)
		perm          = make([]int, n)
		permMat       = new(mat.Dense)
	)
	// a. Create the permutation to re-order correctly.
	for i := range perm {
		perm[i] = i
	}
	sort.Slice(perm, func(i, j int) bool {
		indexI, indexJ := perm[i], perm[j]
		return unorderedVars[indexI] > unorderedVars[indexJ]
	})
	// b. Apply this permutation.
	for i, index := range perm {
		vars[i] = unorderedVars[index]
	}
	permMat.Permutation(len(perm), perm)
	ev.Mul(ev, permMat)

	pf = pcaFactorization{
		covMat:   covMat,
		eigVal:   vars,
		eigVect:  ev,
		convCrit: computeConvergence(ev),
	}

	return ok, pf
}

func computeConvergence(ev *mat.Dense) (convCrit float64) {
	r, c := ev.Dims()

	for j := 0; j < c; j++ {
		var maxJ, v float64
		for i := 0; i < r; i++ {
			v = ev.At(i, j)
			v *= v
			if v > maxJ {
				maxJ = v
			}
			convCrit += v
		}
		convCrit -= maxJ
	}

	convCrit /= float64(c)
	return convCrit
}

// Make covariance based on the data collected from live data.
// Uased to refactorize the PCA basis (see above).
func (bs *basisStats) getCovMat() (covMat *mat.SymDense) {
	var (
		means = make([]float64, bs.basisSize)
		covs  = make([]float64, bs.basisSize*bs.basisSize)
	)

	for i, s := range bs.sums {
		means[i] = s / bs.sampleN[i]
	}

	for i, meanI := range means {
		for j := i; j < bs.basisSize; j++ {
			meanJ := means[j]
			prodSum := bs.prodSums[i][j]
			n := bs.sampleN[i]
			if bs.sampleN[j] < bs.sampleN[i] {
				n = bs.sampleN[j]
			}
			if n < almostZero {
				continue
			}

			cov := (prodSum / n) - meanI*meanJ
			if cov > 1e-10 { // "De-noising"
				covs[i*bs.basisSize+j] = cov
			}
		}
	}

	covMat = mat.NewSymDense(bs.basisSize, covs)
	return covMat
}

// *************************
// ** Apply factorization **

func (bs *basisStats) applyFactorization(pf pcaFactorization) {
	// If implement cutting, will need to apply it here as well.
	// Change basisSize
	// @TODO

	var (
		newN  = make([]float64, bs.basisSize)
		means = make([]float64, bs.basisSize)
	)
	// Project component means.
	for i, s := range bs.sums {
		means[i] = s / (bs.sampleN[i] + 1)
	}
	meanMat := mat.NewDense(1, len(means), means)
	meanMat.Mul(meanMat, pf.eigVect)
	//sumMat := mat.NewDense(1, len(bs.sums), bs.sums)
	//sumMat.Mul(sumMat, pf.eigVect)
	// Reproject sampleN.
	for i := range newN {
		var sampleNI float64
		for j, n := range bs.sampleN {
			v := pf.eigVect.At(i, j)
			// By definition of the basis a PCA finds, the vectors are
			// orthonormal. Meaning, in particular, the sum of the square of its
			// coordinates equals to 1.
			sampleNI += v * v / (n + 1)
		}
		newN[i] = 1 / sampleNI
		bs.sums[i] = means[i] * newN[i]
	}
	bs.sampleN = newN
	// prodSums is diagonal after factorization.
	bs.prodSums = make([][]float64, bs.basisSize)
	for i := range bs.prodSums {
		bs.prodSums[i] = make([]float64, bs.basisSize)
		meanI := means[i]

		for j := range bs.prodSums[i] {
			n := float64(bs.sampleN[i])
			if bs.sampleN[j] < bs.sampleN[i] {
				n = float64(bs.sampleN[j])
			}
			if n < almostZero {
				continue
			}

			meanJ := means[j]
			bs.prodSums[i][j] = n * meanI * meanJ
		}

		// Diagonal is the variance.
		bs.prodSums[i][i] += pf.eigVal[i] * bs.sampleN[i]
	}

	if useBasisStatsLogger {
		bsLogger.logRefact()
	}
}
