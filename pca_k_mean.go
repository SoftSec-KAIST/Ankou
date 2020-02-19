package main

import (
	"fmt"
	"log"

	"math"
	"math/rand"
	"sort"
	"sync"

	"time"

	"gonum.org/v1/gonum/stat"
)

// *****************************************************************************
// *************************** K-Mean Clustering *******************************

type kEle struct {
	// Index of phenotype in phenos slice OR, of mean index in means slice.
	index int
	dist  float64 // Distance of this phenotype to the mean.
}

func (pl *pcaLearner) cullK() {
	if !pl.converged { // No need to cull.
		return
	} else if len(pl.phenos) < maxPhenoN/2 {
		log.Printf("len(phenos)=%d -> why cull was called?\n", len(pl.phenos))
		return
	}

	start := time.Now()
	means, clusts := doKMean(maxPhenoN/2, pl.phenos, pl.vars)
	fmt.Printf("K-mean time: %v.\n", time.Now().Sub(start))
	pl.postKAnalysis(means, clusts)
}

// ************************************
// ******* Do K-Mean clustering *******

func doKMean(k int, phenos []phenotype, vars []float64) (
	means [][]float64, clusts [][]kEle) {

	var loopI int
	means, clusts = initMeans(k, phenos, vars)

	for {
		// A - Recomputing means.
		for i := range means {
			for j := range means[i] {
				means[i][j] = 0
			}
		}
		for i, c := range clusts {
			for _, ele := range c {
				for j, p := range phenos[ele.index].proj {
					means[i][j] += p
				}
			}
			for j := range means[i] {
				means[i][j] /= float64(len(c))
			}
		}

		// B - New cluster with updated means.
		var wg sync.WaitGroup
		newClusts := make([][]kEle, k)
		closestMean := make([]kEle, len(phenos))
		for phenoI, pheno := range phenos {
			wg.Add(1)
			go func(phenoI int, pheno phenotype) {

				dists := make([]float64, len(means))
				for i, mean := range means {
					var dist float64
					for j, p := range pheno.proj {
						diff := p - mean[j]
						dist += diff * diff / vars[j]
					}
					dists[i] = dist
				}

				var minI int = 0
				min := dists[0]
				for j, d := range dists {
					if d < min {
						min = d
						minI = j
					}
				}
				closestMean[phenoI] = kEle{index: minI, dist: min}

				wg.Done()
			}(phenoI, pheno)
		}
		wg.Wait()

		for phenoI, ele := range closestMean {
			meanI := ele.index
			newClusts[meanI] = append(newClusts[meanI],
				kEle{index: phenoI, dist: ele.dist})
		}

		// C - If cluststers are same as before, stop.
		loopI++
		if !hasClustChange(clusts, newClusts) || loopI > 100 {
			break
		}
		clusts = newClusts
	}

	return means, clusts
}

func initMeans(k int, phenos []phenotype, vars []float64) (
	means [][]float64, clusts [][]kEle) {

	means = make([][]float64, k)
	clusts = make([][]kEle, k)

	perm := rand.Perm(len(phenos))
	for i, phenoI := range perm[:k] {
		proj := phenos[phenoI].proj
		means[i] = make([]float64, len(proj))
		copy(means[i], proj)
		clusts[i] = []kEle{kEle{index: phenoI}}
	}

	var wg sync.WaitGroup
	closestMean := make([]kEle, len(phenos)-k)
	for i, phenoI := range perm[k:] {
		wg.Add(1)
		go func(i int, pheno phenotype) {

			dists := make([]float64, k)
			for j, mean := range means {
				var dist float64
				for l, p := range pheno.proj {
					diff := p - mean[l]
					dist += diff * diff / vars[l]
				}
				dists[j] = dist
			}

			var minI int
			min := dists[0]
			for j, d := range dists {
				if d < min {
					min = d
					minI = j
				}
			}
			closestMean[i] = kEle{index: minI, dist: min}
			wg.Done()
		}(i, phenos[phenoI])
	}
	wg.Wait()

	for i, ele := range closestMean {
		meanI := ele.index
		clusts[meanI] = append(clusts[meanI], kEle{perm[i+k], ele.dist})
	}

	return means, clusts
}

func hasClustChange(clusts, newClusts [][]kEle) bool {
	for i := range clusts {
		if len(clusts[i]) != len(newClusts[i]) {
			return true
		}
	}

	for i := range clusts {
		sort.Slice(clusts[i], func(j, k int) bool {
			return clusts[i][j].index < clusts[i][k].index
		})
	}
	for i := range newClusts {
		sort.Slice(newClusts[i], func(j, k int) bool {
			return newClusts[i][j].index < newClusts[i][k].index
		})
	}
	for i := range clusts {
		for j, ele := range clusts[i] {
			if ele.index != newClusts[i][j].index {
				return true
			}
		}
	}

	return false
}

// *************
// *** Debug ***
func checkClusts(clusts [][]kEle, phenoN int) {
	lens := make([]int, len(clusts))
	for i, c := range clusts {
		lens[i] = len(c)
	}
	fmt.Printf("lens = %+v\n", lens)

	set := make(map[int]struct{})
	for _, c := range clusts {
		for _, ele := range c {
			i := ele.index
			if _, ok := set[i]; ok {
				fmt.Printf("%d is doubly in clusters.\n", i)
			}
			set[i] = struct{}{}
		}
	}

	fmt.Printf("len(set): %d v. %d: phenoN.\n", len(set), phenoN)
}

// ************************************
// ******* Post K-Mean Analysis *******
// From the data of the K-Mean analysis:
// - chose which phenotype is kept.
// - chose which floor will be used.

func (pl *pcaLearner) postKAnalysis(means [][]float64, clusts [][]kEle) (
	indexes []int) {

	for _, c := range clusts {
		if len(c) == 0 {
			continue
		}
		//
		sort.Slice(c, func(i, j int) bool {
			return c[i].dist < c[j].dist
		})
		indexes = append(indexes, c[0].index)
	}
	//
	start := time.Now()
	preLen := len(indexes)
	covCompIndexes := pl.setCovCompletion(indexes,
		getComplement(indexes, len(pl.phenos)), pl.phenos)
	indexes = append(indexes, covCompIndexes...)
	fmt.Printf("Completion length gain: %d/%d.\n", len(indexes)-preLen, len(indexes))
	fmt.Printf("Completion time: %v.\n", time.Now().Sub(start))

	// *************
	start = time.Now()
	var wg sync.WaitGroup
	n := len(means)
	dists := make([]float64, n)
	for i, mI := range means {
		wg.Add(1)
		go func(i int, mI []float64) {
			var jDists []float64
			for j, mJ := range means {
				if i == j {
					continue
				}
				//
				var dist float64
				for k, p := range mI {
					diff := p - mJ[k]
					dist += diff * diff / pl.vars[k]
				}
				//dists = append(dists, math.Sqrt(dist))
				//dists[index+j-i-1] = math.Sqrt(dist)
				jDists = append(jDists, math.Sqrt(dist))
			}
			//
			sort.Float64s(jDists)
			dists[i] = jDists[0]
			wg.Done()
		}(i, mI)
	}
	//
	wg.Wait()
	fmt.Println("K-mean inter distances:")
	describe(dists)
	fmt.Printf("Dist anal time: %v.\n", time.Now().Sub(start))

	return indexes
}

func (pl *pcaLearner) applyCulling(indexes []int) {
	startT := time.Now()
	addedN := len(indexes)
	covCompIndexes := pl.setCovCompletion(indexes,
		getComplement(indexes, len(pl.phenos)), pl.phenos)
	indexes = append(indexes, covCompIndexes...)
	addedN = len(indexes) - addedN
	if debug {
		fmt.Printf("Coverage completion time: %v - added seeds: %d.\n",
			time.Now().Sub(startT), addedN)
	}

	var toRem []uint64
	comp := getComplement(indexes, len(pl.phenos))
	for _, i := range comp {
		toRem = append(toRem, pl.phenos[i].hash)
	}
	//
	var newPhenos []phenotype
	for _, i := range indexes {
		newPhenos = append(newPhenos, pl.phenos[i])
	}
	pl.phenos = newPhenos

	pl.cullCh <- toRem
}

func describe(fs []float64) {
	if len(fs) < 100 {
		fmt.Printf("len(fs) = %+v\n", len(fs))
		return
	}
	//
	sort.Float64s(fs)
	m, sig := stat.MeanStdDev(fs, nil)
	k := stat.ExKurtosis(fs, nil)
	fmt.Printf("mean %.3v - std: %.3v - k: %.3v  \n", m, sig, k)
	for i := range make([]struct{}, 11) {
		p := float64(i) / 10
		per := stat.Quantile(p, stat.Empirical, fs, nil)
		fmt.Printf("p: %.3v - per: %.3v  \n", p, per)
	}
}

// *****************************************************************************
// ********************** Divisive Hierarchical Clustering *********************
// Originally called DIANA: DIvisive ANAlysis Clustering (where did the 'C' go :P)?
//
// - Have a list of clusters initilized with as a one element list (just the
//   whole).
// - At each step, select a cluster to divide. Here, the selection criteria is
// 	 is the cluster with the higher radius. Radius is the maximum distance from
// 	 one point to the mean of the cluster. Alternatively, could use the diameter
// 	 (longest distance between two points), or Ward's criterion.
// - At some point stop splitting. Here, stops when the list of cluster have a
//   certain length. Alternatively, it could

const kDiv = 2 // Always divide a cluster in 2.

func (pl *pcaLearner) cullD() {
	if !pl.converged { // No need to cull.
		return
	} else if len(pl.phenos) < maxPhenoN/2 {
		log.Printf("len(phenos)=%d -> why cull was called?\n", len(pl.phenos))
		return
	}

	startT := time.Now()
	_, heights, clusts := pl.doDivisiveClustering((maxPhenoN / 2) - 1)

	if debug {
		fmt.Printf("Divisive clustering time: %v.\n", time.Now().Sub(startT))
		//
		fmt.Println("\nHeights:")
		describe(heights)
	}

	sort.Float64s(heights)
	pl.dFloor = heights[len(heights)/5] // Set floor as first quintile.

	indexes := getBestPoints(clusts)
	pl.applyCulling(indexes)
}

// Called only once when the PCA-Learner basis converged and is thus ready to
// be used for fitness calculation. At this moment, if there are more phenotypes
// than the fixed maximum, need to cull. The remnant is itself divided in two
// parts: the one we keep in order to cover all, and the second part that we
// really throw away.
func (pl pcaLearner) convergenceCulling() {
	if !pl.converged { // No need to cull.
		return
	} else if len(pl.phenos) < maxPhenoN+50 {
		// Add the +50 because not worth it in this case. The popPheno function
		// is going to handle it just as well.
		return
	}

	_, _, clusts := pl.doDivisiveClustering(maxPhenoN - 1)
	indexes := getBestPoints(clusts)
	covCompIndexes := pl.setCovCompletion(indexes,
		getComplement(indexes, len(pl.phenos)), pl.phenos)

	var toRem []uint64
	trashIndexes := getComplement(append(indexes, covCompIndexes...), len(pl.phenos))
	for _, i := range trashIndexes {
		toRem = append(toRem, pl.phenos[i].hash)
	}
	//
	var newPhenos, covComp []phenotype
	for _, i := range indexes {
		newPhenos = append(newPhenos, pl.phenos[i])
	}
	for _, i := range covCompIndexes {
		covComp = append(covComp, pl.phenos[i])
	}
	pl.phenos = newPhenos
	pl.covComp = covComp

	pl.cullCh <- toRem
}

func (pl *pcaLearner) doDivisiveClustering(iterN int) (
	means [][]float64, heights []float64, clusts [][]kEle) {

	var (
		radius []float64
		vars   = pl.vars
	)
	//
	// Initialization
	clusts = make([][]kEle, 1, iterN)
	for i := range pl.phenos {
		clusts[0] = append(clusts[0], kEle{index: i})
	}

	for i := 0; i < iterN; i++ {
		var index int
		index, radius = getHighestRad(clusts, radius)
		phenos, relativeIndexes := getPhenos(clusts[index], pl.phenos)

		end := len(clusts) - 1
		if index != end {
			clusts[index], clusts[end] = clusts[end], clusts[index]
			radius[index], radius[end] = radius[end], radius[index]
			means[index], means[end] = means[end], means[index]
		}
		clusts, radius, means = clusts[:end], radius[:end], means[:end]

		// Clustering
		var newMeans [][]float64
		var newClusts [][]kEle
		if len(phenos) < kDiv {
			break
		} else if len(phenos) == kDiv {
			newMeans = [][]float64{phenos[0].proj, phenos[1].proj}
			newClusts = [][]kEle{
				[]kEle{kEle{index: 0}},
				[]kEle{kEle{index: 1}},
			}
		} else {
			newMeans, newClusts = doKMean(kDiv, phenos, vars)
		}

		// Post-clustering
		// a. Append new clusters. Mostly, need for reindexing.
		for _, c := range newClusts {
			var rad float64
			for i := range c {
				c[i].index = relativeIndexes[c[i].index]
				if c[i].dist > rad {
					rad = c[i].dist
				}
			}
			radius = append(radius, rad)
		}
		clusts = append(clusts, newClusts...)
		means = append(means, newMeans...)
		//
		// b. Compute means dists as to get in height.
		var dist float64
		for i, p := range newMeans[0] {
			diff := p - newMeans[1][i]
			dist += diff * diff / vars[i]
		}
		heights = append(heights, math.Sqrt(dist))
	}

	return means, heights, clusts
}

func getHighestRad(clusts [][]kEle, radius []float64) (int, []float64) {
	if len(clusts) < 2 {
		return 0, nil
	}

	var maxRad float64
	var maxI int
	for i, rad := range radius {
		if len(clusts[i]) < kDiv {
			continue
		}
		if rad > maxRad {
			maxRad = rad
			maxI = i
		}
	}

	return maxI, radius
}
func getPhenos(clust []kEle, phenos []phenotype) (
	ps []phenotype, relativeIndexes []int) {

	ps = make([]phenotype, len(clust))
	relativeIndexes = make([]int, len(clust))

	for i, ele := range clust {
		index := ele.index
		ps[i] = phenos[index]
		relativeIndexes[i] = index
	}

	return ps, relativeIndexes
}

// For each cluster, get the phenotype (index) which is the closest to the the
// mean.
func getBestPoints(clusts [][]kEle) (indexes []int) {
	for _, c := range clusts {
		minD := c[0].dist
		minI := c[0].index
		for _, ele := range c[1:] {
			if ele.dist < minD {
				minD = ele.dist
				minI = ele.index
			}
		}
		indexes = append(indexes, minI)
	}
	return indexes
}
