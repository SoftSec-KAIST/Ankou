package main

import (
	"fmt"

	"math/rand"
	"time"
)

// *****************************************************************************
// ************************** Analysis Benchmark *******************************

func benchHash(seedPts seedList) (hashes []uint64) {
	hashes = make([]uint64, len(seedPts))
	start := time.Now()

	for i, seedPt := range seedPts {
		hashes[i] = hashTrBits(seedPt.traceBits)
	}

	fmt.Printf("Avg time per hash computation: %v.\n",
		time.Now().Sub(start)/time.Duration(len(seedPts)))
	return hashes
}

// *****************************************************************************
// *************************** Mutation Benchmark ******************************

var benchMutDict [][]byte

func benchMutSeed(seed *seedT) (durs map[string]time.Duration, ret [][]byte) {
	durs = make(map[string]time.Duration)
	rSrc := rand.New(rand.NewSource(rand.Int63()))
	m := makeBasicMutator(rSrc, benchMutDict, nil, 1, len(seed.input))

	for fi, f := range m.funcs {
		tcLen := len(seed.input)
		tc := make([]byte, tcLen)
		copy(tc, seed.input)
		oldTc := tc

		contracts := make([]mutationContract, len(m.funcs))
		for i, f := range m.funcs {
			contracts[i] = f.getMutContract(tcLen)
		}

		name := f.name()
		contract := contracts[fi]

		var benchNb int = 1e7
		if contract.changeLen != nil {
			benchNb /= 100
		}
		start := time.Now()
		for i := 0; i < benchNb; i++ {
			specs := contract.specs
			decisions := make([]int, len(specs))

			for j, specs := range specs {
				var dec int
				if specs.dependency != nil {
					dec = specs.dependency(m.rSrc, decisions)
				} else {
					interval := specs.max - specs.min
					dec = specs.min
					if interval > 1 {
						dec += m.rSrc.Intn(interval)
					}
				}
				decisions[j] = dec
			}

			tc = f.mutate(decisions, tc)
			if len(tc) != len(oldTc) {
				tc = oldTc
			}

			if contract.changeLen != nil {
				tcLen = contract.changeLen(decisions, tcLen)
				for i, f := range m.funcs {
					contracts[i] = f.getMutContract(tcLen)
				}
			}
		}

		dur := time.Now().Sub(start) / time.Duration(benchNb)
		fmt.Printf("Avg mutation time of %s: %v. \n", name, dur)
		durs[name] = dur
		ret = append(ret, tc)
	}

	return durs, ret
}
