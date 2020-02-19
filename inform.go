package main

import (
	"fmt"
	"log"

	"encoding/csv"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/buger/goterm"
	"github.com/olekukonko/tablewriter"
)

// *****************************************************************************
// ******************************** Reporter ***********************************
// Just write seeds that trigger new _branch_ coverage and "unique" crashes.

const formatT = time.RFC3339Nano

type reporterT struct {
	crashDir string
	//
	seedDir string

	// CSV logging
	startT    time.Time
	statusCSV map[string]*csv.Writer
}

const (
	smName           = "seed_manager"
	recName          = "receiver"
	csvWritingPeriod = 10
)

func makeReporter(target, saveDir string, seedPts seedList) reporterT {
	const defaultSaveDir = "fuzz_report"
	if len(saveDir) == 0 {
		baseDir := filepath.Dir(target)
		saveDir = filepath.Join(baseDir, defaultSaveDir)
	}

	if _, err := os.Stat(saveDir); !os.IsNotExist(err) {
		_ = os.RemoveAll(saveDir)
	}

	progName := filepath.Base(target)
	seeds := fmt.Sprintf("seeds-%s", progName)
	crashes := fmt.Sprintf("crashes-%s", progName)
	reporter := reporterT{
		crashDir: filepath.Join(saveDir, crashes),
		seedDir:  filepath.Join(saveDir, seeds),
	}

	err := os.MkdirAll(reporter.seedDir, 0755)
	if err != nil {
		log.Printf("Couldn't create reporter directory: %v.\n", err)
		return reporterT{}
	}
	err = os.Mkdir(reporter.crashDir, 0755)
	if err != nil {
		log.Printf("Couldn't create reporter crash directory: %v.\n", err)
		return reporterT{}
	}

	for _, seedPt := range seedPts {
		go reporter.repSeed(seedPt)
	}

	// ****** CSV preparation ******
	statusDir := filepath.Join(saveDir, fmt.Sprintf("status_%x", rand.Uint32()))
	err = os.Mkdir(statusDir, 0755)
	if err != nil {
		log.Printf("Could create status dir: %v.\n", err)
		return reporter
	}
	//
	initBSLogger(statusDir)
	//
	names := []string{smName, recName}
	cs := []csvee{smStatus{}, recStatus{}}
	reporter.statusCSV = make(map[string]*csv.Writer)
	for _, name := range names {
		f, err := os.Create(filepath.Join(statusDir, fmt.Sprintf("%s.csv", name)))
		if err != nil {
			log.Printf("Couldn't create %s: %v.\n", name, err)
			return reporter
		}
		reporter.statusCSV[name] = csv.NewWriter(f)
	}
	//
	for i := range cs {
		reporter.initCSV(names[i], cs[i])
	}
	reporter.startT = time.Now()

	return reporter
}

func (rep reporterT) initCSV(name string, c csvee) {
	if _, ok := rep.statusCSV[name]; !ok {
		log.Printf("Unknown name for CSV record: %s.\n", name)
		return
	}
	err := rep.statusCSV[name].Write(append(c.names(), "time"))
	if err != nil {
		log.Printf("Couldn't write title in %s: %v.\n", name, err)
	}
}
func (rep reporterT) logCSV(name string, c csvee) {
	if _, ok := rep.statusCSV[name]; !ok {
		log.Printf("Unknown name for CSV record: %s.\n", name)
		return
	}
	err := rep.statusCSV[name].Write(append(c.strings(),
		fmt.Sprintf("%d", time.Now().Sub(rep.startT)/time.Second)))
	if err != nil {
		log.Printf("Couldn't write title in %s: %v.\n", name, err)
	}
	rep.statusCSV[name].Flush()
	if err := rep.statusCSV[name].Error(); err != nil {
		log.Printf("Error logging to %s: %v.\n", name, err)
	}
}

// **************************************
// *** A. Reporting Seeds and Crashes ***

// Just write the crashes. Assume they have already been checked.
func (rep reporterT) repCrash(point ExecPoint) {
	if len(rep.crashDir) == 0 { // Reporter wasn't initialized.
		return
	}

	path := filepath.Join(rep.crashDir, time.Now().Format(formatT))
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Couldn't create crash file: %v.\n", err)
		return
	}
	_, err = f.Write(point.Input())
	if err != nil {
		log.Printf("Couldn't write crash: %v.\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Printf("Couldn't close crash file: %v.\n", err)
	}
}

func (rep reporterT) repSeed(point ExecPoint) {
	if len(rep.seedDir) == 0 { // Reporter wasn't initialized.
		return
	}

	path := filepath.Join(rep.seedDir, time.Now().Format(formatT))
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Couldn't create seed file: %v.\n", err)
		return
	}
	_, err = f.Write(point.Input())
	if err != nil {
		log.Printf("Couldn't write seed: %v.\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Printf("Couldn't close seed file: %v.\n", err)
	}
}

// *****************************************************
// *** B. Reporting Seed Manager and Receiver Status ***

type csvee interface { // Structure that can easily be recorded in the CSV format.
	names() []string
	strings() []string
}

var _ csvee = smStatus{}
var _ csvee = recStatus{}

// Seed manager status
type smStatus struct {
	mem uint64

	// Seed list status
	seedN int
	//
	fileSizeMean float64
	trSizeMean   float64
	execTimeMean int // In micro seconds (us)

	execN uint
}

func makeSMStatus(seedPts seedList, execN uint) smStatus {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	//
	return smStatus{
		mem: memStats.HeapAlloc / 1e6,
		//
		seedN:        len(seedPts),
		fileSizeMean: seedPts.getFileSizeMean(),
		trSizeMean:   seedPts.getTrSizeMean(),
		execTimeMean: int(seedPts.getExecTimeMean()), // In micro seconds (us)
		//
		execN: execN,
	}
}
func (smStatus) names() []string {
	return []string{
		"mem", "seed_n", "file_size_mean", "tr_size_mean", "exec_time_mean", "execN"}
}
func (sms smStatus) strings() []string {
	return []string{
		fmt.Sprintf("%d", sms.mem),
		fmt.Sprintf("%d", sms.seedN),
		fmt.Sprintf("%f", sms.fileSizeMean),
		fmt.Sprintf("%f", sms.trSizeMean),
		fmt.Sprintf("%d", sms.execTimeMean), // In micro seconds (us)
		fmt.Sprintf("%d", sms.execN),
	}
}

// Receiver status
type recStatus struct {
	edgeN int

	// PCA-Learner
	totVar   float64
	extraVar float64
	dFloor   float64
	oFloor   float64
	vars     []float64
	trueVars []float64
}

type statusRecorder interface {
	makeRecStatus() recStatus
}

func (pcaA *pcaAnalyzer) makeRecStatus() recStatus {
	edgeN := len(pcaA.brList)
	if pcaA.pl == nil {
		return recStatus{edgeN: edgeN}
	}
	//
	// In theory, should call the lock here, but want to minimize impact.
	pl := pcaA.pl
	vars, trueVars := make([]float64, len(pl.vars)), make([]float64, len(pl.trueVars))
	copy(vars, pl.vars)
	copy(trueVars, pl.trueVars)
	return recStatus{
		edgeN:    edgeN,
		totVar:   pl.totVar,
		extraVar: pl.extraVar,
		dFloor:   pl.dFloor,
		oFloor:   pl.oFloor,
		vars:     vars,
		trueVars: trueVars,
	}
}
func (recStatus) names() []string {
	return []string{"edge_n", "tot_var", "extra_var", "d_floor", "o_floor",
		"vars", "true_vars"}
}
func (rs recStatus) strings() []string {
	return []string{
		fmt.Sprintf("%d", rs.edgeN),
		fmt.Sprintf("%f", rs.totVar),
		fmt.Sprintf("%f", rs.extraVar),
		fmt.Sprintf("%f", rs.dFloor),
		fmt.Sprintf("%f", rs.oFloor),
		fmt.Sprintf("%f", rs.vars),
		fmt.Sprintf("%f", rs.trueVars),
	}
}

// *****************************************************************************
// *****************************************************************************
// *********** Restart a new (short) fuzz campaign to collect data *************

func doSomeMoreFuzz(glbDataPt *PUT, seedPts seedList) {
	// Make a not-so-deep copy :P
	newGlbData := new(PUT)
	*newGlbData = *glbDataPt

	// Set parameter for (very short) fuzz campaign.
	newGlbData.seedPts = seedPts
	newGlbData.seedSelector = makeRandomSel(newGlbData)
	evolutivePool = false
	nbRounds := 5 * len(seedPts) / len(newGlbData.puts)

	fmt.Printf("Starting a second fuzzing campaign for %d rounds.\n", nbRounds)
	time.Sleep(5 * time.Second)
	fuzzing(newGlbData, reporterT{}, nbRounds)
}

// *****************************************************************************
// ****************************** End fuzz report ******************************

// EndReport is produced at the end of the fuzzing session and returned to the
// caller.
type EndReport struct {
	TotalRoundNb uint
	TotalCrashes int
	TotalExecs   uint
	BrCov        int // Branch coverage
	BrCovPr      float64
	TupCov       int // Tuple coverage
	TupCovPr     float64

	Stopped bool

	Crashes map[uint64]Crash

	NbSeeds int
	NbHash  int
}

// Strings is a nicer way to visualize the report.
func (endRep EndReport) Strings() (strs []string) {
	/* 0 */ strs = append(strs, fmt.Sprintf("%.1f", 0)) // Total Gain but was removed.
	/* 1 */ strs = append(strs, fmt.Sprintf("%d (%0.2f%%)",
		endRep.BrCov, endRep.BrCovPr))
	/* 2 */ strs = append(strs, fmt.Sprintf("%d (%0.2f%%)",
		endRep.TupCov, endRep.TupCovPr))
	/* 3 */ strs = append(strs, fmt.Sprintf("%d", endRep.TotalCrashes))
	/* 4 */ strs = append(strs, fmt.Sprintf("#seeds: %d", endRep.NbSeeds))
	return strs
}

// StrStds compute the standard deviation of values and put them into strings.
func (endRep EndReport) StrStds(std []float64) (strs []string) {
	strs = endRep.Strings()
	if len(std) == 0 {
		return strs
	}

	strStd := make([]string, len(std))
	for i := range std {
		strStd[i] = fmt.Sprintf("%.3f", std[i])
		strs[i] = fmt.Sprintf("%s\n(std=%s)", strs[i], strStd[i])
	}

	return strs
}

func (endRep EndReport) String() (str string) {
	strs := endRep.Strings()

	str = fmt.Sprintf("gain: %s - ", strs[0])
	str += fmt.Sprintf("#edges: %s - ", strs[1])
	str += fmt.Sprintf("#tuples: %s - ", strs[2])
	str += fmt.Sprintf("#crash: %s - ", strs[3])
	str += fmt.Sprintf("#hash: %.3v - ", float64(endRep.NbHash))
	str += fmt.Sprintf("%s", strs[5])

	return str
}

func endReporting(glbDataPt *PUT) (endRep EndReport) {
	if glbDataPt == nil {
		return endRep
	}

	glbTrace := makeGlbTr()
	for _, seedPt := range glbDataPt.seedPts {
		glbTrace.add(seedPt.traceBits)
	}

	endRep.TotalRoundNb = glbDataPt.totalRoundNb
	endRep.TotalCrashes = len(glbDataPt.crashes)
	endRep.BrCov = countEdges(glbTrace)
	endRep.BrCovPr = 100 * float64(endRep.BrCov) / float64(len(glbTrace))
	endRep.TupCov = countTuples(glbTrace)
	endRep.TupCovPr = 100 * float64(endRep.TupCov) / float64(len(glbTrace)*hitCountLog2Max)
	endRep.Crashes = glbDataPt.crashes
	endRep.NbSeeds = len(glbDataPt.seedPts)
	endRep.NbHash = glbDataPt.nbHash

	var selfExecs uint
	for _, seedPt := range glbDataPt.seedPts {
		endRep.TotalExecs += seedPt.execNb
	}
	for _, nb := range glbDataPt.seedLoops {
		selfExecs += nb
	}

	correctedExecNb := endRep.TotalExecs - selfExecs
	fmt.Printf("Self executions: %.3v (%.3f%%) \n", float64(selfExecs),
		100*float64(selfExecs)/float64(endRep.TotalExecs))
	fmt.Printf("TotalExecs (corrected): %.3v - avg exec/hash: %.3f  \n",
		float64(correctedExecNb), float64(correctedExecNb)/float64(endRep.NbHash))

	fmt.Printf("TotalRoundNb = %+v \n", endRep.TotalRoundNb)

	return endRep
}

type glbTraceT [][]byte

func makeGlbTr() glbTraceT { return make(glbTraceT, mapSize) }
func (gt glbTraceT) add(trace []byte) {
	for i, tr := range trace {
		if tr == 0 {
			continue
		}
		gt[i] = traceInsert(gt[i], tr)
	}
}

func report(glbDataPt *PUT, endRep EndReport) {
	seedPts := glbDataPt.seedPts
	fmt.Printf("\nlen(seedPts) = %+v\n", len(seedPts))

	var subSeedPts seedList
	if len(seedPts) < seedTableMax {
		subSeedPts = seedPts
	} else {
		subSeedPts = seedPts[:seedTableMax]
	}
	subSeedPts.printTable()

	fmt.Printf("known edges: %+v (%.02f%%)\n", endRep.BrCov, endRep.BrCovPr)
	fmt.Printf("known tuples: %d (%.02f%%)\n", endRep.TupCov, endRep.TupCovPr)
	fmt.Printf("#crashes: %d\n", len(endRep.Crashes))
	fmt.Printf("Seeed selection: %s\n", selectionName[selType])
}

// ExploreCrashes can be called after another fuzzer has been used. It will
// check if all specified crashes are real ones.
func ExploreCrashes(args Arguments, testCases [][]byte) (crashes map[uint64]Crash) {
	postParse(&args)

	if sHand == nil {
		StopSoon = make(chan struct{}, sHandBufSize)
		sHand = &signalHandler{}
	}
	sHand.addFrkSrvNb(1)

	glbDataPt := initFuzzing(args.Target, 1, [][]byte{}, args)

	crashes = runCrashes(glbDataPt.puts[0], testCases)

	endFuzzing(glbDataPt)
	return crashes
}

func runCrashes(put frkSrv, testCases [][]byte) (crashes map[uint64]Crash) {
	crashes = make(map[uint64]Crash)
	killerChan := makeNullKillerChan()

	for i, testCase := range testCases {
		if len(testCase) == 0 {
			continue
		}

		runInfo, err := runTarget(put, testCase, execTimeOut, killerChan, true)
		if err != nil {
			log.Printf("Problem running testcase %d: %v.\n", i, err)
			continue
		}

		if runInfo.crashed { // Check the signal?
			hash := hashTrBits(put.traceBits)
			cpyTr := make([]byte, len(put.traceBits))
			copy(cpyTr, put.traceBits)
			crashes[hash] = Crash{
				In:        testCase,
				HashVal:   hash,
				traceBits: cpyTr,
			}
		}
	}

	return crashes
}

// ******************************************************************************
// *********************************** Display **********************************

var selectionName = map[int]string{
	randSel:   "Random",
	pcaWmoSel: "PCA Weighted Multi-O",
}

// Debug print will only print if in debug mode.
func dbgPr(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format, a...)
	}
}

func (seedPts seedList) printTable() {
	if len(seedPts) == 0 {
		return
	}

	strs0 := seedPts[0].strings()
	strs0 = strs0[:len(strs0)]
	header := make([]string, len(strs0))
	for i := range strs0 {
		header[i] = strs0[i][0]
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)

	for _, seedPt := range seedPts {
		strs := seedPt.strings()
		strs = strs[:len(strs)]
		row := make([]string, len(strs))
		for i := range strs {
			row[i] = strs[i][1]
		}
		table.Append(row)
	}

	table.Render()
}

func printTable(header []string, content [][]string) {
	if len(content) == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	for _, c := range content {
		table.Append(c)
	}
	table.Render()
}

func (glbInfo *infoRecord) printStatus(roundNb int, glbDataPt *PUT, extraStr string,
	selection seedList) {

	cleanScreen()

	seedPts := glbDataPt.seedPts

	gtPrintf("\nTarget: %s\n", glbDataPt.progName)
	gtPrintf("round number: %v (%v)\n", roundNb,
		time.Duration(roundNb)*time.Second)
	gtPrintf("len(seedPts) = %+v - throughput: %.3v\n", len(seedPts), glbInfo.throughput())

	gtPrintf("total unique crashes: %+v - ", len(glbDataPt.crashes))
	gtPrintf("hangs: %+v\n", glbDataPt.totalHangs)
	gtPrintf("%s", extraStr)

	var subSeedPts seedList
	if len(seedPts) < seedTableMax {
		subSeedPts = seedPts
	} else {
		subSeedPts = seedPts[:seedTableMax]
	}
	if selType != randSel {
		subSeedPts.printTable()
	}

	gtPrintf("\n")
	goterm.Flush()
}

func gtPrintf(format string, a ...interface{}) {
	_, err := goterm.Printf(format, a...)
	if err != nil {
		log.Printf("Error while using goterm: %v.\n", err)
	}
}

func printScore(guiTraces [][]byte) (str string) {
	str = fmt.Sprintf("score[%d]: %.f\t", 3,
		scoreGlb(guiTraces, 3))
	str += fmt.Sprintf("score[%d]: %.f", 5,
		scoreGlb(guiTraces, 5))
	return str
}

var (
	glbRnds  []float64
	glbGains []float64
)

// Also called branch coverage.
func countEdges(glbTrace [][]byte) (count int) {
	for _, tr := range glbTrace {
		if len(tr) > 0 {
			count++
		}
	}
	return count
}

// AFL style 'tuple coverage'.
// Appears as 'map density' on his retro screen.
func countTuples(glbTrace [][]byte) int {
	tuples := make(map[int]struct{})
	for branchI, tr := range glbTrace {
		for _, val := range tr {
			_, log2 := math.Frexp(float64(val))
			tupleI := hitCountLog2Max*branchI + log2
			tuples[tupleI] = struct{}{}
		}
	}
	return len(tuples)
}

func cleanScreen() {
	goterm.MoveCursor(1, 1)
	width := goterm.Width()
	strLine := ""

	if width > 0 {
		line := make([]byte, width)
		for i := range line {
			line[i] = 0x20
		}
		strLine = string(line)
	}

	var err error
	height := goterm.Height()
	for i := 0; i < height; i++ {
		_, err = goterm.Printf("%s\n", strLine)
	}
	if err != nil {
		log.Printf("Problem while cleaning screen: %v.\n", err)
	}

	goterm.Flush()
	goterm.MoveCursor(1, 1)
}
