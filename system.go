package main

import (
	"fmt"
	"log"

	"encoding/binary"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	// For memory profiling
	"runtime/pprof"

	// Raw execution
	"bytes"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// *****************************************************************************
// *************************** CPU Affinity Managing ***************************

func lockRoutine(usedCPUs []bool) (origSet unix.CPUSet) {
	err := unix.SchedGetaffinity(0, &origSet)
	if err != nil {
		log.Printf("Failed to get current cpuset.\n")
		return origSet
	}

	runtime.LockOSThread()

	targetedCPU := -1
	var unusedCPUs []int
	for cpu, used := range usedCPUs {
		if used {
			continue
		}
		unusedCPUs = append(unusedCPUs, cpu)
	}
	if len(unusedCPUs) > 0 {
		targetedCPU = unusedCPUs[rand.Intn(len(unusedCPUs))]
		usedCPUs[targetedCPU] = true

	} else { // No CPU available.
		log.Print("No CPU available.")
		initProblem = true
		return origSet
	}

	var set unix.CPUSet
	set.Zero()
	set.Set(targetedCPU)

	err = unix.SchedSetaffinity(0, &set)
	if err != nil {
		log.Printf("Could not associate PUT with a CPU: %v.\n", err)
	}
	return origSet
}

func cntUsedCPUs() (cnt int) {
	usedCPUs := GetUsedCPUs()
	for _, isUsed := range usedCPUs {
		if isUsed {
			cnt++
		}
	}
	return cnt
}

var getCPUMtx sync.Mutex

// GetUsedCPUs return CPUs available for fuzzing (meaning, can be binded to
// fuzzer)
func GetUsedCPUs() (usedCPUs []bool) {
	getCPUMtx.Lock()
	defer getCPUMtx.Unlock()
	nbCPU := runtime.NumCPU()
	usedCPUs = make([]bool, nbCPU)

	procDir, err := ioutil.ReadDir("/proc")
	if err != nil {
		log.Printf("Could not read /proc: %v.\n", err)
		for i := range usedCPUs { // Mark all CPU as used
			usedCPUs[i] = true
		}
		return
	}

	for _, procFileInfo := range procDir {
		if !procFileInfo.IsDir() { // Only care about dirs
			continue
		}
		name := procFileInfo.Name()
		if name[0] < '0' || name[0] > '9' { // Only care about pids
			continue
		}

		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}

		var set unix.CPUSet
		set.Zero()
		err = unix.SchedGetaffinity(pid, &set)
		if err != nil {
			//log.Printf("Problem getting affinity of %s: %v.\n", name, err)
			continue
		}

		count := set.Count()
		if count == nbCPU {
			continue
		}
		status, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			log.Printf("Cannot read %s status: %v.\n", name, err)
			continue
		}
		if !strings.Contains(string(status), "VmSize") { // Prob' kernel task
			continue
		}

		for cpu := range usedCPUs {
			if set.IsSet(cpu) {
				usedCPUs[cpu] = true
			}
		}
	}

	return usedCPUs
}

func lockProcessCPU() {
	usedCPUs := GetUsedCPUs()

	targetedCPU := -1
	for cpu, used := range usedCPUs {
		if !used {
			targetedCPU = cpu
			usedCPUs[targetedCPU] = true
			break
		}
	}

	if targetedCPU < 0 {
		log.Print("No CPU to lock process to")
		return
	}

	var set unix.CPUSet
	set.Zero()
	set.Set(targetedCPU)

	tids := getThreadIDList()

	for _, tid := range tids {
		dbgPr("Locking tid %d to cpu %d.\n", tid, targetedCPU)
		err := unix.SchedSetaffinity(tid, &set)
		if err != nil {
			log.Printf("Could not associate PUT with a CPU: %v.\n", err)
		}
	}
}

func getThreadIDList() (list []int) {
	pid := os.Getpid()
	taskPath := fmt.Sprintf("/proc/%d/task", pid)

	tids, err := ioutil.ReadDir(taskPath)
	if err != nil {
		log.Print(err)
		return list
	}

	list = make([]int, len(tids))
	for i, strTid := range tids {
		tid, err := strconv.Atoi(strTid.Name())
		if err != nil {
			log.Print(err)
			continue
		}
		list[i] = tid
	}

	return list
}

// *****************************************************************************
/************************************** SHM ***********************************/
// Use syscalls directly without using cgo.

const (
	ipcPrivate = 0
	ipcCreat   = 0x200
	ipcExcl    = 0x400
	ipcRmid    = 0
)

func setupShm() (uintptr, []byte) {
	id, _, err := syscall.RawSyscall(syscall.SYS_SHMGET, ipcPrivate, mapSize,
		ipcCreat|ipcExcl|0600)
	if err != 0 {
		log.Fatalf("Problem creating a new shared memory segment: %v\n", err)
	}

	segMap, _, err := syscall.RawSyscall(syscall.SYS_SHMAT, id, 0, 0)
	if err != 0 || id < 0 {
		log.Fatalf("Problem attaching segment: %v\n", err)
	}

	// Dirty thing we have to do (to use AFL instrumentation).
	traceBitPt := (*[mapSize]byte)(unsafe.Pointer(segMap))

	return id, (*traceBitPt)[:]
}

func closeShm(id uintptr) {
	_, _, err := syscall.RawSyscall(syscall.SYS_SHMCTL, id, ipcRmid, 0)
	if err != 0 {
		log.Fatalf("Problem closing shared memory segment: %v\n", err)
	}
}

func zeroShm(traceBitPt []byte) {
	for i := range traceBitPt {
		traceBitPt[i] = 0
	}
}

// *****************************************************************************
/******************************* Fork Server **********************************/

const (
	forksrvFd = 198

	// Memory Sanitizer configuration usage, from AFL:
	// "MSAN is tricky, because it doesn't support abort_on_error=1 at this
	// point. So, we do this in a very hacky way."
	// Meaning, defines a signal that will be sent when security policy of msan
	// is activated, and we catch that.
	msanError = 86

	shmEnvVar        = "__AFL_SHM_ID"
	persistentEnvVar = "__AFL_PERSISTENT"
	deferEnvVar      = "__AFL_DEFER_FORKSRV"
	asanVar          = "ASAN_OPTIONS"
	msanVar          = "MSAN_OPTIONS"

	persistentSig = "##SIG_AFL_PERSISTENT##"
	deferSig      = "##SIG_AFL_DEFER_FORKSRV##"
	asanDetect    = "libasan.so"
	msanDetect    = "__msan_init"
)

var usesMsan bool

func prepareProcAttr(shmID uintptr, args Arguments) (
	procAttr *syscall.ProcAttr, tcWriter putWriter) {

	env := os.Environ()
	env = append(env, getExtraEnvs(args.Target, shmID)...)

	var files []uintptr
	if args.Stdin {
		var ok bool
		ok, tcWriter, files = makeStdinPUTWriter()
		if !ok {
			panic("Could not start stdin-based PUT")
		}

	} else if args.FileIn {
		fileInName := fmt.Sprintf("/tmp/tmp-%d", rand.Int())
		tcWriter = &fileIO{path: fileInName}
		files = []uintptr{devNull.Fd(), devNull.Fd(), devNull.Fd()}

		for i := range args.Argv {
			if index := isFileIn(args.Argv[i]); index != 0 {
				newArgv := ""
				if index-2 > 0 {
					newArgv += args.Argv[i][:index-2]
				}
				newArgv += fileInName
				if index > len(args.Argv[i]) {
					newArgv += args.Argv[i][index:]
				}

				dbgPr("newArgv: %s.\n", newArgv)
				args.Argv[i] = newArgv
			}
		}
	}

	var sysProcAttr syscall.SysProcAttr
	sysProcAttr.Setsid = true

	procAttr = &syscall.ProcAttr{
		Env:   env,
		Files: files,
		Sys:   &sysProcAttr,
	}
	return
}

func getExtraEnvs(binPath string, shmID uintptr) (envs []string) {
	binContent, err := ioutil.ReadFile(binPath)
	if err != nil {
		log.Fatalf("Couldn't open the binary: %v.\n", err)
	}

	// Shared memory with the PUT to get the branch hit count.
	reShm := regexp.MustCompile(shmEnvVar)
	if !reShm.Match(binContent) {
		log.Fatal("This binary wasn't instrumented correctly.")
	}
	envs = append(envs, fmt.Sprintf("%s=%d", shmEnvVar, shmID))
	//
	// Persitent mode
	rePer := regexp.MustCompile(persistentSig)
	if rePer.Match(binContent) {
		fmt.Println("Persistent mode detected.")
		envs = append(envs, fmt.Sprintf("%s=1", persistentEnvVar))
	}
	//
	// Deferred fork server
	reDef := regexp.MustCompile(deferSig)
	if reDef.Match(binContent) {
		fmt.Println("Deferred fork server detected.")
		envs = append(envs, fmt.Sprintf("%s=1", deferEnvVar))
	}

	// Address and Memory SANitizers
	reASAN := regexp.MustCompile(asanDetect)
	reMSAN := regexp.MustCompile(msanDetect)
	isAsan, isMsan := reASAN.Match(binContent), !reMSAN.Match(binContent)
	if !isAsan && !isMsan {
		return envs
	} else if isMsan {
		usesMsan = true
	}
	//
	// ASAN
	asanOps, ok := os.LookupEnv(asanVar)
	if ok {
		if !regexp.MustCompile("abort_on_error=1").MatchString(asanOps) {
			log.Fatal("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!")
		} else if !regexp.MustCompile("symbolize=0").MatchString(asanOps) {
			log.Fatal("Custom ASAN_OPTIONS set without symbolize=0 - please fix!")
		}
	} else {
		envs = append(envs, fmt.Sprintf("%s=abort_on_error=1:detect_leaks=0:"+
			"symbolize=0:allocator_may_return_null=1", asanVar))
	}
	// MSAN
	ec := fmt.Sprintf("exit_code=%d", msanError)
	msanOps, ok := os.LookupEnv(msanVar)
	if ok {
		if !regexp.MustCompile(ec).MatchString(msanOps) {
			log.Fatalf("Custom MSAN_OPTIONS set without %s - please fix!\n", ec)
		} else if !regexp.MustCompile("symbolize=0").MatchString(msanOps) {
			log.Fatal("Custom MSAN_OPTIONS set without symbolize=0 - please fix!")
		}
	} else {
		envs = append(envs, fmt.Sprintf("%s=%s:symbolize=0:abort_on_error=1:"+
			"allocator_may_return_null=1:msan_track_origins=0", msanVar, ec))
	}

	return envs
}

func isFileIn(arg string) int {
	for i := len(arg); i > 1; i-- {
		subStr := arg[i-2 : i]
		if subStr == "@@" {
			return i
		}
	}
	return 0
}

// Could return error here rather than checking nil pointers when return.
// But a bit annoying because a lot of operations done in pair.
func initForkserver(execTarget string, procAttr *syscall.ProcAttr,
	args Arguments) (f1 *os.File, f2 *os.File, pid int) {

	ctlPipeR, ctlPipeW, stPipeR, stPipeW := createPipes()

	// Want to fork, dup2&close and then execv...
	// Problem is, it's not possible to 'just' fork in Go (because of the Go run
	// time), it needs to directly exec something else.
	// Going to solve this by dup2-ing beforehand and flagging what should be
	// closed as close-on-exec.
	err1 := syscall.Dup2(ctlPipeR, forksrvFd)
	err2 := syscall.Dup2(stPipeW, forksrvFd+1)
	if err1 != nil || err2 != nil {
		log.Printf("Error while dup2-licating pipes: (ctl) %v - (st) %v\n",
			err1, err2)
		return nil, nil, pid
	}

	err1 = syscall.Close(ctlPipeR)
	err2 = syscall.Close(stPipeW)
	if err1 != nil || err2 != nil {
		log.Printf("Error while closing unused pipes: (ctl) %v - (st) %v\n",
			err1, err2)
		return nil, nil, pid
	}

	// To be fully 'clean' ctlPipeW and stPipeR are flagged  as
	// O_CLOEXEC so they are not accessible by the PUT (child processes).
	// It would be a problem if PUT read/write these instead of us.
	_, _, errno1 := syscall.RawSyscall(syscall.SYS_FCNTL, ctlPipeW.Fd(),
		syscall.F_SETFD, syscall.FD_CLOEXEC)
	_, _, errno2 := syscall.RawSyscall(syscall.SYS_FCNTL, stPipeR.Fd(),
		syscall.F_SETFD, syscall.FD_CLOEXEC)
	if errno1 != 0 || errno2 != 0 {
		log.Printf("Problem setting ctlPipeW and stPipeR flag to CLOEXEC."+
			" errno: (ctlPipeW) %d (stPipeR) %d\n", errno1, errno2)
		return nil, nil, pid
	}

	// Fork
	pid, err := syscall.ForkExec(execTarget, args.Argv, procAttr)
	if err != nil {
		log.Fatalf("Failed to ForkExec %s: %v\n", execTarget, err)
	}

	// Fork epilogue
	err1 = syscall.Close(forksrvFd)
	err2 = syscall.Close(forksrvFd + 1)
	if err1 != nil || err2 != nil {
		log.Printf("Error while closing the fork server (main process) pipes:"+
			"(ctl) %v - (st) %v\n",
			err1, err2)
		return nil, nil, pid
	}

	timer := setExecTimer(3*execTimeOut, pid)
	// Last check: reading to check fork server is ready.
	encodedStatus := make([]byte, 4)
	_, err = stPipeR.Read(encodedStatus)
	if err != nil {
		log.Printf("Fork server handshake failed: %v\n", err)
		return nil, nil, pid
	}
	status := binary.LittleEndian.Uint32(encodedStatus)
	sig, crashed := checkStatus(syscall.WaitStatus(status))

	if !timer.Stop() || crashed {
		log.Printf("Fork server did not start correctly: %v.\n", sig)
		return nil, nil, pid
	}
	return ctlPipeW, stPipeR, pid
}

// ************** io.Writers **************
// Define how test cases are given to the PUT

type putWriter interface {
	io.Writer
	clean()
}

var devNull *os.File

func init() {
	var err error
	devNull, err = os.OpenFile(os.DevNull, os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("Could not open pipes /dev/null: %v.\n", err)
	}
}

type fileIO struct {
	path string
}

func (fio fileIO) Write(tc []byte) (n int, err error) {
	err = os.Remove(fio.path)
	if err != nil {
		log.Printf("Problem removing test case path %s: %v.\n", fio.path, err)
	}
	f, err := os.OpenFile(fio.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Printf("Could not open test case file %s: %v.\n", fio.path, err)
	}
	n, err = f.Write(tc)
	if err != nil {
		return n, err
	}
	err = f.Close()
	return n, err
}
func (fio fileIO) clean() {}

// **************************

type stdinIO struct{ *os.File }

func (sio stdinIO) Write(tc []byte) (n int, err error) {
	_, err = sio.File.Seek(0, os.SEEK_SET) // Reset head from last read.
	if err != nil {
		log.Printf("Error moving head of stdin writing: %v.\n", err)
	}
	n, err = sio.File.Write(tc)
	if err != nil {
		return n, err
	}
	err = sio.File.Truncate(int64(n)) // To ensure no "spill over" from last write.
	if err != nil {
		return n, err
	}
	_, err = sio.File.Seek(0, os.SEEK_SET) // To prepare the PUT reading.
	return n, err
}
func (sio stdinIO) clean() {
	name := sio.Name()
	errClose := sio.Close()
	if errClose != nil {
		log.Printf("Problem closing previous file descriptor: %v.\n", errClose)
	}
	err := os.Remove(name)
	if err != nil {
		log.Printf("Could not close input file: %v\n", err)
	}
}

func makeStdinPUTWriter() (ok bool, pw putWriter, files []uintptr) {
	fileInName := fmt.Sprintf("/tmp/tmp-%x", rand.Int63())
	// Need to use the system call directly because std library use O_CLOEXEC
	// making impossible to pass this file to child.
	fd, err := syscall.Open(fileInName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Printf("Could not open %s: %v\n", fileInName, err)
		return
	}
	f := os.NewFile(uintptr(fd), fileInName)
	//
	ok, pw = true, stdinIO{File: f}
	files = []uintptr{f.Fd(), devNull.Fd(), devNull.Fd()}
	return ok, pw, files
}

// *****************************************************************************
// ****************************** Raw Execution ********************************
// Execution without the need for a fork server.
type rawExecutor interface {
	exec([]byte, time.Duration) *os.ProcessState
}
type stdinRawExec struct{ target string }

func makeRawExec(target string, args Arguments) (rawExec rawExecutor) {
	if args.Stdin {
		rawExec = stdinRawExec{target}
	}
	return rawExec
}

func (sre stdinRawExec) exec(input []byte, timeout time.Duration) (state *os.ProcessState) {
	baseName := filepath.Base(sre.target)
	cmd := exec.Command(sre.target)
	cmd.Stdin = bytes.NewReader(input)

	timer := time.AfterFunc(timeout, func() {
		if cmd.Process == nil {
			return
		}
		err := cmd.Process.Kill()
		if err != nil {
			dbgPr("Could not kill %s after timeout: %v.\n", baseName, err)
		}
	})

	err := cmd.Run()
	state = cmd.ProcessState
	if err != nil {
		dbgPr("Error while raw-running %s: %v.\n", baseName, err)
	}
	if !timer.Stop() {
		dbgPr("Timer for calibration fired\n")
	}

	return state
}

// *********************** Pipe Utils ***********************

func createPipes() (ctlPipeR int, ctlPipeW, stPipeR *os.File,
	stPipeW int) {

	var ctlPipe, stPipe [2]int
	err1 := syscall.Pipe(ctlPipe[0:])
	err2 := syscall.Pipe(stPipe[0:])
	if err1 != nil || err2 != nil {
		log.Fatalf("Error while creating pipes: (ctl) %v - (st) %v\n",
			err1, err2)
	}

	// Ensure no collision with AFL fork server
	ctlPipe[0] = moveFd(ctlPipe[0])
	ctlPipe[1] = moveFd(ctlPipe[1])
	stPipe[0] = moveFd(stPipe[0])
	stPipe[1] = moveFd(stPipe[1])

	ctlPipeR = ctlPipe[0]
	ctlPipeW = os.NewFile(uintptr(ctlPipe[1]), "|1")
	stPipeR = os.NewFile(uintptr(stPipe[0]), "|0")
	stPipeW = stPipe[1]
	return
}

func moveFd(fd int) int {
	if fd == forksrvFd || fd == forksrvFd+1 {
		newFd, err := unix.Dup(fd)
		if err != nil {
			log.Fatalf("Could not copy fd: %v.\n", err)
		}
		newFd = moveFd(newFd)

		err = unix.Close(fd)
		if err != nil {
			log.Fatalf("Could not close old fd: %v.\n", err)
		}

		if debug {
			log.Printf("Moved fd from %d to %d.\n", fd, newFd)
		}
		return newFd
	}
	return fd
}

func moveFileFd(file *os.File) *os.File {
	fd := int(file.Fd())
	newFd := moveFd(fd)

	// Nothing to do. Everything was fine.
	if fd == newFd {
		return file
	}

	moveFd(newFd)
	// Need to create a new "golang file structure" around the new fd.
	newFile := os.NewFile(uintptr(newFd), file.Name())

	return newFile
}

func enlargePipe(pipe *os.File) {
	if debug {
		_ = getPipeSize(pipe)
	}

	_, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, pipe.Fd(),
		syscall.F_SETPIPE_SZ, fileSizeMax)
	if errno != 0 {
		log.Fatalf("Could not enlarge file: %s.\n", errno.Error())
	}

	if debug {
		_ = getPipeSize(pipe)
	}
}

func getPipeSize(pipe *os.File) (size uintptr) {
	size, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, pipe.Fd(),
		syscall.F_GETPIPE_SZ, 0)
	if errno != 0 {
		log.Fatalf("Could not get pipe size: %s.\n", errno.Error())
	}
	fmt.Printf("pipe size = %+v\n", size)
	return
}

// Unused. Did not solve the problem I was looking at.
func setRLimMax(ressource int) {
	var rlim unix.Rlimit
	err := unix.Getrlimit(ressource, &rlim)
	if err != nil {
		log.Printf("Failed to get rlimit nb of file: %v\n.", err)
		return
	}

	rlim.Cur = rlim.Max
	err = unix.Setrlimit(ressource, &rlim)
	if err != nil {
		log.Printf("Failed to set rlimit nb of file: %v.\n", err)
	}
}

// *****************************************************************************
// ****************************** Signal Handler *******************************

const (
	failTime     = 10 * time.Second
	sHandBufSize = 100
	doMemProfile = false
)

type signalHandler struct {
	signalChan  chan os.Signal
	totalSignal int // signal to send when interrupted
	totSigChan  chan int
	started     bool
	//
	mtx         sync.Mutex
	interrupted bool
}

var (
	// StopSoon has receives struct{}{}'s whenever program is Interrupted by
	// user.
	StopSoon  chan struct{}
	stopSHand chan struct{}
	sHand     *signalHandler
)

func init() {
	stopSHand = make(chan struct{})
	go func() {
		<-stopSHand
		if sHand != nil {
			sHand.stop()
		}
	}()
}

// StopFuzzing signal the fuzzer it should stop fuzzing. Equivalent to an
// interrupt.
func StopFuzzing() {
	sHand.mtx.Lock()
	sHand.interrupted = true
	sHand.mtx.Unlock()
	for i := 0; i < sHandBufSize; i++ {
		StopSoon <- struct{}{}
	}
	_ = time.AfterFunc(failTime, func() {
		panic("Interrupted; should stop (StopSoon)")
	})
}

func (sHand *signalHandler) addFrkSrvNb(frkSrvNb int) {
	if !sHand.started {
		sHand.start()
	}

	sHand.totalSignal += frkSrvNb

	if sHand.totalSignal < 1 {
		sHand.stop()
	}
}

func (sHand *signalHandler) start() {
	sHand.started = true
	sHand.signalChan = make(chan os.Signal)
	signal.Notify(sHand.signalChan, os.Interrupt)

	go func() {
		for range sHand.signalChan {
			if doMemProfile { // If debugging, do memory profiling before doing anything.
				memProfile()
			}

			for i := 0; i < sHandBufSize; i++ {
				StopSoon <- struct{}{}
			}
			sHand.mtx.Lock()
			sHand.interrupted = true
			sHand.mtx.Unlock()
			_ = time.AfterFunc(failTime, func() {
				panic("Interrupted; should stop (signal handler)")
			})
		}
	}()
}

func (sHand *signalHandler) stop() {
	signal.Stop(sHand.signalChan)
	sHand.started = false
}
func (sHand *signalHandler) wasInterrupted() (interrupted bool) {
	sHand.mtx.Lock()
	interrupted = sHand.interrupted
	sHand.mtx.Unlock()
	return interrupted
}

// *** memory snapshot for debugging ***
func memProfile() {
	f, err := os.Create("fuzz_mem_profile.out")
	if err != nil {
		log.Printf("Error while creating memory profile file: %v.\n", err)
		return
	}

	runtime.GC()
	err = pprof.WriteHeapProfile(f)
	if err != nil {
		log.Printf("pprof failed to create memory profile: %v.\n", err)
	}

	//memStats := new(runtime.MemStats)
	//runtime.ReadMemStats(memStats)
	//fmt.Printf("memStats = %+v\n", memStats)
}
