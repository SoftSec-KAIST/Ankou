Ankou
===

Ankou is a source-based grey-box fuzzer. It intends to use a more rich fitness
function by going beyond simple branch coverage and considering the
*combination* of branches during program execution.
The details of the technique can be found in our paper "Ankou: Guiding Grey-box
Fuzzing towards Combinatorial Difference", which is published in ICSE 2020.

## Dependencies.

#### Go
Ankou is written solely in Go and thus requires its
[installation](https://golang.org/doc/install). Be sure to configure this
`GOPATH` environment variable, for example to `~/go` directory.

#### AFL
Ankou relies on [AFL](http://lcamtuf.coredump.cx/afl/) instrumentation: fuzzed
targets needs to compiled using `afl-gcc` or `afl-clang`. To install AFL:
```bash
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar xf afl-latest.tgz
cd afl-2.52b
make
# The last command is optional, but you'll need to provide the absolute path to
# the compiler in the configure step below if you don't install AFL compiler.
sudo make install
```

#### GDB

For the triaging `gdb` is required, and ASLR needs to be deactivated:
```bash
sudo echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
Note that when using docker containers, this needs to be run in the host.

## Installation

Once Go and AFL are installed, you can get Ankou by:
``` bash
go get github.com/SoftSec-KAIST/Ankou   # Clone Ankou and its dependencies
go build github.com/SoftSec-KAIST/Ankou # Compile Ankou
```

##### Note: If getting Ankou from another location, this needs to be done manually:
```bash
mkdir -p $GOPATH/src/github.com/SoftSec-KAIST
cd $GOPATH/src/github.com/SoftSec-KAIST
git clone REPO  # By default REPO is https://github.com/SoftSec-KAIST/Ankou
cd Ankou
go get .    # Get dependencies
go build .  # Compile
```

## Usage

Now we are ready to fuzz. We first to compile any target we want with `afl-gcc`
or `afl-clang`. Let's take the classical starting example for fuzzing, binutils:
```bash
wget https://mirror.ibcp.fr/pub/gnu/binutils/binutils-2.33.1.tar.xz
tar xf binutils-2.33.1.tar.xz
cd binutils-2.33.1
CC=afl-gcc CXX=afl-g++ ./configure --prefix=`pwd`/install
make -j
make install
```

Now we are ready to run Ankou:
```bash
cd install/bin
mkdir seeds; cp elfedit seeds/ # Put anything in the seeds folder.
go run github.com/SoftSec-KAIST/Ankou -app ./readelf -args "-a @@" -i seeds -o out
# Or use the binary we compiled above:
/path/to/Ankou -app ./readelf -args "-a @@" -i seeds -o out
```

## Evaluation Reproduction

Once Ankou is installed, in order to reproduce the Ankou evaluation:
1. Compile the 24 packages mentioned in the paper at the same version or
   commit using `afl-gcc`. All the packages' source can be found with the
   same version used in Ankou evaluation at
   https://github.com/SoftSec-KAIST/Ankou-Benchmark. Additionnally, this
   repository includes the seeds used to initialize the evalution fuzzing
   campaigns.
2. Run the produced subjects with the commands found in
   `benchmark/configuration.json`. `benchmark/rq1_rq3.json` only contains the
   24 subjets used for Research Question 1 and 3 of the paper.
3. Analyze Ankou output directory for results. Crashes are listed in
   `$OUTPUT_DIR/crashes-*` and found seeds in `$OUTPUT_DIR/seeds-*`.
   Statistics of the fuzzing campaign can be found in the
   `$OUTPUT_DIR/status*` directory CSV files. The `edge_n` value of
   `receiver.csv` represents the branch coverage. And the `execN` column of
   `seed_manager.csv` represents the total number of test cases executed so
   far. Divide it by the `time` column to obtain the throughout.

There are too many programs in our benchmark, so we will use only one package
in this example: cflow.

1. Compilation.
```bash
git clone https://github.com/SoftSec-KAIST/Ankou-Benchmark
cd Ankou-Benchmark
tar xf seeds.tar.xz
cd sources
tar xf cflow-1.6.tar.xz
cd cflow-1.6
CC=afl-gcc CXX=afl-g++ ./configure --prefix=`pwd`/build
make -j
make install
cd ../../..
```

2. Preparation of the fuzzing campaign.
```bash
mkdir fuzzrun
cp Ankou-Benchmark/sources/cflow-1.6/build/bin/cflow fuzzrun
cp -r Ankou-Benchmark/seeds/cflow fuzzrun/seeds
```

3. Run the campaign. The above starts a 24 hours fuzzing campaign. The '-dur'
option can be adjusted, or Ankou interrupted earlier. In this version of
cflow, and initialized with these seeds, a crash should be found in less than
an hour.
```bash
cd fuzzrun
go run github.com/SoftSec-KAIST/Ankou -app cflow -args "-o /dev/null @@" \
    -i seeds -threads 1 -o cflow_out -dur 24h
```

4. Results analysis
```bash
cd cflow_out/status_*
# Print the final branch coverage:
python -c "print(open('receiver.csv').readlines()[-1].split(',')[0])"
# Print the overall throughput:
python -c "last = open('seed_manager.csv').readlines()[-1].split(','); print(float(last[5])/int(last[6]))"
# Print effectiveness of the dynamic PCA (see RQ2):
python -c "last = open('receiver.csv').readlines()[-1].split(','); print('{}%'.format(100-100*float(last[2])/float(last[1])))"
```

### Safe Stack Hash Triaging

Once the environment is setup, the scripts works in two steps:
1. Run the binary on the crashing input to produce a `core` file.
Using `ulimit -c unlimited` ensures the core to be dumped.
2. Use the scripts in the `triage` folder of this repository:
```bash
cd $GOPATH/src/github.com/SoftSec-KAIST/Ankou/triage
gdb -x triage.py -x triage.gdb -batch -c /path/to/core /path/to/binary
cat hash.txt # The stack hashes are found in this text file.
```
