package main

import (
	"log"

	"io/ioutil"
	"os"
	"path/filepath"
)

// ***** local chosers *****
type localMeta struct {
	// Ressource management
	killerChan chan func()
	freeer     func()
}

func (locC *localMeta) free() {
	if locC.freeer != nil {
		locC.freeer()
	}
}

func makeDictWords(dictPath string) (words [][]byte) {
	if len(dictPath) == 0 { // No dictionnary given by user.
		return
	}

	stat, err := os.Stat(dictPath)
	if err != nil {
		log.Printf("Problem while reading dictionary path: %v.\n", err)
		return words
	}

	if !stat.IsDir() {
		log.Print("Sorry, dictionary file format not implemented yet")
		return words
	}

	fileInfos, err := ioutil.ReadDir(dictPath)
	if err != nil {
		log.Printf("Problem reading dictionary directory: %v.\n", err)
		return words
	}

	knownWords := make(map[string]struct{})
	for _, info := range fileInfos {
		path := filepath.Join(dictPath, info.Name())
		fileContent, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("Problem reading a file for dict: %v.\n", err)
			continue
		}

		if _, ok := knownWords[string(fileContent)]; !ok {
			knownWords[string(fileContent)] = struct{}{}
			words = append(words, fileContent)
		}
	}

	dbgPr("Parsed %d extras for dictionary fuzzing.\n", len(words))
	return words
}
