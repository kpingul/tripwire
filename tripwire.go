package main

import (
	"log"
	"time"
  	"github.com/djherbis/times"
  	"github.com/jasonlvhit/gocron"
)

var (
	lastAccessTime time.Time
)

func main() {
	gocron.Every(10).Second().Do(checkFileChanges)

	// Start all the pending jobs
	<- gocron.Start()
}

func checkFileChanges() {
	t, err := times.Stat("./test.txt")
  	if err != nil {
    		log.Fatal(err.Error())
  	}

  	log.Println(t.AccessTime())
 	log.Println(t.ModTime())

}