package main

import (
	"fmt"
	"time"
  	"github.com/djherbis/times"
  	"github.com/jasonlvhit/gocron"
)


//global variables
var (
	lastAccessTime time.Time
)

func main() {
	lastAccessTime = time.Now()

	gocron.Every(10).Second().Do(checkFileChanges)

	// Start all the pending jobs
	<- gocron.Start()
}

func checkFileChanges() {

	fileStat, err := times.Stat("./test.txt")
  	if err != nil {
    		fmt.Println(err.Error())
  	}

  	//checks if last access time changed
  	//then updates the last access time to 
  	//current access time for next check
    	if fileStat.AccessTime().After(lastAccessTime) {
    		fmt.Println("File Access")
    		lastAccessTime = fileStat.AccessTime()
    	}


}