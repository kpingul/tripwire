package main

import (
	"fmt"
	"time"
	"bufio"
	"os/exec"
  	"strings"
  	"log"
  	"github.com/djherbis/times"
  	"github.com/jasonlvhit/gocron"
  	"github.com/asdine/storm/v3"
)


//global variables
var (
	lastAccessTime time.Time
	tripwireDB *storm.DB
	errDB error
	runningState = false
)

const (
	FILE_ACCESS = "4663"
	LOGIN_SUCCESS = "4624"
	FAILURE = "4625"
)

/* Data models */

type EventRecord struct {
  	ID string `storm:"id"`// primary key
  	AccountName string 
  	AccountDomain string 
  	ProcessName string 
  	ProcessPath string 
  	AccessType string 
}


func main() {

	//set last acces time
	lastAccessTime = time.Now()

	//open a db connection
	tripwireDB, errDB = storm.Open("tripwire.db")
	if errDB != nil {
		log.Fatal(errDB) 
	}

	defer tripwireDB.Close()

	//set scheduler
	gocron.Every(10).Second().Do(checkFileChanges)

	// Start all the pending jobs and block app
	<- gocron.Start()
}


/* Utility */

func checkFileChanges() {
	fmt.Println("checkFileChanges...")
	

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

    		//run when file access is triggered
    		runAndParseEvents()
    	}

}

func runAndParseEvents() {
	if !runningState {

		fmt.Println("runAndParseEvents..")

		runningState = true

		//using wevtutil to extract windows event ID's
		//4663 = file access event	
	   	cmd := exec.Command("cmd", "/C", "wevtutil", "qe", "Security", "/q:*[System [(EventID=4663)]]", "/format:text")
		pipe, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
		}

			
		//create a reader to iterate through findings
		//and extract the data we need 
		reader := bufio.NewReader(pipe)
		line, err := reader.ReadString('\n')
		for err == nil {
			if strings.Contains(line, "Account Name") {
		    		var accountName = strings.Split(line, "Name:")
		    		fmt.Println("Account Name - " + strings.TrimSpace(accountName[1]))
		    	} 
		    	if strings.Contains(line, "Account Domain") {
		    		var accountDomain = strings.Split(line, "Domain:")
		    		fmt.Println("Account Domain - " + strings.TrimSpace(accountDomain[1]))
		    	}
		    	if strings.Contains(line, "Process Name") {
		    		var processName = strings.Split(line, "Name:")
		    		fmt.Println("Process Name - " + strings.TrimSpace(processName[1]))
		    	}    
		    	if strings.Contains(line, "Accesses") {
		    		var accessType = strings.Split(line, "Accesses:")
		    		fmt.Println("Access Type - " + strings.TrimSpace(accessType[1]))
		    	}
		    	
		    	line, err = reader.ReadString('\n')
		}

		fmt.Println(" DONE RUNNING PARSER")
		runningState = false
	}
	

}


func storeEventRecord (accountName string, accountDomain string, processName string, aType string) {

	//store in db
	errSave := tripwireDB.Save(&EventRecord{
		AccountName: accountName, 
	  	AccountDomain: accountDomain,
	  	ProcessName: processName, 
	  	ProcessPath: processName, 
	  	AccessType: aType,
	})
	if errSave != nil {
		log.Fatal(errSave)
	}

}