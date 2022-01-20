package main

import (
	"fmt"
	"time"
	"bufio"
	"os/exec"
  	"strings"
  	"log"
  	"net/http"
  	"encoding/json"
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
  	ID  int `storm:"id,increment"` // primary key
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
	gocron.Start()

	//setup http web server and API's
    	fileServer := http.FileServer(http.Dir("./frontend")) 
    	http.Handle("/", fileServer) 
	http.HandleFunc("/api/records", getRecords)
	http.ListenAndServe(":8090", nil)

}

/* REST API */

func getRecords(w http.ResponseWriter, req *http.Request) {

	records := getAllEventRecords()

	jsonData, err := json.Marshal(records)
	if err != nil {
	    log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
   	
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
		
		var accountName = ""
		var accountDomain = ""
		var processName = ""
		var accessType = ""
		
		for err == nil {
			if strings.Contains(line, "Account Name") {
				var aName = strings.Split(line, "Name:")
		    		fmt.Println("Account Name - " + strings.TrimSpace(aName[1]))
		    		accountName = strings.TrimSpace(aName[1])
		    	} 
		    	if strings.Contains(line, "Account Domain") {
		    		var aDomain = strings.Split(line, "Domain:")
		    		fmt.Println("Account Domain - " + strings.TrimSpace(aDomain[1]))
		    		accountDomain = strings.TrimSpace(aDomain[1])
		    	}
		    	if strings.Contains(line, "Process Name") {
		    		var pName = strings.Split(line, "Name:")
		    		fmt.Println("Process Name - " + strings.TrimSpace(pName[1]))
		    		processName = strings.TrimSpace(pName[1])
		    	}    
		    	if strings.Contains(line, "Accesses") {
		    		var aType = strings.Split(line, "Accesses:")
		    		fmt.Println("Access Type - " + strings.TrimSpace(aType[1]))
		    		accessType = strings.TrimSpace(aType[1])
		    		storeEventRecord(
		    			accountName,
		    			accountDomain,
		    			processName,
		    			accessType,
		    		)
		    	}
		    	
		    	line, err = reader.ReadString('\n')
		}

		fmt.Println(" DONE RUNNING PARSER")
		runningState = false
	}
	

}

/* DB  Management */

func storeEventRecord (accountName string, accountDomain string, processName string, aType string) {
	fmt.Println("storing event record")
 	record := EventRecord{
		AccountName: accountName, 
	  	AccountDomain: accountDomain,
	  	ProcessName: processName, 
	  	ProcessPath: processName, 
	  	AccessType: aType,
	}

	fmt.Println(record)

	//store in db
	errSave := tripwireDB.Save(&record)
	if errSave != nil {
		log.Fatal(errSave)
	}

}


func getAllEventRecords () []EventRecord{

	var records []EventRecord

	errFetch := tripwireDB.All(&records)
	if errFetch != nil {
		log.Fatal(errFetch)
		return records
	} else {
		return records
	}

}