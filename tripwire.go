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
  	EventID string 
  	TimeStamp string 
  	AccountName string 
  	AccountDomain string 
  	ObjectType string 
  	ObjectName string 
  	ObjectPath string 
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
    		runAndParseFileAccessEvents()
    	}

}

func runAndParseFileAccessEvents() {
	if !runningState {

		fmt.Println("runAndParseFileAccessEvents..")

		//set current state of parser
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
		
		//creating event record variables 	
		var timeStamp = ""
		var accountName = ""
		var accountDomain = ""
		var objectName = ""
		var objectType = ""
		var objectPath = ""
		var processName = ""
		var processPath = ""
		var accessType = ""
		

		//scan through output
		for err == nil {
			if strings.Contains(line, "Date") {
				var tstamp = strings.Split(line, "Date:")
		    		fmt.Println("Date - " + strings.TrimSpace(tstamp[1]))
		    		timeStamp = strings.TrimSpace(tstamp[1])
		    	} 
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
		    	if strings.Contains(line, "Object Type") {
				var oType = strings.Split(line, "Type:")
		    		fmt.Println("Object Type - " + strings.TrimSpace(oType[1]))
		    		objectType = strings.TrimSpace(oType[1])
		    	} 
		    	if strings.Contains(line, "Object Name") {
		    		var oPath = strings.Split(line, "Name:")
		    		fmt.Println("Object Name - " + strings.TrimSpace(oPath[1]))
		    		objectPath = strings.TrimSpace(oPath[1])
		    		objectName = strings.Split(objectPath, "\\")[len(strings.Split(objectPath, "\\"))-1]
		    	}
		    	if strings.Contains(line, "Process Name") {
		    		var pPath = strings.Split(line, "Name:")
		    		fmt.Println("Process Name - " + strings.TrimSpace(pPath[1]))
		    		processPath = strings.TrimSpace(pPath[1])
		    		processName = strings.Split(processPath, "\\")[len(strings.Split(processPath, "\\"))-1]
		    	}    
		    	if strings.Contains(line, "Accesses") {
		    		var aType = strings.Split(line, "Accesses:")
		    		fmt.Println("Access Type - " + strings.TrimSpace(aType[1]))
		    		accessType = strings.TrimSpace(aType[1])

		    		//only intreseted in file types and not our own application since it
		    		//does the checking of the file itself
		    		if objectType == "File" && processName != "tripwire.exe" {

		    			//store records
			    		storeEventRecord(
			    			"4663",
			    			timeStamp,
			    			accountName,
			    			accountDomain,
			    			objectType,
			    			objectName,
			    			objectPath,
			    			processName,
			    			processPath,
			    			accessType,
			    		)
		    		}
		    	}
		    	
		    	line, err = reader.ReadString('\n')
		}

		fmt.Println(" DONE RUNNING PARSER")
		runningState = false
	}
	

}
func runAndParseLogonEvents() {

	fmt.Println("runAndParseLogonEvents..")

	//using wevtutil to extract windows event ID's
	//4624 = logon success event	
	//4625 = logon failure event	
   	cmd := exec.Command("cmd", "/C", "wevtutil", "qe", "Security", "/q:*[System [(EventID=4624)]]", "/format:text")
	pipe, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
	}

		
	//create a reader to iterate through findings
	//and extract the data we need 
	reader := bufio.NewReader(pipe)
	line, err := reader.ReadString('\n')

	//scan through output
	for err == nil {
		fmt.Println(line)
	    	line, err = reader.ReadString('\n')
	}

	fmt.Println(" DONE RUNNING PARSER")
	

}

/* DB  Management */

func storeEventRecord (eventID string, timeStamp string,  accountName string, accountDomain string, objectType string, objectName string, objectPath string, processName string, processPath string,  aType string) {
	fmt.Println("storing event record")
 	record := EventRecord{
 		EventID : eventID,
 		TimeStamp : timeStamp,
		AccountName: accountName, 
	  	AccountDomain: accountDomain,
	  	ObjectType: objectType,
	  	ObjectName: objectName,
	  	ObjectPath: objectPath,
	  	ProcessName: processName, 
	  	ProcessPath: processPath, 
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