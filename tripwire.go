package main

import (
	"fmt"
	"time"
	"bufio"
	"os/exec"
  	"strings"
  	"log"
  	"os"
  	"net/http"
  	"encoding/json"
  	"github.com/djherbis/times"
  	"github.com/jasonlvhit/gocron"
  	"github.com/asdine/storm/v3"
  	"github.com/urfave/cli/v2"
  	"github.com/brianvoe/gofakeit/v6"
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
  	OriginAccountName string
  	OriginAccountDomain string
}


func main() {
	generateFakeData("PII")
	generateFakeData("Credentials")
	generateFakeData("CC")

	//set last acces time
	lastAccessTime = time.Now()


	//open a db connection
	tripwireDB, errDB = storm.Open("tripwire.db")
	if errDB != nil {
		log.Fatal(errDB) 
	}

	defer tripwireDB.Close()


	//Initial CLI App Setup
	app := &cli.App{
		Name:        "Tripwire",
		Version:     "0.1.0",
		Description: "File integrity and Cyber deception tool used to lure attackers",
		Authors: []*cli.Author{
			{Name: "KP",},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "web", Value: "no", Usage: "Enable web server for GUI", Required: false,},
			&cli.StringFlag{Name: "frequency", Value: "", Usage: "Choose the frequency to check for changes", Required: false,},
			&cli.StringFlag{Name: "luretype", Value: "", Usage: "Choose file type: PII, CC, or Credentials", Required: false,},
		},
		Action: func(c *cli.Context) error {
			//flag to check if everything checks out
			webCheck := false 

		    	//input validation checks
		    	if (c.String("web") == "yes" ) {
		    		webCheck = true
		    	} else {
		    		//add validation checking here..
		    	}


		     	// run if input checks out 
	     		if webCheck {
	     			//setup http web server and API's
			    	fileServer := http.FileServer(http.Dir("./frontend")) 
			    	http.Handle("/", fileServer) 
				http.HandleFunc("/api/records", getRecords)
				http.ListenAndServe(":8090", nil)
	     		} else {
			     	//set scheduler
				gocron.Every(10).Second().Do(checkFileChanges)

				// Start all the pending jobs and block app
				gocron.Start()
	     		}

		     	return nil
	    	},
	}



	//Run CLI
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

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
    		runAndParseLogonEvents()
    	}

}

func generateFakeData(typeOfData string) {

	//create file
	file, err := os.Create(typeOfData + ".txt")

    	if err != nil {
        	log.Fatal(err)
    	}

    	defer file.Close()

	switch typeOfData {
		case "CC":
			//create fake credit card numbers (5) 
			//write to file
			for i := 0; i < 5 ; i++ {
				writeFakeCCDataToFile(file, gofakeit.CreditCard())
			} 
		case "PII":
			//create fake PII (5) 
			//write to file
			for i := 0; i < 5 ; i++ {
				writeFakeDataPIIToFile(file, gofakeit.Person())
			} 

		case "Credentials":
			//create fake PII (5) 
			//write to file
			for i := 0; i < 5 ; i++ {
				writeFakeDataPCredentialsToFile(file, gofakeit.Username(), gofakeit.Password(false, true, false, false, false, 32))
			} 
		
		default:

		return
	}

}

func writeFakeCCDataToFile(file *os.File, cc *gofakeit.CreditCardInfo) {

    	_, errWrite := file.WriteString(cc.Type + "\n" + cc.Number + "\n" + cc.Exp + "\n" + cc.Cvv + "\n")
    	if errWrite != nil {
        	log.Fatal(errWrite)
    	}
}
func writeFakeDataPIIToFile(file *os.File, person *gofakeit.PersonInfo) {

    	_, errWrite := file.WriteString(person.FirstName + " " + person.LastName + "\n" + person.Gender + "\n" + person.SSN + "\n")
    	if errWrite != nil {
        	log.Fatal(errWrite)
    	}
}
func writeFakeDataPCredentialsToFile(file *os.File, username string, password string) {
   
    	_, errWrite := file.WriteString("Username - " + username + "\n" + "Password - " + password + "\n")
    	if errWrite != nil {
        	log.Fatal(errWrite)
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
			if strings.Contains(line, "Date:") {
				var tstamp = strings.Split(line, "Date:")
		    		// fmt.Println("Date - " + strings.TrimSpace(tstamp[1]))
		    		timeStamp = strings.TrimSpace(tstamp[1])
		    	} 
		    	if strings.Contains(line, "Account Name:") {
				var aName = strings.Split(line, "Name:")
		    		// fmt.Println("Account Name - " + strings.TrimSpace(aName[1]))
		    		accountName = strings.TrimSpace(aName[1])
		    	} 
		    	if strings.Contains(line, "Account Domain:") {
		    		var aDomain = strings.Split(line, "Domain:")
		    		// fmt.Println("Account Domain - " + strings.TrimSpace(aDomain[1]))
		    		accountDomain = strings.TrimSpace(aDomain[1])
		    	}
		    	if strings.Contains(line, "Object Type:") {
				var oType = strings.Split(line, "Type:")
		    		// fmt.Println("Object Type - " + strings.TrimSpace(oType[1]))
		    		objectType = strings.TrimSpace(oType[1])
		    	} 
		    	if strings.Contains(line, "Object Name:") {
		    		var oPath = strings.Split(line, "Name:")
		    		// fmt.Println("Object Name - " + strings.TrimSpace(oPath[1]))
		    		objectPath = strings.TrimSpace(oPath[1])
		    		objectName = strings.Split(objectPath, "\\")[len(strings.Split(objectPath, "\\"))-1]
		    	}
		    	if strings.Contains(line, "Process Name:") {
		    		var pPath = strings.Split(line, "Name:")
		    		// fmt.Println("Process Name - " + strings.TrimSpace(pPath[1]))
		    		processPath = strings.TrimSpace(pPath[1])
		    		processName = strings.Split(processPath, "\\")[len(strings.Split(processPath, "\\"))-1]
		    	}    
		    	if strings.Contains(line, "Accesses:") {
		    		var aType = strings.Split(line, "Accesses:")
		    		// fmt.Println("Access Type - " + strings.TrimSpace(aType[1]))
		    		accessType = strings.TrimSpace(aType[1])

		    		//only intreseted in file types and not our own application since it
		    		//does the checking of the file itself
		    		if objectType == "File" && processName != "tripwire.exe" {

		    			//store records
			    		storeFileAccessRecord(
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


// Logon Type for windows
// Description
// 2	Interactive (logon at keyboard and screen of system)
// 3	Network (i.e. connection to shared folder on this computer from elsewhere on network)
// 4	Batch (i.e. scheduled task)
// 5	Service (Service startup)
// 7	Unlock (i.e. unnattended workstation with password protected screen saver)
// 8	NetworkCleartext (Logon with credentials sent in the clear text. Most often indicates a logon to IIS with "basic authentication") See this article for more information.
// 9	NewCredentials such as with RunAs or mapping a network drive with alternate credentials.  This logon type does not seem to show up in any events.  If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."
// 10	RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)
// 11	CachedInteractive (logon with cached domain credentials such as when logging on to a laptop when away from the network)
func runAndParseLogonEvents() {

	fmt.Println("runAndParseLogonEvents..")

	//using wevtutil to extract windows event ID's
	//4624 = logon success event	
	//4625 = logon failure event	
   	cmd := exec.Command("cmd", "/C", "wevtutil", "qe", "Security", "/q:*[System [(EventID=4624) or (EventID=4625)]]", "/format:text")
	pipe, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
	}

	//create a reader to iterate through findings
	//and extract the data we need 
	reader := bufio.NewReader(pipe)
	line, err := reader.ReadString('\n')

	var eventID = ""
	var logonType = ""
	var timeStamp = ""
	var accountDomain = ""
	var accountName = ""
	var originAccountName = ""
	var originAccountDomain = ""

	//prevents us from having different
	//account and domain names
	var subjectFlag = true

	//scan through output
	for err == nil {
		if strings.Contains(line, "Account Name:")  && subjectFlag{
			var aName = strings.Split(line, "Name:")
	    		// fmt.Println("Origin Account Name - " + strings.TrimSpace(aName[1]))
	    		originAccountName = strings.TrimSpace(aName[1])
	    		originAccountName = strings.TrimSuffix(originAccountName, "$")
	    	} 
	    	if strings.Contains(line, "Account Domain:")  && subjectFlag{
	    		var aDomain = strings.Split(line, "Domain:")
	    		fmt.Println("Origin Account Domain - " + strings.TrimSpace(aDomain[1]))
	    		originAccountDomain = strings.TrimSpace(aDomain[1])

	    		//set subject flag to stop
	    		//checking for this 
	    		subjectFlag = false
	    	}
		
	    	if strings.Contains(line, "Date:") {
			var tstamp = strings.Split(line, "Date:")
	    		// fmt.Println("Date - " + strings.TrimSpace(tstamp[1]))
	    		timeStamp = strings.TrimSpace(tstamp[1])
	    	} 
	    	if strings.Contains(line, "Event ID:") {
			var eID = strings.Split(line, "ID:")
	    		// fmt.Println("Date - " + strings.TrimSpace(eID[1]))
	    		eventID = strings.TrimSpace(eID[1])
	    	} 
	    	if strings.Contains(line, "Account Name:") && !strings.Contains(line, "Network Account Name:") && !subjectFlag {
			var aName = strings.Split(line, "Name:")
	    		// fmt.Println("Account Name - " + strings.TrimSpace(aName[1]))
	    		accountName = strings.TrimSpace(aName[1])
	    	} 
	    	if strings.Contains(line, "Account Domain:") && !strings.Contains(line, "Network Account Domain:") && !subjectFlag {
	    		var aDomain = strings.Split(line, "Domain:")
	    		// fmt.Println("Account Domain - " + strings.TrimSpace(aDomain[1]))
	    		accountDomain = strings.TrimSpace(aDomain[1])
	    	}

		//logon type other than 5 (which denotes a service startup) is a red flag
		if strings.Contains(line, "Logon Type:") {
			var lType = strings.Split(line, "Type:")
	    		// fmt.Println("Logon Type - " + strings.TrimSpace(lType[1]))
	    		logonType = strings.TrimSpace(lType[1])
	    	} 

	    	if strings.Contains(line, "Network Information:") {

	    		//reset to true for next
	    		//set of events
	    		subjectFlag = true
	    		
	    		if logonType != "5" &&  logonType != "2" {
	    			// store records
		    		storeAccountLogonRecord(
		    			eventID,
		    			timeStamp,
		    			accountName,
		    			accountDomain,
		    			originAccountName,
		    			originAccountDomain,

		    		)
	    		}

	    	}
	    	
	    	line, err = reader.ReadString('\n')
	}

	fmt.Println(" DONE RUNNING PARSER")
	

}

/* DB  Management */

func storeFileAccessRecord (eventID string, timeStamp string,  accountName string, accountDomain string, objectType string, objectName string, objectPath string, processName string, processPath string,  aType string) {
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

func storeAccountLogonRecord (eventID string, timeStamp string,  accountName string, accountDomain string, originAccountName string, originAccountDomain string ) {
	fmt.Println("storing event record")
 	record := EventRecord{
 		EventID : eventID,
 		TimeStamp : timeStamp,
		AccountName: accountName, 
	  	AccountDomain: accountDomain,
	  	OriginAccountName: originAccountName,
	  	OriginAccountDomain: originAccountDomain,
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