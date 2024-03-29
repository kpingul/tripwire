# tripwire

## Another Tripwire ?

This project was inspired by learning how attackers move laterally within an environment, always on the move looking for credentials, PII, and other data critical to the organization. By creating a tripwire, we can get some true positives. I’ve also incorporated some windows event logs to provide more contextual data. For example, with event id 4663, we can determine what process was involved in opening the file and possibly what account they used and the domain they are in. And with event id 4624 and 4625, we can now see when they’ve logged into that account and from which machine if not coming from the compromised host. And with this evidence, IR and SOC teams can use this evidence for further investigations. 

## Tripwire Visualizer

This feature was inspired by the Logontracer project by JPCERTCC. In this example, we have a rogue user that has successfully logged into the win_10 workstation. And from there, the individual accessed the tripwire we planted as password.txt. From a visual standpoint, we can see the lateral movement that took place which eventually lead them to access the tripwire. 

![tripwire](https://user-images.githubusercontent.com/11414669/152615979-63443858-f160-412c-90e6-92ca7429d7e5.png)

## Plaform support

Windows 8/8.1/10

## Installation

Go version 1.17.6+

## Commands

Usage:

```sh
go run tripwire.go <flag>
```

#### `--web <string>`

Yes/no for web server and GUI ( localhost:8090 )

#### `--frequency <int>`

Choose the frequency to check for changes ( in seconds )

#### `--luretype <string>`

Choose fake file type: PII, CC, or Credentials

#### `--help`

Show help

#### `--version`

Show current version


## Notes

A couple of things to note with this project. The UEBA aspect comes from windows security events. These are events that are logged and used for auditing windows systems. Events such as authentication, file integrity, application activity and many others. Since we will be utilizing these events for our UEBA part, the Audit object access policy has to be enabled for our file monitoring module to work properly. Assuming we are in a windows environment with domain controllers and active directories with existing security controls in place, we will assume that this is already enabled. But know that if you're on a windows 10 home version build, this feauture isn't available to edit from what I know, but I might be wrong.      
