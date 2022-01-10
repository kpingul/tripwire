# tripwire

File monitoring with a touch of UEBA 

## Another Tripwire ?

This project was inspired by learning about how attackers move laterally in an environment. Always on the move looking for PII/SPI on a system. By creating a tripwire, we can get some true positives. That someone is accessing an asset that they aren't suppose to. And by adding UEBA around this, you can build more context around their movements. So for example, which user account did they use to access the file? When did they login to this machine? Some failed login attempts? And with this evidence, IR and SOC teams can respond accordingly. List could go on depending what can we extract from a windows machine, but for now, this will do. 

## Plaform support

Windows 8/8.1/10

## Installation

Go version 1.17.6+

## Notes

A couple of things to note with this project. The UEBA aspect comes from windows security events. These are events that are logged and used for auditing windows systems. Events such as authentication, file integrity, application activity and many others. Since we will be utilizing these events for our UEBA part, the Audit object access policy has to be enabled for our file monitoring module to work properly. Assuming we are in a windows environment with domain controllers and active directories with existing security controls in place, we will assume that this is already enabled. But know that if you're on a windows 10 home version build, this feauture isn't available to edit from what I know, but I might be wrong.      
