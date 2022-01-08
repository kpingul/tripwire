# tripwire

File monitoring with a touch of UEBA 

## Another Tripwire ?

This project was inspired by learning about how attackers move laterally in an environment. Always on the move looking for PII/SPI on a system. By creating a tripwire, we can get some true positives. That someone is accessing an asset that they aren't suppose to. And by adding UEBA around this, you can build more context around their movements. So for example, which user account did they use to access the file? When did they login to this machine? Some failed login attempts? And with this evidence, IR and SOC teams can respond accordingly. List could go on depending what can we extract from a windows machine, but for now, this will do. 
