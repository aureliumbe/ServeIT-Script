# Aurelium ServeIT script
The Aurelium ServeIT script is a script library that can be used to check the system status and uncover system configuration issues. Currently the script is in a single ps1-file but the goal is to rework this script into modules.


## Installation
```powershell
# TODO

```

## Usage
```powershell
# Output script results and adds verbose progress information to the console
.\ServeIT.ps1 -Verbose

# Only process the servers found in the referenced Active Directory OU
.\ServeIT.ps1 -ServersSearchbase $ldapPathToOU

# Output script progress information to the console and writes output to the mentioned file
.\ServeIT.ps1 -Verbose > $outputlocation
```

## Contributing
Feel free to contribute by opening an issue and/or adding a push request after verifying there isn't a similar item in progress.

## License
TODO