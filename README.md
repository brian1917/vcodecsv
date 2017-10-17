# Veracode All Flaws to CSV

## Description
Creates a CSV file with all open flaws for an account. The default includes policy-violating, non-mitigated flaws for all scan types. Flags can be used to override.

## Third-party Packages
1. github.com/brian1917/vcodeapi

## Parameters
1.  **-credsFile**: Credentials file with Veracode API ID/Key.
2. **-nonpv**: Will include non-policy violating flaws.
3. **-mitigated**: Will include flaws with accepted mitigations.
4. **-static**: Will only export flaws from static scans.
5. **-dynamic**: Will only export flaws from dynamic scans.
6. **-desc**: Will include the detailed description of the flaw (increases file size).

**Note**: Setting _-static_ and _-dynamic_ flags will export all flaws excluding those from MPT.

## Credentials File
Must be structured like the following:
```
[DEFAULT]
veracode_api_key_id = ID HERE
veracode_api_key_secret = SECRET HERE
```

## Executables
I've added the executables for Mac (vcodecsv) and Windows (vcodecsv.exe). Building from source is preferred, but I'll try to keep these up-to-date for those that don't have Go installed.
* For Windows, users download the EXE and from the command line run `vcodexsv.exe --help`.
* For Mac, download the executable, set it to be an executable: `chmod +x vcodecsv` and run `./vcodecsv --help`