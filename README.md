# Veracode All Flaws to CSV

## Description
Creates a CSV file with all open flaws for an account. The default includes policy-violating, non-mitigated flaws for all scan types. Flags can be used to override.

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
Executables for Windows, Mac, and Linux will be available in the releases section of the repository (https://github.com/brian1917/vcodecsv/releases)
* For Windows, users download the EXE and from the command line run `vcodexsv.exe --help`.
* For Mac, download the executable, set it to be an executable: `chmod +x vcodecsv` and run `./vcodecsv --help`

## Third-party Packages
1. github.com/brian1917/vcodeapi