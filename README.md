# Veracode All Flaws to CSV

## Description
Creates a CSV file with all open flaws for an account. The default includes policy-violating, non-mitigated flaws for all scan types. Flags can be used to override.

## Third-party Packages
1. github.com/brian1917/vcodeapi

## Parameters
1.  **-user**: Veracode username.
2.  **-password**: Veracode password.
3. **-nonpv**: Will include non-policy violating flaws.
4. **-mitigated**: Will include flaws with accepted mitigations.
5. **-static**: Will only export flaws from static scans.
6. **-dynamic**: Will only export flaws from dynamic scans.

**Note**: Setting _-static_ and _-dynamic_ flags will export all flaws excluding those from MPT.