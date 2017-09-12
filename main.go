package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
)

func main() {
	/*
		EACH APP CONTAINS A LIST OF BUILDS
		EACH BUILD CONTAINS A RESULTS SET
		BUILDS THAT HAVE NOT COMPLETED CONTAIN AN "ERROR" IN THE XML
		PROCESS:GET ACCOUNT'S APP LIST -> GET BUILD LIST FOR EACH APP -> GET RESULTS FOR MOST RECENT BUILD -> CHECK MOST
		RECENT BUILD FOR ERROR -> IF PRESENT, GET THE NEXT MOST RECENT BUILD. WE NEED TO DO THIS FOR 4 TOTAL BUILDS TO
		COVER THE FOLLOWING WORST CASE SCENARIO:
		- - - PENDING STATIC BUILD (NO RESULTS YIELDS ERROR)
		- - - PENDING DYNAMIC BUILD (NO RESULTS YIELDS ERROR)
		- - - PENDING MANUAL BUILD (NO RESULTS YIELDS ERROR)
		- - - 4TH BUILD WILL HAVE RESULTS. IF ERROR HERE, NO RESULTS AVAILABLE FOR APP
	*/

	// DECLARE SOME VARIABLES
	var results_file *os.File
	var err error
	var appSkip bool

	// GET SOME USER INPUT
	veracodeUser := flag.String("user", "", "Veracode username")
	veracodePwd := flag.String("password", "", "Veracode password")
	inclNonPV := flag.Bool("nonpv", false, "Includes only non-policy-violating flaws")
	inclMitigated := flag.Bool("mitigated", false, "Includes mitigated flaws")
	staticOnly := flag.Bool("static", false, "Only exports static flaws")
	dynamicOnly := flag.Bool("dynamic", false, "Only exports dynamic flaws")
	flag.Parse()

	// CREATE A CSV FILE FOR RESULTS
	if results_file, err = os.Create("all_veracode_flaws.csv"); err != nil {
		fmt.Println(err)
	}
	defer results_file.Close()

	// GET THE APP LIST
	appList := GetAppList(*veracodeUser, *veracodePwd)

	// Create the writer
	writer := csv.NewWriter(results_file)
	defer writer.Flush()

	// Write the headers
	headers := []string{"app_id", "build_id", "issueid", "cweid", "remediation_status", "mitigation_status", "affects_policy_compliance",
		"date_first_occurrence", "severity", "exploitLevel", "module", "sourcefile", "line", "description"}
	if err = writer.Write(headers); err != nil {
		fmt.Println(err)
	}

	// CYCLE THROUGH EACH APP AND GET THE BUILD LIST
	for _, app := range appList {
		// RESET appSkip TO FALSE
		appSkip = false
		fmt.Printf("Processing App ID: %v\n", app)
		buildList := GetBuildList(*veracodeUser, *veracodePwd, app)

		// GET FOUR MOST RECENT BUILD IDS
		if len(buildList) == 0 {
			appSkip = true
		}

		//GET THE DETAILED RESULTS FOR MOST RECENT BUILD
		detailedResults, error_check := GetDetailedreport(*veracodeUser, *veracodePwd, buildList[len(buildList)-1])
		recent_build := buildList[len(buildList)-1]

		//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS).
		if len(buildList) > 1 && error_check == true {
			detailedResults, error_check = GetDetailedreport(*veracodeUser, *veracodePwd, buildList[len(buildList)-2])
			recent_build = buildList[len(buildList)-2]

			if len(buildList) > 2 && error_check == true {
				detailedResults, error_check = GetDetailedreport(*veracodeUser, *veracodePwd, buildList[len(buildList)-3])
				recent_build = buildList[len(buildList)-3]

				if len(buildList) > 3 && error_check == true {
					detailedResults, error_check = GetDetailedreport(*veracodeUser, *veracodePwd, buildList[len(buildList)-4])
					recent_build = buildList[len(buildList)-4]

					// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
					if error_check == true {
						appSkip = true
					}
				}
			}
		}

		//PRINT THE DETAILED RESULTS TO CSV
		if appSkip == false {

			for _, f := range detailedResults {
				// LOGIC CHECKS BASED ON FIELDS AND FLAGS
				if f.Remediation_status == "Fixed" {
					continue
				}
				if *inclNonPV == false && f.Affects_policy_compliance == "false" {
					continue
				}
				if *inclMitigated == false && f.Mitigation_status == "accepted" {
					continue
				}
				if *staticOnly == true && f.Module == "dynamic_analysis" {
					continue
				}
				if *dynamicOnly == true && f.Module != "dynamic_analysis" {
					continue
				}

				// CREATE ARRAY AND WRITE TO CSV
				entry := []string{app, recent_build, f.Issueid, f.Cweid, f.Remediation_status, f.Mitigation_status,
					f.Affects_policy_compliance, f.Date_first_occurrence, f.Severity, f.ExploitLevel, f.Module,
					f.Sourcefile, f.Line}

				err := writer.Write(entry)
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	}
}
