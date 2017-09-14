package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

//DECLARE VARIABLES
var veracodeUser, veracodePwd, recentBuild string
var inclNonPV, inclMitigated, staticOnly, dynamicOnly, inclDesc bool
var resultsFile *os.File
var appSkip bool
var detailedResults []Flaw
var appCustomFields []CustomField
var errorCheck error
var err error
var appList []App

func init() {
	flag.StringVar(&veracodeUser, "user", "", "Veracode username")
	flag.StringVar(&veracodePwd, "password", "", "Veracode password")
	flag.BoolVar(&inclNonPV, "nonpv", false, "Includes only non-policy-violating flaws")
	flag.BoolVar(&inclMitigated, "mitigated", false, "Includes mitigated flaws")
	flag.BoolVar(&staticOnly, "static", false, "Only exports static flaws")
	flag.BoolVar(&dynamicOnly, "dynamic", false, "Only exports dynamic flaws")
	flag.BoolVar(&inclDesc, "desc", false, "Includes detailed flaw descriptions (larger file size)")
}

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

	// PARSE FLAGS
	flag.Parse()

	// GET THE APP LIST
	appList, err = GetAppList(veracodeUser, veracodePwd)
	if err != nil {
		log.Fatal(err)
	}

	// CREATE A CSV FILE FOR RESULTS
	if resultsFile, err = os.Create("allVeracodeFlaws_" + time.Now().Format("2006-01-02-15-04-05") + ".csv"); err != nil {
		log.Fatal(err)
	}
	defer resultsFile.Close()

	// Create the writer
	writer := csv.NewWriter(resultsFile)
	defer writer.Flush()

	// Write the headers
	headers := []string{"custom_field1", "app_name", "app_id", "build_id", "issueid", "cweid", "remediation_status", "mitigation_status", "affects_policy_compliance",
		"date_first_occurrence", "severity", "exploitLevel", "module", "sourcefile", "line"}
	if inclDesc == true {
		headers = append(headers, "description")
	}
	if err = writer.Write(headers); err != nil {
		log.Fatal(err)
	}

	// CYCLE THROUGH EACH APP AND GET THE BUILD LIST
	appCounter := 0
	for _, app := range appList {
		appCounter += 1
		// RESET appSkip TO FALSE
		appSkip = false
		fmt.Printf("Processing App ID %v: %v (%v of %v)\n", app.AppID, app.AppName, appCounter, len(appList))
		buildList, err := GetBuildList(veracodeUser, veracodePwd, app.AppID)

		if err != nil {
			log.Fatal(err)
		}

		// GET FOUR MOST RECENT BUILD IDS
		if len(buildList) == 0 {
			appSkip = true
			detailedResults = nil
			recentBuild = ""
		} else {

			//GET THE DETAILED RESULTS FOR MOST RECENT BUILD
			detailedResults, appCustomFields, errorCheck = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-1])
			recentBuild = buildList[len(buildList)-1]

			//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS).
			if len(buildList) > 1 && errorCheck != nil {
				detailedResults, appCustomFields, errorCheck = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-2])
				recentBuild = buildList[len(buildList)-2]

				if len(buildList) > 2 && errorCheck != nil {
					detailedResults, appCustomFields, errorCheck = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-3])
					recentBuild = buildList[len(buildList)-3]

					if len(buildList) > 3 && errorCheck != nil {
						detailedResults, appCustomFields, errorCheck = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-4])
						recentBuild = buildList[len(buildList)-4]

						// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
						if errorCheck != nil {
							appSkip = true
						}
					}
				}
			}
		}

		//PRINT THE DETAILED RESULTS TO CSV
		if appSkip == false {

			// GET CUSTOM FIELD 1

			for _, f := range detailedResults {
				// LOGIC CHECKS BASED ON FIELDS AND FLAGS
				if f.Remediation_status == "Fixed" ||
					(inclNonPV == false && f.Affects_policy_compliance == "false") ||
					(inclMitigated == false && f.Mitigation_status == "accepted") ||
					(staticOnly == true && f.Module == "dynamic_analysis") ||
					(dynamicOnly == true && f.Module != "dynamic_analysis") {
					continue
				}

				// CREATE ARRAY AND WRITE TO CSV
				entry := []string{appCustomFields[0].Value, app.AppName, app.AppID, recentBuild, f.Issueid, f.Cweid, f.Remediation_status, f.Mitigation_status,
					f.Affects_policy_compliance, f.Date_first_occurrence, f.Severity, f.ExploitLevel, f.Module,
					f.Sourcefile, f.Line}
				if inclDesc == true {
					entry = append(entry, f.Description)
				}
				err := writer.Write(entry)
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	}
}
