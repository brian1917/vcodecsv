package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/brian1917/vcodeapi"
)

//DECLARE VARIABLES
var veracodeUser, veracodePwd, recentBuild, scanType string
var inclNonPV, inclMitigated, staticOnly, dynamicOnly, inclDesc bool
var resultsFile *os.File
var appSkip bool
var flaws []vcodeapi.Flaw
var appCustomFields []vcodeapi.CustomField
var errorCheck error

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

	start := time.Now()

	// PARSE FLAGS
	flag.Parse()

	// GET THE APP LIST
	appList, err := vcodeapi.ParseAppList(veracodeUser, veracodePwd)
	if err != nil {
		log.Fatal(err)
	}

	// CREATE A CSV FILE FOR RESULTS
	if resultsFile, err = os.Create("allVeracodeFlaws_" + time.Now().Format("20060102_150405") + ".csv"); err != nil {
		log.Fatal(err)
	}
	defer resultsFile.Close()

	// Create the writer
	writer := csv.NewWriter(resultsFile)
	defer writer.Flush()

	// CYCLE THROUGH EACH APP AND GET THE BUILD LIST
	appCounter := 0
	appWithFlawsCounter := 0
	for _, app := range appList {
		appCounter++
		// RESET appSkip TO FALSE
		appSkip = false
		fmt.Printf("Processing App ID %v: %v (%v of %v)\n", app.AppID, app.AppName, appCounter, len(appList))
		buildList, err := vcodeapi.ParseBuildList(veracodeUser, veracodePwd, app.AppID)

		if err != nil {
			log.Fatal(err)
		}

		// GET FOUR MOST RECENT BUILD IDS
		if len(buildList) == 0 {
			appSkip = true
			flaws = nil
			recentBuild = ""
		} else {

			//GET THE DETAILED RESULTS FOR MOST RECENT BUILD
			flaws, appCustomFields, errorCheck = vcodeapi.ParseDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-1].BuildID)
			recentBuild = buildList[len(buildList)-1].BuildID

			//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS)
			for i := 1; i < 4; i++ {
				if len(buildList) > i && errorCheck != nil {
					flaws, appCustomFields, errorCheck = vcodeapi.ParseDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-(i+1)].BuildID)
					recentBuild = buildList[len(buildList)-(i+1)].BuildID
				}
			}

			// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
			if errorCheck != nil {
				appSkip = true
			}

		}

		//PRINT THE DETAILED RESULTS TO CSV
		if appSkip == false {
			appWithFlawsCounter++

			// IF FIRST APP WITH FLAWS, WRITE THE HEADERS
			if appWithFlawsCounter == 1 {
				headers := []string{"app_name", "app_id", appCustomFields[0].Name, "build_id", "unique_id", "issueid", "analysis_type", "category", "cwe_name", "cwe_id", "remediation_status",
					"mitigation_status", "policy_name", "affects_policy_compliance", "date_first_occurrence", "severity", "exploit_level", "module", "source_file", "line"}
				if inclDesc == true {
					headers = append(headers, "description")
				}
				if err = writer.Write(headers); err != nil {
					log.Fatal(err)
				}

			}

			for _, f := range flaws {
				// LOGIC CHECKS BASED ON FIELDS AND FLAGS
				if f.RemediationStatus == "Fixed" ||
					(inclNonPV == false && f.AffectsPolicyCompliance == "false") ||
					(inclMitigated == false && f.MitigationStatus == "accepted") ||
					(staticOnly == true && f.Module == "dynamic_analysis") ||
					(dynamicOnly == true && f.Module != "dynamic_analysis") {
					continue
				}

				// DETERMINE SCAN TYPE
				if f.Module == "dynamic_analysis" {
					scanType = "dynamic"
				} else if f.Module == "manual_analysis" {
					scanType = "manual"
				} else {
					scanType = "static"
				}

				//CREATE A UNIQUE FLAW ID
				uniqueFlawID := app.AppID + "-" + f.Issueid

				// CREATE ARRAY AND WRITE TO CSV
				entry := []string{app.AppName, app.AppID, appCustomFields[0].Value, recentBuild, uniqueFlawID, f.Issueid, scanType, f.CategoryName, f.CweName, f.Cweid, f.RemediationStatus, f.MitigationStatus,
					f.PolicyName, f.AffectsPolicyCompliance, f.DateFirstOccurrence, f.Severity, f.ExploitLevel, f.Module, f.Sourcefile, f.Line}
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

	elapsed := time.Since(start)
	fmt.Printf("Run time: %v \n", elapsed)
}
