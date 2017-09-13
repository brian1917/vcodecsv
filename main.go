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
var veracodeUser, veracodePwd string
var inclNonPV, inclMitigated, staticOnly, dynamicOnly, inclDesc bool
var results_file *os.File
var appSkip bool

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
	appList, err := GetAppList(veracodeUser, veracodePwd)
	if err != nil {
		log.Fatal(err)
	}

	// CREATE A CSV FILE FOR RESULTS
	if results_file, err = os.Create("allVeracodeFlaws" + time.Now().Format("20060102150405") + ".csv"); err != nil {
		log.Fatal(err)
	}
	defer results_file.Close()

	// Create the writer
	writer := csv.NewWriter(results_file)
	defer writer.Flush()

	// Write the headers
	headers := []string{"app_id", "build_id", "issueid", "cweid", "remediation_status", "mitigation_status", "affects_policy_compliance",
		"date_first_occurrence", "severity", "exploitLevel", "module", "sourcefile", "line"}
	if inclDesc == true {
		headers = append(headers, "description")
	}
	if err = writer.Write(headers); err != nil {
		log.Fatal(err)
	}

	// CYCLE THROUGH EACH APP AND GET THE BUILD LIST
	for _, app := range appList {
		// RESET appSkip TO FALSE
		appSkip = false
		fmt.Printf("Processing App ID: %v\n", app)
		buildList,err := GetBuildList(veracodeUser, veracodePwd, app)

		if err !=nil{
			log.Fatal(err)
		}

		// GET FOUR MOST RECENT BUILD IDS
		if len(buildList) == 0 {
			appSkip = true
		}

		//GET THE DETAILED RESULTS FOR MOST RECENT BUILD
		detailedResults, error_check := GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-1])
		recent_build := buildList[len(buildList)-1]

		//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS).
		if len(buildList) > 1 && error_check != nil {
			detailedResults, error_check = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-2])
			recent_build = buildList[len(buildList)-2]

			if len(buildList) > 2 && error_check != nil {
				detailedResults, error_check = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-3])
				recent_build = buildList[len(buildList)-3]

				if len(buildList) > 3 && error_check != nil {
					detailedResults, error_check = GetDetailedReport(veracodeUser, veracodePwd, buildList[len(buildList)-4])
					recent_build = buildList[len(buildList)-4]

					// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
					if error_check != nil {
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
				if inclNonPV == false && f.Affects_policy_compliance == "false" {
					continue
				}
				if inclMitigated == false && f.Mitigation_status == "accepted" {
					continue
				}
				if staticOnly == true && f.Module == "dynamic_analysis" {
					continue
				}
				if dynamicOnly == true && f.Module != "dynamic_analysis" {
					continue
				}

				// CREATE ARRAY AND WRITE TO CSV
				entry := []string{app, recent_build, f.Issueid, f.Cweid, f.Remediation_status, f.Mitigation_status,
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
