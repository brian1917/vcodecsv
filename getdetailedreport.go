package main

import (
	"bytes"
	"encoding/xml"
	"github.com/brian1917/vcodeapi"
	"log"
	"errors"
)

type Flaw struct {
	Issueid                   string `xml:"issueid,attr"`
	Cweid                     string `xml:"cweid,attr"`
	Remediation_status        string `xml:"remediation_status,attr"`
	Mitigation_status         string `xml:"mitigation_status,attr"`
	Affects_policy_compliance string `xml:"affects_policy_compliance,attr"`
	Date_first_occurrence     string `xml:"date_first_occurrence,attr"`
	Severity                  string `xml:"severity,attr"`
	ExploitLevel              string `xml:"exploitLevel,attr"`
	Module                    string `xml:"module,attr"`
	Sourcefile                string `xml:"sourcefile,attr"`
	Line                      string `xml:"line,attr"`
	Description               string `xml:"description,attr"`
}

func GetDetailedReport(username, password, build_id string) ([]Flaw, error) {
	var flaws []Flaw
	var errMsg error = nil

	detailedReportAPI, err := vcodeapi.DetailedReport(username, password, build_id)
	if err!=nil{
		log.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(detailedReportAPI))
	for {
		// Read tokens from the XML document in a stream.
		t, _ := decoder.Token()

		if t == nil {
			break
		}
		// Inspect the type of the token just read
		switch se := t.(type) {
		case xml.StartElement:
			// Read StartElement and check for flaw
			if se.Name.Local == "flaw" {
				var flaw Flaw
				decoder.DecodeElement(&flaw, &se)
				flaws = append(flaws, flaw)
			}
			if se.Name.Local == "error" {
				err = errors.New("api for GetDetailedReport returned with an error element")
			}
		}
	}
	return flaws, errMsg

}
