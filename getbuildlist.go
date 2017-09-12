package main

import (
	"bytes"
	"encoding/xml"
	"github.com/brian1917/vcodeapi"
)

type Build struct {
	BuildID string `xml:"build_id,attr"`
}

func GetBuildList(username, password, app_id string) []string {
	var buildIDs []string
	buildListAPI := vcodeapi.BuildList(username, password, app_id)
	decoder := xml.NewDecoder(bytes.NewReader(buildListAPI))
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
			if se.Name.Local == "build" {
				var build Build
				decoder.DecodeElement(&build, &se)
				buildIDs = append(buildIDs, build.BuildID)
			}
		}
	}
	return buildIDs
}
