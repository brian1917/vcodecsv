package main

import (
	"bytes"
	"encoding/xml"
	"github.com/brian1917/vcodeapi"
)

type App struct {
	AppID   string `xml:"app_id,attr"`
	AppName string `xml:"app_name,attr"`
}

func GetAppList(username, password string) []string {
	var appIDs []string
	appListAPI := vcodeapi.AppList(username, password)
	decoder := xml.NewDecoder(bytes.NewReader(appListAPI))
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
			if se.Name.Local == "app" {
				var app App
				decoder.DecodeElement(&app, &se)
				appIDs = append(appIDs, app.AppID)
			}
		}
	}
	return appIDs
}
