// SPDX-License-Identifier: Apache-2.0
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package falcogitlab

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"time"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	//"github.com/oschwald/geoip2-golang"

	"github.com/xanzy/go-gitlab"
	
)

func (p *Plugin) initInstance(oCtx *PluginInstance) error {

	// think of plugin_init as initializing the plugin software

	oCtx.whSecret = p.config.ValidationToken
	oCtx.whSrvChan = nil
	return nil

}

// Open an event stream and return an open plugin instance.
func (p *Plugin) Open(params string) (source.Instance, error) {

	// think of plugin_open as configuring the software to return events

	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}

	if p.config.Debug {
		log.Printf("GitLab Plugin: Debug logging is enabled at Debug Level: " + fmt.Sprintf("%d", p.config.DebugLevel))
	}

	// Create the channel
	oCtx.whSrvChan = make(chan []byte, 128)
	oCtx.whSrvErrorChan = make(chan []byte, 128)

	// Launch the APIClient
	go fetchAuditAPI(p, oCtx)

	return oCtx, nil
}

// Closing the event stream and deinitialize the open plugin instance.
func (oCtx *PluginInstance) Close() {
	println("GitLab Plugin: Closing Maxmind DB")
	oCtx.geodb.Close()
}

// Produce and return a new batch of events.
func (oCtx *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Casting to our plugin type
	p := pState.(*Plugin)

	// Batching is not supported for now, so we only write the first entry of the batch
	evt := evts.Get(0)
	writer := evt.Writer()

	// Receive the event from the webserver channel with a 1 sec timeout
	var gitlabData []byte
	var gitlabErrorData []byte

	afterCh := time.After(1 * time.Second)
	select {
	case gitlabData = <- oCtx.whSrvChan:
		// Process data from box channel
		written, err := writer.Write(gitlabData)
		if err != nil {
			return 0, fmt.Errorf("GitLab Plugin ERROR: Couldn't write GitLab Event data events - %v", err)
		}
		if written < len(gitlabData) {
			return 0, fmt.Errorf("GitLab Plugin ERROR: GitLab message too long: %d, max %d supported", len(gitlabData), written)
		}

	case gitlabErrorData = <- oCtx.whSrvErrorChan:

		falcoalert := ErrorMessage{"pluginerror", string(gitlabErrorData)}
		falcoalertjson, err := json.Marshal(falcoalert)
		if err != nil {
			log.Printf("GitLab Plugin ERROR -  NextBatch(): Couldn't Create Plugin Error JSON")
		}
		written, err := writer.Write(falcoalertjson)
		if err != nil {
			return 0, fmt.Errorf("GitLab Plugin ERROR: Couldn't write Error Event - %v", err)
		}
		if written < len(gitlabErrorData) {
			return 0, fmt.Errorf("GitLab Plugin ERROR: event message too long: %d, max %d supported", len(gitlabErrorData), written)
		}
		
	case <-afterCh:
		p.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

type ErrorMessage struct {
	EventType          string
	PluginErrorMessage string
}

func breakOut(backoffcount int, Debug bool, errorMessage string, oCtx *PluginInstance) bool {
	// This function does back off processing - it will back off all the way out to 24 hours before exiting

	// Log a Debug Error Message
	if Debug {
		log.Print(errorMessage)
	}

	// Now work a back off
	errorCount := 40
	if backoffcount > errorCount {
		if Debug {
			log.Printf("GitLab Plugin ERROR: Error persisted for ages... - exiting")
		}

		// Start: Send an alert to Falco
		errorMessage = "GitLab Plugin ERROR: Error persisted for ages... - exiting"
		falcoalert := ErrorMessage{"pluginerror", errorMessage}
		falcoalertjson, err := json.Marshal(falcoalert)
		if err != nil {
			log.Printf("GitLab Plugin Error - breakOut(): Couldn't Create Plugin Error JSON")
		}
		oCtx.whSrvChan <- falcoalertjson
		// End: Send an alert to Falco

		return false
	}
	if Debug {
		log.Printf("GitLab Plugin WARNING: error occurred while connecting to API - sleeping for %d min", backoffcount*5)
	}

	// Start: Send an alert to Falco
	errorMessage = errorMessage + " - sleeping for " + fmt.Sprintf("%d", (backoffcount*5)) + " mins."
	falcoalert := ErrorMessage{"pluginerror", errorMessage}
	falcoalertjson, err := json.Marshal(falcoalert)
	if err != nil {
		log.Printf("GitLab Plugin Error - breakOut(): Couldn't Create Plugin Error JSON")
	}
	oCtx.whSrvChan <- falcoalertjson
	// End: Send an alert to Falco

	// Back off for a while
	time.Sleep(time.Duration(backoffcount*5) * time.Minute)
	return true
}

func fetchAuditAPI(p *Plugin, oCtx *PluginInstance) {
	backoffcount := 1

	if p.config.Debug && p.config.DebugLevel >= 0 {
		log.Printf("GitLab Plugin - Starting Audit Event API requester")
	}
	
	querytimestamp :=  time.Now().UTC()

	// Outerloop is used for the backoff processing
	// after timeout, it continues this loop essentially restarting the whole process
outerloop:
	for {

		// Sleep for the poll interval
		if p.config.Debug && p.config.DebugLevel >= 1 {
			println("Box Plugin: Sleeping for " + fmt.Sprintf("%d", p.config.PollIntervalSecs) + " seconds")
		}
		time.Sleep(time.Duration(p.config.PollIntervalSecs) * time.Second)
		
		if p.config.Debug && p.config.DebugLevel >= 0 {
			println("GitLab Plugin: Authenticating against API")
		}
		// Authenticate with GitLab Token
		git, err := gitlab.NewClient(p.config.GitLabToken, gitlab.WithBaseURL(p.config.GitLabBaseURL))
		if err != nil {
			errorMessage := "GitLab Plugin ERROR: could not authenticate - check your gitlabtoken and gitlabbaseurl settings in falco.yaml - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}

		}

		// Scope the Audit Event Query to only the events since the timestamp
		auditEventOptions := gitlab.ListAuditEventsOptions {
			CreatedAfter: &querytimestamp,
		}


		eventsArray, httpResponse, err := git.AuditEvents.ListInstanceAuditEvents(&auditEventOptions)
		if err != nil || httpResponse.StatusCode != 200 {
			errorMessage := "GitLab Plugin ERROR: Could not fetch initial Admin Streaming Logs Stream Position - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}
		}


		// Loop through the events backwards and populate FalcoEvent
		for i := len(eventsArray)-1; i >=0; i-- {
		
			tmpFalcoEvent := FalcoEvent{GitLabEvent:eventsArray[i]}
			
			// Check if the IP exists
			ipstr := eventsArray[i].Details.IPAddress
			if strings.Contains(ipstr, ",") {
				stringSlice := strings.Split(ipstr, ",")
				ipstr = stringSlice[0]
			}

			// If Geolocation enrichment is enabled then enrich the IP with Geolocation info
			checkGeoDB := false


			if checkGeoDB && len(ipstr) > 0 {
				ip := net.ParseIP(ipstr)
				if ip != nil {
					city, err := oCtx.geodb.City(ip)
					if err != nil {
						if p.config.Debug  {
							println("GitLab Plugin WARNING: fetchAuditAPI: couldn't get City() for ip: " + ipstr)
						}
					}
					
					tmpFalcoEvent.City = city.City.Names["en"]
					tmpFalcoEvent.Country = city.Country.Names["en"]
					tmpFalcoEvent.CountryIsoCode = city.Country.IsoCode
					tmpFalcoEvent.Continent = city.Continent.Names["en"]
				}

			} 

			// Marshall Event into JSON
			jsonEvent, err := json.Marshal(tmpFalcoEvent)
			if err != nil {
				errorMessage := "GitLab Plugin:  Failed to Marshal FalcoEvent to JSON"
				if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
					backoffcount += 1
					continue outerloop
				} else {
					os.Exit(1)
				}
	
			}

			// Print out the JSON event if Debugging is enabled.
			if p.config.Debug {
				println(string(jsonEvent))
			}


			// Send the JSON event through the channel
			oCtx.whSrvChan <- jsonEvent

			// Check if this is the last event and if it is then update the timestamp
			if i == 0 {
				querytimestamp = *eventsArray[i].CreatedAt
				
			
			}
		
		}
		
		
		if p.config.Debug && p.config.DebugLevel >= 1 {
			println("GitLab Plugin: Closing GitLab Connection")
		}
		
		


	}
}

type GitLabEvent = gitlab.AuditEvent

type FalcoEvent struct {
    City string
	Country string
	CountryIsoCode string
	Continent string
    *GitLabEvent
}
