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
	"os"
	"time"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/oschwald/geoip2-golang"
)

func (p *Plugin) initInstance(oCtx *PluginInstance) error {

	// think of plugin_init as initializing the plugin software

	oCtx.whSecret = p.config.VerificationToken
	oCtx.whSrvChan = nil
	oCtx.whSrvErrorChan = nil
	oCtx.whSrvFatalErrorChan = nil

	// Start: Open Maxmind Geo DB
	oCtx.checkGeoDB = false

	if len(p.config.MaxmindCityDBPath) > 0 {
		if _, err := os.Stat(p.config.MaxmindCityDBPath); err == nil {
			tempgeodb, err2 := geoip2.Open(p.config.MaxmindCityDBPath)
			if err2 != nil {
				oCtx.checkGeoDB = false
				if p.config.Debug {
					log.Printf("GitLab Plugin: Located Maxmind DB at path at MaxmindCityDBPath, but couldn't open it. Disabling GeoDB enrichment")
				}
			} else {
				oCtx.checkGeoDB = true
				oCtx.geodb = *tempgeodb
				if p.config.Debug {
					log.Printf("GitLab Plugin: Found Maxmind GeoDB and opened it successfully - enabling GeoDB enrichment")
				}

			}

		} else {
			if p.config.Debug {
				log.Printf("GitLab Plugin: Could not locate Maxmind DB as specified in MaxmindCityDBPath in falco.yaml. Disabling GeoDB enrichment")
			}
		}

	} else {
		if p.config.Debug {
			log.Printf("GitLab Plugin: MaxmindCityDBPath config setting was blank in falco.yaml. Disabling GeoDB enrichment")
		}
	}
	// End: Open Maxmind Geo DB

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
		log.Printf("GitLab Plugin: Debug logging is enabled")
	}

	// Create the channels
	oCtx.whSrvChan = make(chan []byte, 128)
	oCtx.whSrvErrorChan = make(chan []byte, 128)
	oCtx.whSrvFatalErrorChan = make(chan []byte, 128)


	if p.config.Debug  {
		log.Printf("GitLab Plugin - Starting Webhook Server")
	}
	go webhookServer(p,oCtx)

	return oCtx, nil
}

// Closing the event stream and deinitialize the open plugin instance.
func (oCtx *PluginInstance) Close() {
	println("GitLab Plugin: Closing Maxmind DB")
	err := oCtx.geodb.Close()
	if err != nil {
		log.Printf("GitLab Plugin - Failed to close Maxmind DB")
	}
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
	var gitlabFatalErrorData []byte

	afterCh := time.After(1 * time.Second)
	select {
	case gitlabData = <- oCtx.whSrvChan:
		// Process data from GitLab channel
		
		written, err := writer.Write(gitlabData)
		if err != nil {
			return 0, fmt.Errorf("GitLab Plugin ERROR - NextBatch(): Couldn't write GitLab Event data events - %v", err)
		}
		if written < len(gitlabData) {
			return 0, fmt.Errorf("GitLab Plugin ERROR - NextBatch(): GitLab message too long: %d, max %d supported", len(gitlabData), written)
		}

	case gitlabErrorData = <- oCtx.whSrvErrorChan:

		falcoalert := ErrorMessage{"pluginerror", string(gitlabErrorData)}
		falcoalertjson, err := json.Marshal(falcoalert)
		if err != nil {
			return 0, fmt.Errorf("GitLab Plugin ERROR -  NextBatch(): Couldn't Create Plugin Error JSON - %v", err)
		}
		written, err := writer.Write(falcoalertjson)
		if err != nil {
			return 0, fmt.Errorf("GitLab Plugin ERROR - NextBatch(): Couldn't write Error Event - %v", err)
		}
		if written < len(gitlabErrorData) {
			return 0, fmt.Errorf("GitLab Plugin ERROR - NextBatch(): event message too long: %d, max %d supported", len(gitlabErrorData), written)
		}
	case gitlabFatalErrorData = <- oCtx.whSrvFatalErrorChan:	
		return 0, fmt.Errorf("GitLab Plugin ERROR - %s", string(gitlabFatalErrorData))
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
	Event_Type         string
	PluginErrorMessage string
}