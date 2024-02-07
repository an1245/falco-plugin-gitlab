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
	"fmt"
	"net/http"
	"net/http/httputil"
	"log"
	"net"
	"os"
	"errors"
	"github.com/xanzy/go-gitlab"
	"encoding/json"
	"strings"
	//"github.com/oschwald/geoip2-golang"

)

func createError(message string, oCtx *PluginInstance, p *Plugin) {
	// Start: Send an alert to Falco
	if p.config.Debug {
		log.Print(message)
	}
	
	falcoalert := ErrorMessage{"pluginerror", message}
	falcoalertjson, err := json.Marshal(falcoalert)
	if err != nil {
		log.Printf("GitLab Plugin Error - breakOut(): Couldn't Create Plugin Error JSON")
	}
	oCtx.whSrvErrorChan <- falcoalertjson

}

func webhookServer(p *Plugin, oCtx *PluginInstance){
	
	// Get the certificates from the directory
	secretsDir := p.config.SecretsDir
	crtName := secretsDir + "/server.crt"
	keyName := secretsDir + "/server.key"

	oCtx.whSrv = nil

	isHttps := p.config.UseHTTPs

	// Check HTTPS certificates exist
	if isHttps {
		if !(fileExists(crtName) && fileExists(keyName)) {
			errorMessage := fmt.Sprintf("GitLab Plugin: Webhook webserver is configured to use HTTPs, but either %s or %s can't be found. Either provide the secrets, or set the UseHTTPs init parameter to false", keyName, crtName)
			createError(errorMessage,oCtx,p)
			return
		}
	}

	// Create HTTP Connection Handler
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			handleHook(w, r, oCtx,p)
		},
	))

	// Create HTTP Server
	oCtx.whSrv = &http.Server{
		Handler: mux,
	}

	// Connect HTTP Server
	var err error
	if isHttps {
		if p.config.Debug {
			log.Printf("GitLab Plugin: starting HTTPs webhook server on port 443\n")
		}
		err = oCtx.whSrv.ListenAndServeTLS(crtName, keyName)
	} else {
		if p.config.Debug {
			log.Printf("GitLab Plugin: starting HTTP webhook server on port 80\n")
		}
		err = oCtx.whSrv.ListenAndServe()
	}

	if err != nil {
		errorMessage := fmt.Sprintf("GitLab Plugin: Webhook webserver is configured to use HTTPs, but either %s or %s can't be found. Either provide the secrets, or set the UseHTTPs init parameter to false", keyName, crtName)
		createError(errorMessage,oCtx,p)
		return
	}

	return 
}

func handleHook(w http.ResponseWriter, r *http.Request, oCtx *PluginInstance, p *Plugin) {
	
	event := []gitlab.AuditEvent{}
	
	headers := r.Header
	val, ok := headers["X-Gitlab-Event-Streaming-Token"]
	if ok {
		tmpGitLabToken := strings.Join(val,"")
		if len(tmpGitLabToken) > 0 {
			if tmpGitLabToken == oCtx.whSecret {
				// Token passed authentication
				r.ParseForm()
				err := json.NewDecoder(r.PostForm).Decode(&event)
				if err != nil {
					errorMessage := fmt.Sprintf("GitLab Plugin Error: Couldn't decode event" )
					createError(errorMessage,oCtx,p)
					if p.config.Debug {
						res, err := httputil.DumpRequest(r, true)  
						if err != nil {  
							log.Printf("GitLab Plugin Error: Couldn't dump request")  
						}  
			
						log.Printf("GitLab Plugin Error: HTTP REQUEST - %v",string(res))
						log.Printf("GitLab Plugin Error: Post Form Variables")
						
						for key, value := range r.PostForm {
							log.Printf("-- %s = %s", key, value)

						}
						log.Printf("GitLab Plugin Error: Form Variables")
						for key, value := range r.Form {
							log.Printf("-- %s = %s", key, value)

						}
					}
					
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("Request Failed"))
					return
				}
				
				for i := range event {

						tmpFalcoEvent := FalcoEvent{GitLabEvent:&event[i]}
						
						tmpFalcoEventType, _ := headers["X-Gitlab-Audit-Event-Type"]
						tmpFalcoEvent.EventType = strings.Join(tmpFalcoEventType,"")

						// Check if the IP exists
						ipstr := event[i].Details.IPAddress
						if strings.Contains(ipstr, ",") {
							stringSlice := strings.Split(ipstr, ",")
							ipstr = stringSlice[0]
						}


						// If Geolocation enrichment is enabled then enrich the IP with Geolocation info
						// Start Geolocation Enrichment
						if oCtx.checkGeoDB && len(ipstr) > 0 {
							ip := net.ParseIP(ipstr)
							if ip != nil {
								city, err := oCtx.geodb.City(ip)
								if err != nil {
									if p.config.Debug  {
										log.Printf("GitLab Plugin WARNING: fetchAuditAPI: couldn't get City() for ip: " + ipstr)
									}
								}
								
								tmpFalcoEvent.City = city.City.Names["en"]
								tmpFalcoEvent.Country = city.Country.Names["en"]
								tmpFalcoEvent.CountryIsoCode = city.Country.IsoCode
								tmpFalcoEvent.Continent = city.Continent.Names["en"]
							} else {
								log.Printf("GitLab Plugin WARNING: handleHook: Couldn't parse IP: " + ipstr)
							}

						} 
						// End Geolocation Enrichment													
				
						// Marshall Event into JSON
						jsonEvent, err := json.Marshal(tmpFalcoEvent)
						if err != nil {
							errorMessage := fmt.Sprintf("GitLab Plugin Error: Error marshalling Event to JSON - %v", err)
							createError(errorMessage,oCtx,p)
							continue;
						}
						
						oCtx.whSrvChan <- jsonEvent
					}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Request Successful"))
				return


			} else {
				// Token didn't match configure secret
				// Respond back with a failure
				if p.config.Debug {
					log.Printf("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it didn't match configured secret (token provided: %v | token configured: %v)", val, oCtx.whSecret )
				}
				oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it didn't match configured secret")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Authetication Failed"))
				return
			}
		} else {
			// Token was 0 length
			// Respond back with a failure
			if p.config.Debug {
				log.Printf("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it was zero length")
			}
			oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it was zero length")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authetication Failed"))
			return
		}
	} else {
		// Token was not provided in header
		// Respond back with a failure
		if p.config.Debug {
			log.Printf("GitLab Plugin Error: Request received without X-Gitlab-Event-Streaming-Token header")
		}
		oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request received without X-Gitlab-Event-Streaming-Token header")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authetication Failed"))
		return
	}
}



func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

