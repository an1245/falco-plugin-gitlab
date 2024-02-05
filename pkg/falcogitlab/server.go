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
	"log"
	"os"
	"errors"
	"github.com/xanzy/go-gitlab"
	"encoding/json"
	"strings"

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
				err := json.NewDecoder(r.Body).Decode(&event)
				if err != nil {
					errorMessage := fmt.Sprintf("GitLab Plugin Error: Couldn't decode event" )
					createError(errorMessage,oCtx,p)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				
				for i := range event {

						tmpFalcoEvent := FalcoEvent{GitLabEvent:&event[i]}
				
						// Marshall Event into JSON
						jsonEvent, err := json.Marshal(tmpFalcoEvent)
						if err != nil {
							http.Error(w, err.Error(), http.StatusBadRequest)
							log.Printf("GitLab Plugin Error: Error marshalling Event to JSON - %v", err)
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
				http.Error(w, "Authetication Failed", http.StatusUnauthorized )
				return
			}
		} else {
			// Token was 0 length
			// Respond back with a failure
			if p.config.Debug {
				log.Printf("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it was zero length")
			}
			oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it was zero length")
			http.Error(w, "Authetication Failed", http.StatusUnauthorized )
			return
		}
	} else {
		// Token was not provided in header
		// Respond back with a failure
		if p.config.Debug {
			log.Printf("GitLab Plugin Error: Request received without X-Gitlab-Event-Streaming-Token header")
		}
		oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request received without X-Gitlab-Event-Streaming-Token header")
		http.Error(w, "Authetication Failed", http.StatusUnauthorized )
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

