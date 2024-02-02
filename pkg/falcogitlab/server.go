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

)

func server(p *Plugin, oCtx *PluginInstance) (error) {
	secretsDir := p.config.SecretsDir

	crtName := secretsDir + "/server.crt"
	keyName := secretsDir + "/server.key"

	oCtx.whSrv = nil

	isHttps := p.config.UseHTTPs

	if isHttps {
		if !(fileExists(crtName) && fileExists(keyName)) {
			err := fmt.Errorf("GitLab Plugin: Webhook webserver is configured to use HTTPs, but either %s or %s can't be found. Either provide the secrets, or set the UseHTTPs init parameter to false", keyName, crtName)
			return err
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			handleHook(w, r, oCtx)
		},
	))

	oCtx.whSrv = &http.Server{
		Handler: mux,
	}

	var err error
	if isHttps {
		log.Printf("GitLab Plugin: starting HTTPs webhook server on port 443\n")
		err = oCtx.whSrv.ListenAndServeTLS(crtName, keyName)
	} else {
		log.Printf("GitLab Plugin: starting HTTP webhook server on port 80\n")
		err = oCtx.whSrv.ListenAndServe()
	}

	if err != nil {
		return err
	}

	return nil
}

func handleHook(w http.ResponseWriter, r *http.Request, oCtx *PluginInstance) {
	
	var event gitlab.AuditEvent
	
	headers := r.Header
	val, ok := headers["X-Gitlab-Event-Streaming-Token"]
	if ok {
		tmpGitLabToken := fmt.Sprint(val)
		if len(tmpGitLabToken) > 0 {
			if tmpGitLabToken == oCtx.whSecret {
				// Token passed authentication
				err := json.NewDecoder(r.Body).Decode(&event)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				tmpFalcoEvent := FalcoEvent{GitLabEvent:&event}
				
				// Marshall Event into JSON
				jsonEvent, err := json.Marshal(tmpFalcoEvent)
				if err != nil {
					log.Printf("GitLab Plugin Error: Error marshalling Event to JSON - %v", err)
				}
				
				oCtx.whSrvChan <- jsonEvent


			} else {
				// Token didn't match configure secret
				// Respond back with a failure
				oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it didn't match configured secret")
				http.Error(w, "Authetication Failed", http.StatusUnauthorized )
				return
			}
		} else {
			// Token was 0 length
			// Respond back with a failure
			oCtx.whSrvErrorChan <- []byte("GitLab Plugin Error: Request included X-Gitlab-Event-Streaming-Token header but it was zero length")
			http.Error(w, "Authetication Failed", http.StatusUnauthorized )
			return
		}
	} else {
		// Token was not provided in header
		// Respond back with a failure
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

