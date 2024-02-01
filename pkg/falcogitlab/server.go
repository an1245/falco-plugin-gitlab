package falcogitlab

import (
	"fmt"
	"net/http"
	"log"
	"os"
	"errors"

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
	
	// Get 
	
	headers := r.Header
	val, ok := headers["X-Gitlab-Event-Streaming-Token"]
	if ok {
		tmpGitLabToken := fmt.Sprint(val)
		if len(tmpGitLabToken) > 0 {
			if tmpGitLabToken == oCtx.whSecret {
				// Token passed authentication


				//oCtx.whSrvChan <- jsonString

			}
		}
	} else {
		// Token failed to authenticate
		// Need to respond back with a failure

	}
}

func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

