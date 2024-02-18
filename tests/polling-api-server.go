package main

import (
        "log"
        "net/http"
        "io/ioutil"
        "strings"
        "bytes"
)

func apiHandler(w http.ResponseWriter, r *http.Request) {
        println("Handling new stream")
        stream, err := ioutil.ReadFile("./gitlab-event.txt")
        if err != nil {
		println("GitLab Polling API Server: Couldn't read gitlab-event.txt")
	}
        b := bytes.NewBuffer(stream)
        
        switch r.Method {
        case "GET":
                println("- Handling GET Request")
                println("- Enumerating Headers")
                headers := r.Header
                for name, values := range r.Header {
                        // Loop over all values for the name.
                        for _, value := range values {
                            println("---" + name + "=" + value)
                        }
                    }

                    println("- Checking for Authorization Header")
	        val, ok := headers["Authorization"]
	        if ok {
                        println("- Found Authorization Header")
		        tmpGitLabToken := strings.Join(val,"")
		        if len(tmpGitLabToken) > 0 {
                                println("- Token provided was greater than zero length")
			        if tmpGitLabToken == "Bearer testing123" {
                                        println("- Token authenticated correctly. Writing Response Headers")
                                        w.WriteHeader(http.StatusOK)
                                        w.Header().Set("Content-type", "application/json")
				        b.WriteTo(w)
                                        println("- sending JSON payload")
                                       
                                } else { 
                                        w.WriteHeader(http.StatusUnauthorized)
                                        w.Write([]byte("Unauthorized"))
                                }
                        } else { 
                                w.WriteHeader(http.StatusUnauthorized)
                                w.Write([]byte("Unauthorized"))
                        }
                } else { 
                        w.WriteHeader(http.StatusUnauthorized)
                        w.Write([]byte("Unauthorized"))
                }
                
        default:
                w.WriteHeader(http.StatusMethodNotAllowed)
                w.Write([]byte("Method Not Allowed"))
        }
}

func main() {
        http.HandleFunc("/api/v4/audit_events", apiHandler)

        log.Println("Waiting for new connect on TCP/8080")
        http.ListenAndServe(":8080", nil)
}
