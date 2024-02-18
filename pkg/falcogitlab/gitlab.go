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

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/oschwald/geoip2-golang"
	"github.com/valyala/fastjson"
	"net/http"
	//"log"
)

const (
	PluginID           uint32 = 999
	PluginName                = "gitlab"
	PluginDescription         = "Reads events from GitLab using API Connection"
	PluginContact             = "github.com/an1245/falco-plugin-gitlab/"
	PluginVersion             = "0.1.0"
	PluginEventSource         = "gitlab"
	ExtractEventSource        = "gitlab"
)

// Plugin represent the Box plugin
type Plugin struct {
	plugins.BasePlugin
	config      PluginConfig
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
}

// PluginInstance represents an opened instance of the plugin,
// which is returned by Open() and deinitialized during Close().
type PluginInstance struct {
	source.BaseInstance
	geodb       geoip2.Reader
	checkGeoDB  bool
	whSrv      *http.Server
	whSrvChan      chan []byte
	whSrvErrorChan chan []byte
	whSecret       string
}

// Return the plugin info to the framework.
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  PluginID,
		Name:                PluginName,
		Description:         PluginDescription,
		Contact:             PluginContact,
		Version:             PluginVersion,
		EventSource:         PluginEventSource,
		ExtractEventSources: []string{ExtractEventSource},
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are mandatory by default
		AllowAdditionalProperties:  true,  // unrecognized properties don't cause a parsing failures
	}

	
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		//log.Printf("GitLab Plugin: Config Schema=" + string(schema))
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}

	return nil
}

// Initialize the plugin state.
func (p *Plugin) Init(cfg string) error {

	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.Reset()
	json.Unmarshal([]byte(cfg), &p.config)

	return nil
}
