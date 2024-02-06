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

// PluginConfig represents a configuration of the GitHub plugin
type PluginConfig struct {
	APIOrWebhook	  string `json:"APIOrWebhook" jsonschema:"title=API or Webhook?,required,default=webhook"`
	GitLabToken       string `json:"GitLabToken" jsonschema:"title=GitLab Token,required"`
	GitLabBaseURL     string `json:"GitLabBaseURL" jsonschema:"title=GitLab Base URL (default: https://gitlab.com/),default=https://gitlab.com/,format=uri"`
	MaxmindCityDBPath string `json:"maxmindcitydbpath" jsonschema:"title=Path to Maxmind GeoLite2 or GeoIP2 City Database"`
	SecretsDir        string `json:"secretsDir" jsonschema:"title=Secrets directory,description=The directory where the secrets required by the plugin are stored. Unless the github token is provided by environment variable, it must be stored in a file named github.token in this directory. In addition, when the webhook server uses HTTPs, server.key and server.crt must be in this directory too."`
	UseHTTPs          bool   `json:"UseHTTPs" jsonschema:"title=Use HTTPS,description=if this parameter is set to true, then the webhook webserver listening at WebsocketServerURL will use HTTPS. In that case, server.key and server.crt must be present in the secrets directory, or the plugin will fail to load. If the parameter is set to false, the webhook webserver will be plain HTTP. Use HTTP only for testing or when the plugin is behind a proxy that handles encryption."`
	ValidationToken   string `json:"ValidationToken" jsonschema:"title=validation token,description=Token for valiating webhook messages"`
	Debug             bool   `json:"Debug" jsonschema:"title=Enable debug output (true = yes, false=no), default=False"`
	DebugLevel        int    `json:"DebugLevel" jsonschema:"title=What Debug Level is set (0 through 4), default=0"`
	PollIntervalSecs  int    `json:"PollIntervalSecs" jsonschema:"title=How often do you want to poll the API?,required,default=300"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {

}
