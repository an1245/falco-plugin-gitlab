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
	MaxmindCityDBPath string `json:"MaxmindCityDBPath" jsonschema:"title=Path to Maxmind GeoLite2 or GeoIP2 City Database,required"`
	SecretsDir        string `json:"SecretsDir" jsonschema:"title=Secrets directory,required"`
	UseHTTPs          bool   `json:"UseHTTPS" jsonschema:"title=Use HTTPS,required"`
	ValidationToken   string `json:"ValidationToken" jsonschema:"title=validation token,required"`
	Debug             bool   `json:"Debug" jsonschema:"title=Enable debug output (true = yes, false=no), required, default=False"`
}


// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {

}
