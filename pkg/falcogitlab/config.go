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
	APIOrWebhook      string `json:"APIOrWebhook" jsonschema:"title=api or webhook?,required,default=webhook,pattern=^(api|webhook)$"`
	GitLabToken       string `json:"GitLabToken" jsonschema:"title=GitLab Token,required"`
	GitLabBaseURL     string `json:"GitLabBaseURL" jsonschema:"title=GitLab Base URL (default: https://gitlab.com/),required,default=https://gitlab.com/,format=uri"`
	SkipSSLVerification  bool `json:"SkipSSLVerification" jsonschema:"title=Skip SSL Verification on API Polling,required,default=False"`
	MaxmindCityDBPath string `json:"MaxmindCityDBPath" jsonschema:"title=Path to Maxmind GeoLite2 or GeoIP2 City Database,required"`
	SecretsDir        string `json:"SecretsDir" jsonschema:"title=Secrets directory,required"`
	UseHTTPs          bool   `json:"UseHTTPS" jsonschema:"title=Use HTTPS,required"`
	VerificationToken   string `json:"VerificationToken" jsonschema:"title=validation token,required"`
	Debug             bool   `json:"Debug" jsonschema:"title=Enable debug output (true = yes, false=no), required, default=False"`
	DebugJSON         bool 	 `json:"DebugJSON" jsonschema:"title=Show JSON Received(true = yes, false=no), default=False"`
	PollIntervalSecs  int    `json:"PollIntervalSecs" jsonschema:"title=How often do you want to poll the API?,required,default=300"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {

}
