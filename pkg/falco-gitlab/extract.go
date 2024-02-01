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

package falco-gitlab

import (
	"fmt"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// Return the fields supported for extraction.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "gitlab.event_id", Display: "Access Token ID", Desc: "Access Token ID"},
	}
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "gitlab.event_id":
		res = string(jdata.GetStringBytes("id"))
	case "gitlab.author_id":
		res = string(jdata.GetStringBytes("author_id"))
	case "gitlab.entity_id":
		res = string(jdata.GetStringBytes("entity_id"))
	case "gitlab.entity_type":
		res = string(jdata.GetStringBytes("entity_type"))
	case "gitlab.created_at":
		res = string(jdata.GetStringBytes("created_at"))
	case "gitlab.operation_type":
		// check whether add, change,  remove
		if len(jdata.GetStringBytes("add")) > 0 {
			res = "add"
		} else if len(jdata.GetStringBytes("change")) > 0 {
			res = "change"
		} else if len(jdata.GetStringBytes("remove")) > 0 {
			res = "remove"
		}
	case "gitlab.operation_type_details":
		if len(jdata.GetStringBytes("add")) > 0 {
			res = string(jdata.GetStringBytes("add"))
		} else if len(jdata.GetStringBytes("change")) > 0 {
			res = string(jdata.GetStringBytes("change"))
		} else if len(jdata.GetStringBytes("remove")) > 0 {
			res = string(jdata.GetStringBytes("remove"))
		}
	case "gitlab.change_from":
		res = string(jdata.GetStringBytes("from"))
	case "gitlab.change_to":
		res = string(jdata.GetStringBytes("to"))
	default:
		return false, ""
	}

	return true, res
}

// Extract a field value from an event.
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := io.ReadAll(evt.Reader())
		if err != nil {
			return fmt.Errorf("GitLab Plugin ERROR: Couldn't read event from Event Reader in Extract - %v", err)
		}

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return fmt.Errorf("GitLab Plugin ERROR: Couldn't parse JSON in Extract - %v", err)
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}

	return nil
}
