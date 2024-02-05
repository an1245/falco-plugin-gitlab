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
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// Return the fields supported for extraction.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "gitlab.event_id", Display: "GitLab Audit Event ID", Desc: "What was the ID of the Audit Event"},
		{Type: "string", Name: "gitlab.event_type", Display: "GitLab Audit Event Type", Desc: "What type of audit event is it?"},
		{Type: "string", Name: "gitlab.author_id", Display: "GitLab Author ID", Desc: "What was the ID od the user that made the change"},
		{Type: "string", Name: "gitlab.author_name", Display: "GitLab Author Name", Desc: "What was the name of the user that made the change"},
		{Type: "string", Name: "gitlab.author_email", Display: "GitLab Author Email", Desc: "What was the email of the user that made the change"},
		{Type: "string", Name: "gitlab.author_class", Display: "GitLab Author Class", Desc: "What class of author made the change"},
		{Type: "string", Name: "gitlab.custom_message", Display: "GitLab Custom Audit Message", Desc: "Contents of a GitLab Custom Message"},
		{Type: "string", Name: "gitlab.entity_id", Display: "GitLab Entity ID", Desc: "What was the ID of the entity that was changed"},
		{Type: "string", Name: "gitlab.entity_type", Display: "GitLab Entity Type", Desc: "What type of entity was changed"},
		{Type: "string", Name: "gitlab.entity_path", Display: "GitLab Entity Path", Desc: "What was the path of the entity that was changed"},
		{Type: "string", Name: "gitlab.failed_login", Display: "GitLab Failed Login", Desc: "Was this a failed login?"},
		{Type: "string", Name: "gitlab.created_at", Display: "GitLab Audit Event Creation Date", Desc: "GitLab Audit Event Created Date"},
		{Type: "string", Name: "gitlab.ip_address", Display: "GitLab user IP address", Desc: "GitLab IP Address who generated Event"},
		{Type: "string", Name: "gitlab.op_type", Display: "GitLab Operation type", Desc: "GitLab Operation Type (add/remove/change)"},
		{Type: "string", Name: "gitlab.op_item", Display: "GitLab affected item", Desc: "What was added, removed or changed"},
		{Type: "string", Name: "gitlab.op_changed_from", Display: "GitLab Changed From", Desc: "What was it changed from"},
		{Type: "string", Name: "gitlab.op_changed_to", Display: "GitLab Changed To", Desc: "What was it changed to?"},
		{Type: "string", Name: "gitlab.target_id", Display: "GitLab ID of target changed", Desc: "ID of target object that was changed"},
		{Type: "string", Name: "gitlab.target_type", Display: "GitLab Type of target changed", Desc: "Type of target object that was changed"},
		{Type: "string", Name: "gitlab.target_details", Display: "GitLab Idetails of change to target", Desc: "Details of the change to the target"},

	}
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "gitlab.event_id":
		res = fmt.Sprintf("%v", jdata.GetInt("id"))
	case "gitlab.event_type":
		res = string(jdata.GetStringBytes("event_type"))
	case "gitlab.author_id":
		if jdata.GetInt("author_id") > 0 {
			res = fmt.Sprintf("%v", jdata.GetInt("author_id"))
		} else if jdata.GetInt("details","author_id") > 0 {
			res = fmt.Sprintf("%v", jdata.GetInt("details","author_id"))	
		}
	case "gitlab.author_name":
		if len(jdata.GetStringBytes("author_name")) > 0 {
			res = string(jdata.GetStringBytes("author_name"))
		} else if len(jdata.GetStringBytes("details","author_name")) > 0{
			res = string(jdata.GetStringBytes("details","author_name"))	
		}
	case "gitlab.author_email":
		if len(jdata.GetStringBytes("author_email")) > 0 {
			res = string(jdata.GetStringBytes("author_email"))
		} else if len(jdata.GetStringBytes("details","author_email")) > 0 {
			res = string(jdata.GetStringBytes("details","author_email"))	
		}
	case "gitlab.author_class":
		if len(jdata.GetStringBytes("author_class")) > 0 {
			res = string(jdata.GetStringBytes("author_class"))
		} else if len(jdata.GetStringBytes("details","author_class")) > 0{
			res = string(jdata.GetStringBytes("details","author_class"))	
		}
	case "gitlab.custom_message":
		if len(jdata.GetStringBytes("custom_message")) > 0 {
			res = string(jdata.GetStringBytes("custom_message"))
		} else if len(jdata.GetStringBytes("details","custom_message")) > 0{
			res = string(jdata.GetStringBytes("details","custom_message"))	
		}
	case "gitlab.entity_id":
		if jdata.GetInt("entity_id") > 0 {
			res = fmt.Sprintf("%v", jdata.GetInt("entity_id"))
		} else if jdata.GetInt("details","entity_id") > 0 {
			res = fmt.Sprintf("%v", jdata.GetInt("details","entity_id"))	
		}
	case "gitlab.entity_type":
		if len(jdata.GetStringBytes("entity_type")) > 0 {
			res = string(jdata.GetStringBytes("entity_type"))
		} else if len(jdata.GetStringBytes("details","entity_type")) > 0{
			res = string(jdata.GetStringBytes("details","entity_type"))	
		}
	case "gitlab.entity_path":
		if len(jdata.GetStringBytes("entity_path")) > 0 {
			res = string(jdata.GetStringBytes("entity_path"))
		} else if len(jdata.GetStringBytes("details","entity_path")) > 0 {
			res = string(jdata.GetStringBytes("details","entity_path"))	
		}
	case "gitlab.failed_login":
		print("in failed login" + string(jdata.GetStringBytes("failed_login")))
		res = string(jdata.GetStringBytes("details","failed_login"))
	case "gitlab.created_at":
		res = string(jdata.GetStringBytes("created_at"))
	case "gitlab.ip_address":
		if len(jdata.GetStringBytes("ip_address")) > 0 {
			res = string(jdata.GetStringBytes("ip_address"))
		} else if len(jdata.GetStringBytes("details","ip_address")) > 0{
			res = string(jdata.GetStringBytes("details","ip_address"))	
		}
	case "gitlab.op_type":
		// check whether add, change,  remove
		if len(jdata.GetStringBytes("details","add")) > 0 {
			res = "add"
		} else if len(jdata.GetStringBytes("details","change")) > 0 {
			res = "change"
		} else if len(jdata.GetStringBytes("details","remove")) > 0 {
			res = "remove"
		}
	case "gitlab.op_item":
		if len(jdata.GetStringBytes("details","add")) > 0 {
			res = string(jdata.GetStringBytes("details","add"))
		} else if len(jdata.GetStringBytes("details","change")) > 0 {
			res = string(jdata.GetStringBytes("details","change"))
		} else if len(jdata.GetStringBytes("details","remove")) > 0 {
			res = string(jdata.GetStringBytes("details","remove"))
		}
	case "gitlab.op_changed_from":
		res = string(jdata.GetStringBytes("details","from"))
	case "gitlab.op_changed_to":
		res = string(jdata.GetStringBytes("details","to"))
	case "gitlab.target_id":
		if jdata.GetInt("target_id") > 0 {
			res = fmt.Sprintf("%v",jdata.GetInt("target_id"))
		} else if jdata.GetInt("details","target_id") > 0{
			res = fmt.Sprintf("%v",jdata.GetInt("details","target_id"))	
		}
	case "gitlab.target_type":
		if len(jdata.GetStringBytes("target_type")) > 0 {
			res = string(jdata.GetStringBytes("target_type"))
		} else if len(jdata.GetStringBytes("details","target_type")) > 0{
			res = string(jdata.GetStringBytes("details","target_type"))	
		}
	case "gitlab.target_details":
		if len(jdata.GetStringBytes("target_details")) > 0 {
			res = string(jdata.GetStringBytes("target_details"))
		} else if len(jdata.GetStringBytes("details","target_details")) > 0{
			res = string(jdata.GetStringBytes("details","target_details"))	
		}
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
