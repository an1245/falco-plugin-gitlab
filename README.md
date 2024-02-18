## Introduction
The Falco Plugin for GitLab ingests *Audit Events* from GitLab and makes them available as fields in Falco.  With the GitLab Audit Event fields available in Falco, you can create Falco rules to detect GitLab threats in real-time, and alert on them through your configured notification channel. You can find more about GitLab Audit Events [here](https://docs.gitlab.com/ee/development/audit_event_guide/)

**What's the value in ingesting GitLab events into Falco?**

Well - because Falco can perform threat detection across a number of cloud platforms in parallel, it allows you to correlate security events across multiple sources in real-time, to detect active lateral movement as it is occurring.

## Prerequisites

1. The plugin needs to compile with a minimum of Go version 1.20
2. Accessing *Audit Events* requires a GitLab *Ultimate* or *Premium* subscription.
3. Whilst the plugin will work with *SaaS* or *Self-managed* offerings, instance-level audit events are only available in the *Self-managed* offering - the plugin will detect more with in the *Self-managed* offering
4. (Optional) Access to a Maxmind GeoLite or GeoIP2 database to enrich IP addresses with Geolocation information
  
### Configuring Audit Event Streaming
The plugin provides a webhook server that can be configured as an *Audit Event Streaming Destination* in GitLab.  GitLab will then forward Audit Events to Falco, which will receive them, parse them, and then alert based on rules defined in the *rules/gitlab.yaml*.  

GitLab *Audit Event Streaming Destinations* can be configured at the *Group* or *Instance* Level. Configuring event streaming at the *Instance* Level will send all the instances audit events to Falco, whereas configuring event streaming at the *Group* level will only send group level audit events - more detections will apply if you send *Instance* level events to Falco.

When you configure a instance/group level event streaming, you will be provided with a ***verification token***.  This ***verification token*** needs to be configured in *falco.yaml* to allow Falco to authentication and validate the events. 

### Configuring Instance Level Audit Events
You can find details for configuring an instance streaming destination [here](https://docs.gitlab.com/ee/administration/audit_event_streaming/#http-destinations-1) - the basic steps are:

1.  Access *Admin Area*
2.  Click *Monitoring* -> *Audit Events*
3.  Click on the *Streams* tab
4.  Select *Add streaming destination* and click *HTTP endpoint*
5.  Enter *Name* and *Destination URL*
6.  Click *Add* button to create the streaming destination
7.  Once the streaming destination is created, copy the verification token - we will use it in *falco.yaml* file
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-gitlab/assets/127995147/87eefd4d-b0ba-42dd-9597-7277aa464c0f" style="display: block;margin-left:50px" height="250" /></dd>
</dl>

### Configuring Group Level Audit Events
You can find details for configuring a group-level streaming destination [here](https://docs.gitlab.com/ee/administration/audit_event_streaming/#http-destinations) - the basic steps are:

1.  On the left sidebar, select Search or go to and find your group.
2.  Select Secure > Audit events.
3.  On the main area, select the *Streams* tab.
4.  Select *Add streaming destination* and click *HTTP endpoint*
5.  Enter *Name* and *Destination URL*
6.  Click *Add* button to create the streaming destination
7.  Once the streaming destination is created, copy the verification token - we will use it in *falco.yaml* file
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-gitlab/assets/127995147/87eefd4d-b0ba-42dd-9597-7277aa464c0f" style="display: block;margin-left:50px" height="250" /></dd>
</dl>

### Download Maxmind City Database for IP Geolocation enrichment
The plugin has the ability to enrich IP addresses with geolocation information using the Maxmind GeoLite (free) or GeoIP2 (commercial) databases. You can register for Maxmind databases [here](https://www.maxmind.com/en/geolite2/signup).   Once you have downloaded the ***Maxmind City Database*** in mmdb format, store it somewhere on the file system where Falco can access it.  

You can then configure the plugin to use the database by configuring the *maxmindcitydbpath* option in *falco.yaml*. See *Configuring the plugin* section below.


## Building the GitLab plugin
1. Download the plugin from GitHub using git
2. Change directory to falco-plugin-gitlab
3. Compile the plugin using *make*
4. Copy *libgitlab.so* to */usr/share/falco/plugins*
5. Copy the rules to /etc/falco/rules.d/
```
git clone https://github.com/an1245/falco-plugin-gitlab
cd falco-plugin-gitlab
make
cp libgitlab.so /usr/share/falco/plugins/
cp rules/* /etc/falco/rules.d/
```

## Configuring the plugin
Now that you have configured your streaming destination and collected your ***verification token***, you can provide them as values in the falco.yaml file.  

In the configuration file you will find the following settings:
- **UseHTTPS** and **SecretsDir** - to configure the plugin to use HTTPS for the webhook server (you should do this!)
- **VerificationToken** - here you put your verification token that was supplied in the destination configuration 
- **MaxmindCityDBPath** - path to your Maxmind City DB (oiptional)
- **Debug** and **DebugJSON** - to enable plugin debugging or rule creation

```
- name: gitlab
    library_path: libgitlab.so
    init_config:
      SecretsDir: /path/to/ssl-cert-and-key-files
      UseHTTPS: true
      VerificationToken: {YOUR VERIFICATION TOKEN}
      MaxmindCityDBPath: /path/to/GeoLite2-City.mmdb
      Debug: false
      DebugJSON: false
```

Now that you've got the plugin configuration done, you can enable it by adding the plugin name to the *load_plugins* configuration setting.
```
load_plugins: [gitlab]
```

Now start Falco.  
- If you have set the plugin *UseHTTPS* configuration option to true, the plugin will start a SSL enabled web server on port TCP/443.   
- If you have set the plugin *UseHTTPS* configuration option to false, the plugin will start a SSL enabled web server on port TCP/80.  

## Firewalling the plugin
To ensure that only that only the GitLab server(s) can talk to the plugin, make sure that you firewall the source IPs that can access the webhook server. If you are connecting to the GitLab SaaS service, you can find information about the ip ranges that GitLab use for that service [here](https://docs.gitlab.com/ee/user/gitlab_com/#ip-range)

## Debugging the Plugin

We recommend leaving Debug set to False unless you are trying to troubleshoot the plugin.  

But if you need to troubleshoot the plugin, you set ***Debug: True*** and then run ***falco*** manually from the command line - this will output debug messages to  STDOUT.  You can also set the ***DebugJSON*** value to ***True*** to print the raw JSON message coming from GitLab.

## Default Rules

You can find a number of sample Falco rules in the *rules/gitlab.yaml* file which will detect a number of malicious events including:

- Accessing Admin Mode from an IP address in an unknown country
- Failed user logins - both failed passwords and OTP token failures
- Disabling or 2-Factor Authentication at a user or group level
- Creation of new SSH certificates, GPG Keys or Personal/Project/Group Access tokens
- Creation of new Deploy or Cluster Agent tokens

Here are four tips for creating your own rules.

1. GitLab provides the *event_type* field in the streaming events which we can use as conditions in Falco rules.  You can find documentation on the *event_types* [here](https://docs.gitlab.com/ee/administration/audit_event_types.html)
2. You can view some sample JSON messages in the *tests/jsonmessages/* directory
3. GitLab doesn't currently provide documentation for each events JSON response document; however, there is a rule in *rules/gitlab.yaml* called ***GitLab Catch All*** - it's commented out by default to reduce noise, but you can enable this rule to alert on every GitLab Event not captured by another rule and output all the mapped fields.
4. You can also set the ***DebugJSON*** to true and can see how the GitLab fields are mapped to Falco fields by observing the *Falco Event JSON:* log message.  

## Exported Fields

A number of fields are mapped across from GitLab event fields into Falco fields - these can be seen in the table below.

| Field Name | Type | Description |
| ----------- | ----------- |  ----------- |
| gitlab.event_id | string | What was the ID of the Audit Event |
| gitlab.event_type | string | What type of audit event was it? [check here](https://docs.gitlab.com/ee/administration/audit_event_types.html) |
| gitlab.author_id | string | What was the ID of the user that made the change |
| gitlab.author_name | string | What was the name of the user that made the change |
| gitlab.author_email | string | What was the email of the user that made the change |
| gitlab.author_class | string | What was the class of author made the change |
| gitlab.custom_message | string | Contents of a GitLab Custom Message supplied with the event |
| gitlab.city | string | The city where the user’s IP address is physically located |
| gitlab.country | string | The country where the user’s IP address is physically located |
| gitlab.countryisocode | string | The country iso code where the user’s IP address is physically located |
| gitlab.continent | string | The continent where the user’s IP address is physically located |
| gitlab.entity_id | string | What was the ID of the entity that was changed |
| gitlab.entity_type | string | What type of entity was changed |
| gitlab.entity_path | string | What was the path of the entity that was changed |
| gitlab.failed_login | string | What type of login failed (STANDARD, OTP etc.) |
| gitlab.created_at | string | What was the date that the event was created? |
| gitlab.ip_address | string | What was the IP address of the user that created the event? |
| gitlab.op_type | string | What GitLab Operation Type occurred (add/remove/change) |
| gitlab.op_item | string | What was added, removed or changed |
| gitlab.op_changed_from | string | What was it changed from? |
| gitlab.op_changed_to | string | What was it changed to? |
| gitlab.target_id | string | What was the ID of target object that was changed |
| gitlab.target_type | string | What was the type of target object that was changed |
| gitlab.target_details | string | What was the details of the change to the target |
| gitlab.pluginerrormessage | string | If there was a plugin error, the error message will be sent in this field |


## Note

I have also created a version of the plugin that supports polling the GitLab API to fetch Audit Events -  however, currently GitLab doesn't ship the *event_type* field in the API delivered events so the rules don't work.  So this polling approach is still a work-in-progress, but this version of the plugin is available in *polling-and-webhook* branch.

## Feedback

Please provide me with feedback if you think there are better ways I could do things - you can do that by starting a discussion or logging an issue! 


## Thanks

Thanks to the folks who helped out with this plugin.
