# falco-plugin-gitlab
This is a version of the plugin with polling and webhook - THIS IS NOT PRODUCTION READY.


## Configuration

```
- name: gitlab
    library_path: libgitlab.so
    init_config:
      APIOrWebhook: api
      GitLabToken: glpat-asdfghjkldfghjfghj
      GitLabBaseURL: http://gitlab.com
      SecretsDir: /path/to/certdirectory/
      UseHTTPS: true
      ValidationToken: webhook-validation-token
      MaxmindCityDBPath: /path/to/GeoLite2-City.mmdb
      Debug: false
      DebugJSON: false
      PollIntervalSecs: 300
```
