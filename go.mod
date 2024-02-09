module falcogitlab

go 1.20

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/falcosecurity/plugin-sdk-go v0.7.3
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/valyala/fastjson v1.6.4
)

require (
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/oschwald/maxminddb-golang v1.11.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/xanzy/go-gitlab => github.com/an1245/go-gitlab v0.0.0-20240205022857-a9f900add94a
