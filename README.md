Elasticsearch Auth Proxy
===

`auth-es-proxy` is a small web server sitting between your data forwarders (eg. `fluentd`, `fluentbit` or  `logstash`) and the `elasticsearch-client`. It will sign the requests using an authentication method of your choice. These signed requests can be verified 
