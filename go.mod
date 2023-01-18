module storj.io/minio

go 1.18

require (
	git.apache.org/thrift.git v0.13.0
	github.com/Azure/azure-pipeline-go v0.2.2
	github.com/Azure/azure-storage-blob-go v0.10.0
	github.com/Shopify/sarama v1.27.2
	github.com/VividCortex/ewma v1.1.1
	github.com/alecthomas/participle v0.2.1
	github.com/bcicen/jstream v1.0.1
	github.com/beevik/ntp v0.3.0
	github.com/cespare/xxhash/v2 v2.1.1
	github.com/cheggaaa/pb v1.0.29
	github.com/colinmarc/hdfs/v2 v2.2.0
	github.com/dchest/siphash v1.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/djherbis/atime v1.0.0
	github.com/dswarbrick/smart v0.0.0-20190505152634-909a45200d6d
	github.com/dustin/go-humanize v1.0.0
	github.com/eclipse/paho.mqtt.golang v1.3.0
	github.com/fatih/color v1.10.0
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gomodule/redigo v1.8.3
	github.com/google/uuid v1.1.2
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/jcmturner/gokrb5/v8 v8.4.2
	github.com/json-iterator/go v1.1.10
	github.com/klauspost/compress v1.13.4
	github.com/klauspost/cpuid/v2 v2.0.4
	github.com/klauspost/pgzip v1.2.5
	github.com/klauspost/readahead v1.3.1
	github.com/klauspost/reedsolomon v1.9.11
	github.com/lib/pq v1.9.0
	github.com/mattn/go-colorable v0.1.8
	github.com/mattn/go-isatty v0.0.12
	github.com/miekg/dns v1.1.35
	github.com/minio/cli v1.22.0
	github.com/minio/highwayhash v1.0.2
	github.com/minio/minio-go/v7 v7.0.11-0.20210302210017-6ae69c73ce78
	github.com/minio/selfupdate v0.3.1
	github.com/minio/sha256-simd v1.0.0
	github.com/minio/simdjson-go v0.2.1
	github.com/minio/sio v0.2.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/montanaflynn/stats v0.5.0
	github.com/nats-io/nats-server/v2 v2.7.2
	github.com/nats-io/nats.go v1.13.1-0.20220121202836-972a071d373d
	github.com/nats-io/stan.go v0.8.3
	github.com/ncw/directio v1.0.5
	github.com/nsqio/go-nsq v1.0.8
	github.com/olivere/elastic/v7 v7.0.22
	github.com/philhofer/fwd v1.1.1
	github.com/pierrec/lz4 v2.5.2+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/procfs v0.6.0
	github.com/rjeczalik/notify v0.9.2
	github.com/rs/cors v1.7.0
	github.com/secure-io/sio-go v0.3.1
	github.com/shirou/gopsutil/v3 v3.21.1
	github.com/streadway/amqp v1.0.0
	github.com/tidwall/gjson v1.9.3
	github.com/tidwall/sjson v1.0.4
	github.com/tinylib/msgp v1.1.3
	github.com/valyala/tcplisten v0.0.0-20161114210144-ceec8f93295a
	github.com/willf/bloom v2.0.3+incompatible
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/sys v0.0.0-20220111092808-5a964db01320
	google.golang.org/api v0.14.0
	gopkg.in/yaml.v2 v2.3.0
)

require (
	github.com/Azure/go-autorest/autorest/adal v0.9.1 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/eapache/go-resiliency v1.2.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.4 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/minio/md5-simd v1.1.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/nats-io/jwt/v2 v2.2.1-0.20220113022732-58e87895b296 // indirect
	github.com/nats-io/nats-streaming-server v0.21.1 // indirect
	github.com/nats-io/nkeys v0.3.0 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/prometheus/common v0.14.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/rs/xid v1.2.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/willf/bitset v1.1.11 // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	google.golang.org/protobuf v1.23.0 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/gokrb5.v7 v7.5.0 // indirect
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
)
