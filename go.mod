module github.com/emersonian/zecping

go 1.20

require (
	github.com/sirupsen/logrus v1.9.3
	github.com/zcash/lightwalletd v0.4.16
	golang.org/x/net v0.34.0
	google.golang.org/grpc v1.62.1
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240123012728-ef4313101c80 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace github.com/zcash/lightwalletd => github.com/zecrocks/lightwalletd v0.0.0-20250216193251-38c29195e9d3
