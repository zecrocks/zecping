# zecping

See the gRPC response times of [Zaino](https://github.com/zingolabs/zaino) or [Zcash Lightwalletd](https://github.com/zcash/lightwalletd) nodes.

<img width="1215" alt="zecping" src="https://github.com/emersonian/zecping/assets/19352366/bf69c3ea-b429-453a-af06-26dfb78dd20f">

For a web dashboard showing server uptimes, see [Hosh](https://github.com/zecrocks/hosh).

## Installation

Prerequisite: Golang 1.17+

```
go build
./zecping -help
```
### Docker

```
docker build . -t zp
docker run -ti --rm zp zecping -addr zec.rocks:443
```

Caveat: most Docker installations do not support IPv6 right now, you may see IPv6 failures.

## Examples

```
./zecping -addr zec.rocks:443
```

You can also ping all servers in a list:
```
./zecping -import servers.txt
```

For example, to see which servers support IPv6, run this on a connection that supports IPv6:
```
./zecping -import servers.txt -ipv6
```

### SOCKS support (Tor)

Prerequisite: Install Tor Browser and leave it open (for port 9150), or install the Tor daemon on your local machine (and use port 9050).

TLS is not typical over Tor since the domain name itself authenticates the remote server and traffic is always encrypted to the destination. It is also difficult to obtain SSL certificates for Tor .onion domains, only Digicert offers them at the moment. LetsEncrypt does not support Tor.

```
./zecping -socks localhost:9150 -addr lzzfytqg24a7v6ejqh2q4ecaop6mf62gupvdimc4ryxeixtdtzxxjmad.onion:443
```

Tunneling requests to sites other than Tor hidden services is also supported, useful to see if they are blocking Tor exits:

```
./zecping -socks=127.0.0.1:9150 -timeout=30 -addr zec.rocks:443
```

## Usage

```
Usage of ./zecping:
  -addr string
    	Zcash Lightwalletd server address in the format of host:port
  -import string
    	Check all servers in a newline-delimited text file
  -insecure
    	Allow insecure SSL connections and skip SSL verification
  -ipv4
    	Only test IPv4 addresses
  -ipv6
    	Only test IPv6 addresses
  -socks string
    	SOCKS proxy address (e.g., '127.0.0.1:9050')
  -timeout int
    	Connection timeout (seconds) (default 10)
  -tls
    	Connection uses TLS if true, else plaintext TCP (default true)
  -user_agent string
    	Custom user agent string (default "zecping/0.1")
  -v	Enable verbose logging
```
