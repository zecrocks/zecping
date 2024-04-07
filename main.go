package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zcash/lightwalletd/walletrpc"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	serverAddr        string
	configFile        string
	useTLS            bool
	userAgent         string
	onlyIPv4          bool
	onlyIPv6          bool
	socksProxy        string
	allowInsecure     bool
	connectionTimeout int
	concurrency       int
	verbose           bool
)

func init() {
	flag.StringVar(&serverAddr, "addr", "", "Zcash Lightwalletd server address in the format of host:port")
	flag.StringVar(&configFile, "import", "", "Check all servers in a newline-delimited text file")
	flag.StringVar(&socksProxy, "socks", "", "SOCKS proxy address (e.g., '127.0.0.1:9050')")
	flag.BoolVar(&useTLS, "tls", true, "Connection uses TLS if true, else plaintext TCP")
	flag.BoolVar(&allowInsecure, "insecure", false, "Allow insecure SSL connections and skip SSL verification")
	flag.StringVar(&userAgent, "user_agent", "zecping/0.1", "Custom user agent string")
	flag.BoolVar(&onlyIPv4, "ipv4", false, "Only test IPv4 addresses")
	flag.BoolVar(&onlyIPv6, "ipv6", false, "Only test IPv6 addresses")
	flag.IntVar(&connectionTimeout, "timeout", 10, "Connection timeout (seconds)")
	flag.IntVar(&concurrency, "concurrency", 20, "Number of parallel requests to make at a time")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
}

func main() {
	flag.Parse()
	if verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	if serverAddr == "" && configFile == "" {
		log.Warn("Error: -addr or -import must be specified")
		flag.PrintDefaults()
		return
	}

	serverChan := make(chan string, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range serverChan {
				checkServer(addr)
			}
		}()
	}

	if serverAddr != "" {
		serverChan <- serverAddr
	} else {
		file, err := os.Open(configFile)
		if err != nil {
			log.Fatalf("Failed to open server list file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			serverChan <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading server list file: %v", err)
		}
	}

	close(serverChan)
	wg.Wait()
}

func checkServer(serverAddr string) {
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		log.Fatalf("Failed to parse host and port: %v", err)
	}

	var ips []net.IP
	if socksProxy == "" {
		ips, err = net.LookupIP(host)
		if err != nil {
			log.Fatalf("Failed to lookup IP addresses for host: %v", err)
		}
	} else {
		// Messy: just for the sake of entering the loop below
		ips = append(ips, net.ParseIP("127.0.0.1"))
	}

	for _, ip := range ips {
		if (onlyIPv4 && ip.To4() == nil) || (onlyIPv6 && ip.To4() != nil) {
			continue
		}
		var IPVersionString string
		if ip.To4() == nil {
			IPVersionString = "ipv6"
		} else {
			IPVersionString = "ipv4"
		}

		address := net.JoinHostPort(ip.String(), port)

		var opts []grpc.DialOption
		opts = append(opts, grpc.WithUnaryInterceptor(unaryInterceptor))
		opts = append(opts, grpc.WithUserAgent(userAgent))

		if useTLS {
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: allowInsecure,
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			opts = append(opts, grpc.WithInsecure())
		}

		var dialer func(ctx context.Context, addr string) (net.Conn, error)

		if socksProxy == "" {
			dialer = func(ctx context.Context, addr string) (net.Conn, error) {
				// Dialed address will be "passthrough:///...", instead dial to our resolved address
				return net.Dial("tcp", address)
			}
			log.Printf("Attempting to connect to %s (%s)", serverAddr, address)
		} else {
			socksDialer, err := proxy.SOCKS5("tcp", socksProxy, nil, proxy.Direct)
			if err != nil {
				log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
			}
			dialer = func(ctx context.Context, addr string) (net.Conn, error) {
				// Pass through the hostname and port from the CLI argument to let the proxy resolve DNS
				return socksDialer.Dial("tcp", serverAddr)
			}
			log.Printf("Attempting to connect via SOCKS to %s", serverAddr)
		}

		opts = append(opts, grpc.WithContextDialer(dialer))

		startTime := time.Now()
		conn, err := grpc.DialContext(context.Background(), "passthrough:///"+host, opts...)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", address, err)
			fmt.Printf("FAIL: server=%s ipv=%s ip=%s\n", serverAddr, IPVersionString, ip)
			continue
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(connectionTimeout)*time.Second)
		defer cancel()
		client := walletrpc.NewCompactTxStreamerClient(conn)

		result, err := client.GetLightdInfo(ctx, &walletrpc.Empty{})
		if err != nil {
			log.Printf("Could not get lightd info from %s: %v", address, err)
			fmt.Printf("FAIL: server=%s ipv=%s ip=%s\n", serverAddr, IPVersionString, ip)
		} else {
			log.Printf("Response (GetLightdInfo): %v", result)
			duration := formatDuration(time.Since(startTime))
			fmt.Printf("OK (%s): height=%d server=%s lwd=%s zcd=%s ipv=%s ip=%s\n", duration, result.BlockHeight, serverAddr, result.Version, result.ZcashdSubversion, IPVersionString, ip)
		}
	}
}

func unaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	startTime := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Printf("RPC call to method %s took %v", method, time.Since(startTime))
	return err
}

func formatDuration(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.2fms", ms)
}
