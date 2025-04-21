package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zcash/lightwalletd/walletrpc"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	showDonation      bool
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
	flag.BoolVar(&showDonation, "donation", false, "Show server donation address if available")
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

	tlsFlagExplicitlySet := false
	timeoutFlagExplicitlySet := false
	socksFlagExplicitlySet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "tls" {
			tlsFlagExplicitlySet = true
		}
		if f.Name == "timeout" {
			timeoutFlagExplicitlySet = true
		}
		if f.Name == "socks" {
			socksFlagExplicitlySet = true
		}
	})

	if serverAddr != "" && !socksFlagExplicitlySet {
		host, _, err := net.SplitHostPort(serverAddr)
		if err == nil && strings.HasSuffix(host, ".onion") {
			log.Info("Onion address detected without SOCKS proxy. Checking for Tor on common ports...")

			// Try to auto-detect Tor proxy by checking common ports
			torFound := false
			if isPortOpen("localhost:9050") {
				torFound = true
				log.Info("Found open SOCKS port at localhost:9050 (Tor daemon)")
			} else if isPortOpen("localhost:9150") {
				torFound = true
				log.Info("Found open SOCKS port at localhost:9150 (Tor Browser)")
			}

			if !torFound {
				log.Fatal("Error: Tor must be running to test .onion addresses. Please:\n" +
					"  1. Start Tor Browser or Tor daemon, or\n" +
					"  2. Specify a SOCKS proxy which supports Tor using -socks=<host:port>")
			}
		}
	}

	serverChan := make(chan string, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range serverChan {
				shouldUseTLS := useTLS
				serverTimeout := connectionTimeout
				localSocksProxy := socksProxy

				host, _, err := net.SplitHostPort(addr)
				isOnionAddress := err == nil && strings.HasSuffix(host, ".onion")

				if isOnionAddress {
					if !tlsFlagExplicitlySet {
						log.Infof("Onion address detected for %s. Disabling TLS by default.", addr)
						shouldUseTLS = false
					}

					if !timeoutFlagExplicitlySet {
						log.Infof("Onion address detected for %s. Using increased timeout of 20 seconds.", addr)
						serverTimeout = 20
					}

					if !socksFlagExplicitlySet && localSocksProxy == "" {
						log.Warnf("Onion address %s requires SOCKS proxy. Using any auto-detected proxy.", addr)

						if isPortOpen("localhost:9050") {
							localSocksProxy = "localhost:9050"
							log.Info("Found open SOCKS port at localhost:9050 (Tor daemon)")
						} else if isPortOpen("localhost:9150") {
							localSocksProxy = "localhost:9150"
							log.Info("Found open SOCKS port at localhost:9150 (Tor Browser)")
						} else {
							log.Errorf("Cannot connect to %s: no SOCKS proxy available for .onion address", addr)
							fmt.Printf("FAIL: server=%s reason=no_socks_proxy\n", addr)
							continue
						}
					}
				}

				checkServer(addr, shouldUseTLS, serverTimeout, localSocksProxy)
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

func checkServer(serverAddr string, shouldUseTLS bool, serverTimeout int, socksProxy string) {
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		log.Fatalf("Failed to parse host and port: %v", err)
	}

	isOnionAddress := strings.HasSuffix(host, ".onion")

	var ips []net.IP
	if socksProxy == "" {
		if isOnionAddress {
			log.Fatalf("Cannot connect to .onion address without a SOCKS proxy. Use -socks option.")
		}

		ips, err = net.LookupIP(host)
		if err != nil {
			log.Fatalf("Failed to lookup IP addresses for host: %v", err)
		}
	} else {
		// Add a placeholder IP just to enter the loop below
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

		if shouldUseTLS {
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: allowInsecure,
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		var dialer func(ctx context.Context, addr string) (net.Conn, error)

		if socksProxy == "" {
			dialer = func(ctx context.Context, addr string) (net.Conn, error) {
				// Dialed address will be "passthrough:///...", instead dial to our resolved address
				return net.Dial("tcp", address)
			}
			log.Printf("Attempting to connect to %s (%s) with TLS=%v, timeout=%ds", serverAddr, address, shouldUseTLS, serverTimeout)
		} else {
			socksDialer, err := proxy.SOCKS5("tcp", socksProxy, nil, proxy.Direct)
			if err != nil {
				log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
			}
			dialer = func(ctx context.Context, addr string) (net.Conn, error) {
				// Pass through the hostname and port from the CLI argument to let the proxy resolve DNS
				return socksDialer.Dial("tcp", serverAddr)
			}
			log.Printf("Attempting to connect via SOCKS to %s with TLS=%v, timeout=%ds", serverAddr, shouldUseTLS, serverTimeout)
		}

		opts = append(opts, grpc.WithContextDialer(dialer))

		startTime := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(serverTimeout)*time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, "passthrough:///"+host, opts...)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", address, err)
			fmt.Printf("FAIL: server=%s ipv=%s ip=%s\n", serverAddr, IPVersionString, ip)
			continue
		}
		defer conn.Close()

		client := walletrpc.NewCompactTxStreamerClient(conn)

		result, err := client.GetLightdInfo(ctx, &walletrpc.Empty{})
		if err != nil {
			log.Printf("Could not get lightd info from %s: %v", address, err)
			fmt.Printf("FAIL: server=%s ipv=%s ip=%s\n", serverAddr, IPVersionString, ip)
		} else {
			log.Printf("Response (GetLightdInfo): %v", result)
			duration := formatDuration(time.Since(startTime))
			output := fmt.Sprintf("OK (%s): height=%d server=%s lwd=%s zcd=%s ipv=%s ip=%s",
				duration, result.BlockHeight, serverAddr, result.Version,
				result.ZcashdSubversion, IPVersionString, ip)
			if showDonation {
				output += fmt.Sprintf(" donation=%s", result.DonationAddress)
			}
			fmt.Println(output)
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

func isPortOpen(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		log.Debugf("Port check failed for %s: %v", addr, err)
		return false
	}
	conn.Close()
	return true
}
