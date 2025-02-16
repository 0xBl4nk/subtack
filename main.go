package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FingerprintEntry represents one item from the can-i-take-over-xyz JSON.
type FingerprintEntry struct {
	Cname       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	NxDomain    bool     `json:"nxdomain"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Vulnerable  bool     `json:"vulnerable"`
}

// Global flags
var (
	threadsVal       int
	silentVal        bool
	rateLimitVal     int
	userAgentVal     string
	cookiesVal       string
	fingerprintsPath string
	updateVal        bool
)

var allFingerprints []FingerprintEntry

// Default URL for the fingerprints.json from EdOverflow's repo (master branch).
const defaultFingerprintsURL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json"

func main() {
	flag.IntVar(&threadsVal, "threads", 10, "Number of worker threads/goroutines")
	flag.BoolVar(&silentVal, "silent", false, "Silent mode (no banner)")
	flag.IntVar(&rateLimitVal, "rate-limit", 0, "Requests per second (0 = no limit)")
	flag.StringVar(&userAgentVal, "user-agent", "SubTack/1.0", "Custom User-Agent header")
	flag.StringVar(&cookiesVal, "cookies", "", "Cookies to send with requests (if needed)")
	flag.StringVar(&fingerprintsPath, "fingerprints", "", "Path to local fingerprints JSON file (override default cache)")
	flag.BoolVar(&updateVal, "update", false, "Force update of fingerprints from GitHub into local cache")
	flag.Parse()

	if !silentVal {
		fmt.Println("        _____       _     _             _")
		fmt.Println("       /  ___|     | |   | |           | |")
		fmt.Println("       \\ `--. _   _| |__ | |_ __ _  ___| | __")
		fmt.Println("        `--. \\ | | | '_ \\| __/ _` |/ __| |/ /")
		fmt.Println("       /\\__/ / |_| | |_) | || (_| | (__|   <")
		fmt.Println("       \\____/ \\__,_|_.__/ \\__\\__,_|\\___|_|\\_\\")
		fmt.Println("Subdomain Takeover Checker | github.com/0xBl4nk/subtack")
		fmt.Println()
	}

	// 1) Load fingerprints
	if fingerprintsPath != "" {
		// If user provided a local file, load from that path.
		err := loadFingerprintsFile(fingerprintsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading local fingerprints: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Use the cache logic
		err := ensureCache()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error ensuring cache: %v\n", err)
			os.Exit(1)
		}
		cachePath := getCacheFilePath()
		err = loadFingerprintsFile(cachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading from cache: %v\n", err)
			os.Exit(1)
		}
	}

	// 2) HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 3) Rate limiter
	var rateLimiter <-chan time.Time
	if rateLimitVal > 0 {
		interval := time.Second / time.Duration(rateLimitVal)
		ticker := time.NewTicker(interval)
		rateLimiter = ticker.C
	}

	// 4) Worker pool
	var wg sync.WaitGroup
	domainsChan := make(chan string, threadsVal)

	for i := 0; i < threadsVal; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainsChan {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				if rateLimitVal > 0 {
					<-rateLimiter
				}
				d, cn, takeover, _ := processDomain(domain, client)
				if takeover {
					fmt.Printf("[subtack] %s -> %s\n", d, cn)
				}
			}
		}()
	}

	// 5) Read domains from STDIN
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			domainsChan <- line
		}
	}
	close(domainsChan)
	wg.Wait()

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

// ensureCache handles:
// - If --update is used, it downloads fingerprints and saves them in ~/.config/subtack/fingerprints.json
// - If the cache file does not exist, it downloads it
func ensureCache() error {
	cachePath := getCacheFilePath()

	if updateVal {
		return downloadFingerprintsTo(cachePath)
	}

	_, err := os.Stat(cachePath)
	if os.IsNotExist(err) {
		return downloadFingerprintsTo(cachePath)
	} else if err != nil {
		return err
	}
	return nil
}

// downloadFingerprintsTo downloads the fingerprints from defaultFingerprintsURL and saves them to dst
func downloadFingerprintsTo(dst string) error {
	resp, err := http.Get(defaultFingerprintsURL)
	if err != nil {
		return fmt.Errorf("could not download fingerprints: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP error %d downloading fingerprints", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	dir := filepath.Dir(dst)
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, body, 0644)
	if err != nil {
		return err
	}
	return nil
}

// getCacheFilePath returns the default path: ~/.config/subtack/fingerprints.json
func getCacheFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if UserHomeDir is not available
		return "/tmp/subtack-fingerprints.json"
	}
	return filepath.Join(home, ".config", "subtack", "fingerprints.json")
}

// loadFingerprintsFile reads the JSON file from disk and unmarshals it into allFingerprints
func loadFingerprintsFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var tmp []FingerprintEntry
	err = json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	allFingerprints = tmp
	return nil
}

// processDomain handles the main takeover checking logic:
// 1) net.LookupCNAME
// 2) If NXDOMAIN, check NxDomain logic
// 3) If a service is found with Vulnerable=true, check NxDomain or fingerprint
func processDomain(domain string, client *http.Client) (string, string, bool, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		// If "no such host" => NXDOMAIN
		if strings.Contains(strings.ToLower(err.Error()), "no such host") {
			matched := matchNxDomain(domain)
			if matched != nil && matched.Vulnerable {
				return domain, "(NXDOMAIN)", true, nil
			}
		}
		return domain, "", false, err
	}

	cname = strings.TrimSuffix(cname, ".")

	entry := matchCNAME(cname)
	if entry == nil || !entry.Vulnerable {
		return domain, cname, false, nil
	}

	if entry.NxDomain {
		_, err2 := net.LookupHost(cname)
		if err2 != nil && strings.Contains(strings.ToLower(err2.Error()), "no such host") {
			return domain, cname, true, nil
		}
		return domain, cname, false, nil
	}

	if entry.Fingerprint != "" {
		isTake, err3 := checkHttpBody(domain, client, entry.Fingerprint)
		if err3 == nil && isTake {
			return domain, cname, true, nil
		}
	}

	return domain, cname, false, nil
}

// matchNxDomain checks if domain ends with a known NxDomain service's cname
func matchNxDomain(domain string) *FingerprintEntry {
	lower := strings.ToLower(domain)
	for i := range allFingerprints {
		fp := &allFingerprints[i]
		if !fp.Vulnerable || !fp.NxDomain {
			continue
		}
		for _, c := range fp.Cname {
			if c == "" {
				continue
			}
			if strings.HasSuffix(lower, strings.ToLower(c)) {
				return fp
			}
		}
	}
	return nil
}

// matchCNAME returns the fingerprint entry if the cname ends with one of the known service's cname entries
func matchCNAME(cname string) *FingerprintEntry {
	lower := strings.ToLower(cname)
	for i := range allFingerprints {
		fp := &allFingerprints[i]
		if !fp.Vulnerable {
			continue
		}
		for _, c := range fp.Cname {
			if c == "" {
				continue
			}
			if strings.HasSuffix(lower, strings.ToLower(c)) {
				return fp
			}
		}
	}
	return nil
}

// checkHttpBody sends a GET request to http://domain and checks if the fingerprint is present in the response body
func checkHttpBody(domain string, client *http.Client, fingerprint string) (bool, error) {
	url := "http://" + domain
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgentVal)
	if cookiesVal != "" {
		req.Header.Set("Cookie", cookiesVal)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if strings.Contains(string(body), fingerprint) {
		return true, nil
	}
	return false, nil
}
