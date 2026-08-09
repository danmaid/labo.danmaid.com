package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// SSH Target
	host     = "192.168.1.121"
	port     = 22
	username = "mon"
	password = "monmon"

	// Polling
	pollInterval = 1 * time.Minute
	margin       = 10 * time.Minute

	// SSH Execution
	idleTimeout    = 5 * time.Second
	overallTimeout = 60 * time.Second

	// CLI Commands
	listCommand         = "show logging application | include gc/gc_app.log | include current | nomore"
	readCommandTemplate = "show logging application %s | include GC | nomore"
)

var (
	promptSuffix = "/" + username + "#"
	generationRE = regexp.MustCompile(`gc/gc_app\.log\.(\d{14})\.`)
	gcLineRE     = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{4})`)
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)
	log.Printf("ssh-poller started")

	run()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		log.Printf("sleeping for %v", pollInterval)
		<-ticker.C
		run()
	}
}

func run() {
	log.Printf("poll started")
	start := time.Now()
	if err := poll(); err != nil {
		log.Printf("poll failed: %v", err)
	}
	log.Printf("poll completed (%v)", time.Since(start))
}

func poll() error {
	cutoff := time.Now().Add(-margin)
	log.Printf("cutoff=%s", cutoff.Format(time.RFC3339))
	log.Printf("collecting gc file list")
	listOutput, err := runCLI(listCommand)
	if err != nil {
		return err
	}
	log.Printf("gc file list collected")
	files := selectLatestGenerationFiles(listOutput)
	log.Printf("selected files=%v", files)

	for _, file := range files {
		log.Printf("collecting file=%s", file)
		command := fmt.Sprintf(readCommandTemplate, file)
		body, err := runCLI(command)
		if err != nil {
			log.Printf("failed reading %s: %v", file, err)
			continue
		}
		filtered := filterGCContent(body, cutoff)
		if filtered == "" {
			log.Printf("no matching entries found in %s", file)
			continue
		}
		fmt.Fprintln(os.Stderr, filtered)
		log.Printf("emitted log entries from %s", file)
	}
	return nil
}

func selectLatestGenerationFiles(output string) []string {
	groups := map[string][]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "gc/gc_app.log.") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		filename := fields[len(fields)-1]
		match := generationRE.FindStringSubmatch(filename)
		if match == nil {
			continue
		}
		generation := match[1]
		groups[generation] = append(groups[generation], filename)
	}
	if len(groups) == 0 {
		return nil
	}

	var generations []string
	for generation := range groups {
		generations = append(generations, generation)
	}

	sort.Strings(generations)
	latestGeneration := generations[len(generations)-1]
	files := groups[latestGeneration]
	sort.Strings(files)
	return files
}

func filterGCContent(content string, cutoff time.Time) string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		match := gcLineRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.000-0700", match[1])
		if err != nil {
			continue
		}
		if ts.Local().Before(cutoff) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func runCLI(command string) (string, error) {
	cfg := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}

	defer session.Close()
	err = session.RequestPty("xterm", 50, 200, ssh.TerminalModes{})
	if err != nil {
		return "", err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := session.Shell(); err != nil {
		return "", err
	}

	var (
		buffer   bytes.Buffer
		bufferMu sync.Mutex
		lastData = time.Now()
	)

	reader := func(r io.Reader) {
		tmp := make([]byte, 4096)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				bufferMu.Lock()
				buffer.Write(tmp[:n])
				lastData = time.Now()
				bufferMu.Unlock()
			}

			if err != nil {
				return
			}
		}
	}

	go reader(stdout)
	go reader(stderr)

	time.Sleep(2 * time.Second)
	bufferMu.Lock()
	buffer.Reset()
	bufferMu.Unlock()

	log.Printf("executing command: %s", command)
	_, err = io.WriteString(stdin, command+"\n")
	if err != nil {
		return "", err
	}

	start := time.Now()
	for {
		time.Sleep(250 * time.Millisecond)
		bufferMu.Lock()
		current := buffer.String()
		idle := time.Since(lastData)
		bufferMu.Unlock()
		if strings.Contains(current, promptSuffix) {
			log.Printf("prompt detected")
			break
		}

		if idle > idleTimeout {
			log.Printf("idle timeout detected (%v)", idle)
			break
		}

		if time.Since(start) >
			overallTimeout {
			log.Printf("overall timeout detected (%v)", overallTimeout)
			break
		}
	}

	log.Printf("command finished")
	_, _ = io.WriteString(stdin, "exit\n")
	time.Sleep(500 * time.Millisecond)
	bufferMu.Lock()
	defer bufferMu.Unlock()

	return buffer.String(), nil
}
