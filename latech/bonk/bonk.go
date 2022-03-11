package main

import (
	"bufio"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/fatih/color"
)

var (
	fs              = flag.NewFlagSet("bonk", flag.ExitOnError)
	diag            = fs.String("diag", "/var/log/bonk/logs", "(do not change) dump raw information from kernel to file")
	rate            = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog         = fs.Uint("backlog", 8192, "backlog limit")
	receiveOnly     = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
	mode            = fs.String("mode", "load", "[load/bonk/list] choose between\n>'load' (load rules)\n>'bonk' (bonk processes)\n>'honk' (just honk no bonk)\n")
	verbose         = fs.Bool("v", true, "whether to print to stdout or not")
	colorEnabled    = fs.Bool("color", true, "whether to use color or not")
	configPath      = fs.String("config", "", "where custom config is located")
	showInfo        = fs.Bool("info", true, "whether to show informational warnings or just bonks")
	BonksBeforeWarn = fs.Int("warn", 10, "Number of bonkable offenses before IP address is said to be a potential threat of an IP")
	BonkByIPAllow   = fs.Bool("bonkip-a", false, "do not bonk processes in the allow list set by /etc/bonk/config.json (defualt false)")
	BonkByIPDeny    = fs.Bool("bonkip-d", false, "kills IP addresses in the deny list set by /etc/bonk/config.json (defualt false)")
	cf              = Config{}
	RawLogger       *log.Logger
	CoolLogger      *log.Logger
	IPAddresses     map[string]int
	// ptraceKill   = fs.Bool("ptrace", false, "use ptrace trolling to kill process rudely")
	// immutable    = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")

	//go:embed embed/good.rules
	//go:embed embed/bonk.art
	//go:embed embed/config.json
	res embed.FS
)

// // go:embed 43-module-load.rules
// var embededRules embed.FS

const (
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	CONFIGPATH = "/etc/bonk/config.json"
	// RULESPATH = "/etc/bonk/config"
	LOGSPATH     = "/var/log/bonk/bonk.log"
	LOGSRAWPATH  = "/var/log/bonk/bonk-verbose.log"
	LOGSCOOLPATH = "/var/log/bonk/bonk-cool.log"
	IPADDRESSES  = "/etc/bonk/ips"
)

func init() {
	IPAddresses = make(map[string]int)
	// set up logging
	logFile, err := os.OpenFile(LOGSPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	CoolLogger = log.New(logFile, "", log.Ltime|log.Lshortfile)

	// only log when in bonk mode
	if *mode == "bonk" {
		mw := io.MultiWriter(os.Stdout, logFile)
		CoolLogger.SetOutput(mw)
	} else {
		CoolLogger.SetOutput(logFile)
	}

	RawLogger = log.New(logFile, "", log.Lshortfile)

	logRawFile, err := os.OpenFile(LOGSRAWPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	RawLogger.SetOutput(logRawFile)

	// create /var/bonk & /etc/bonk
	path := "/var/bonk"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil && *verbose {
			fmt.Printf("error> %s\n", err)
		}
		fmt.Print("[!] Made /var/bonk\n")
	}
	path = "/etc/bonk"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil && *verbose {
			fmt.Printf("error> %s\n", err)
		}
		fmt.Print("[!] Made /etc/bonk\n")
	}

}

func main() {
	// ensure we are root
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	if user.Username != "root" {
		log.Fatal("not root!")
	}

	// parse flags
	fs.Parse(os.Args[1:])
	fmt.Printf("FLAGS:\n%+v\n", fs.Args())
	// color magic
	if !*colorEnabled {
		color.NoColor = true
	}

	// load configuration file
	if *configPath == "" {
		fmt.Printf("[!] Loading %s ... \n", CONFIGPATH)
		cf.Load(CONFIGPATH)
	} else {
		fmt.Printf("[!] Loading %s... \n", *configPath)
		dumpConfig()
		cf.Load(*configPath)
	}
	fmt.Printf("CONFIG:\n%+v\n\n", cf)
	if err := read(); err != nil {
		log.Fatalf("error: %v", err)
	}

}

// read() is taken from the example from libaudit. It sets up the kernel for us
func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	// Write netlink response to a file for further analysis or for writing
	// tests cases.
	var diagWriter io.Writer
	if *diag != "" {
		f, err := os.OpenFile(*diag, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		diagWriter = f
	}

	log.Println("starting netlink client")

	var err error
	var client *libaudit.AuditClient
	if *receiveOnly {
		client, err = libaudit.NewMulticastAuditClient(diagWriter)
		if err != nil {
			return fmt.Errorf("failed to create receive-only audit client: %w", err)
		}
		defer client.Close()
	} else {
		client, err = libaudit.NewAuditClient(diagWriter)
		if err != nil {
			return fmt.Errorf("failed to create audit client: %w", err)
		}
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get audit status: %w", err)
		}
		log.Printf("received audit status=%+v", status)

		if status.Enabled == 0 {
			log.Println("enabling auditing in the kernel")
			if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
				return fmt.Errorf("failed to set enabled=true: %w", err)
			}
		}

		if status.RateLimit != uint32(*rate) {
			log.Printf("setting rate limit in kernel to %v", *rate)
			if err = client.SetRateLimit(uint32(*rate), libaudit.NoWait); err != nil {
				return fmt.Errorf("failed to set rate limit to unlimited: %w", err)
			}
		}

		if status.BacklogLimit != uint32(*backlog) {
			log.Printf("setting backlog limit in kernel to %v", *backlog)
			if err = client.SetBacklogLimit(uint32(*backlog), libaudit.NoWait); err != nil {
				return fmt.Errorf("failed to set backlog limit: %w", err)
			}
		}

		// do **not** want to enable immutable kernel **yet**
		// if status.Enabled != 2 {
		// 	log.Printf("setting kernel settings as immutable")
		// 	if err = client.SetImmutable(libaudit.NoWait); err != nil {
		// 		return fmt.Errorf("failed to set kernel as immutable: %w", err)
		// 	}
		// }

		log.Printf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
		if err = client.SetPID(libaudit.NoWait); err != nil {
			return fmt.Errorf("failed to set audit PID: %w", err)
		}

	}

	if *mode == "load" {
		return load(client)
	} else if *mode == "bonk" || *mode == "honk" {
		return receive(client)
	} else {
		flag.PrintDefaults()
		return fmt.Errorf("please specify which mode to use")
	}

}

// command to load our rules
func load(r *libaudit.AuditClient) error {

	data, err := res.Open("embed/good.rules")
	if err != nil {
		return err
	}
	defer data.Close()

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		if rule2add := scanner.Text(); !strings.HasPrefix(rule2add, "#") && rule2add != "" {
			if *verbose {
				fmt.Printf("rule> %s\n", rule2add)
			}
			err := ruleAddWrapper(rule2add, r)
			// r.WaitForPendingACKs()
			if err != nil && *verbose {
				fmt.Printf("error> %s\n", err)
			}

		}

	}

	for _, rule := range cf.Rules {
		if strings.HasPrefix(rule, "#") && rule != "" {
			err := ruleAddWrapper(rule, r)
			// r.WaitForPendingACKs()
			if err != nil && *verbose {

				fmt.Printf("error> %s\n", err)

			}
		}
	}

	return nil
}

// mode=bonk,honk : takes the libaudit client and monitors for naughty processes
func receive(r *libaudit.AuditClient) error {

	var a AuditMessageBonk
	prevMessage := ""

	// var outMessagePrev string
	for {

		rawEvent, err := r.Receive(false)
		if err != nil {
			fmt.Println(fmt.Errorf("receive failed: %w", err))
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		// always save the raw audit log (for future investigation, of course
		RawLogger.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))

		// THIS IS THE BONK LOGIC
		if a.IsNewAuditID(string(rawEvent.Data)) {
			// so this is a new audit message
			// bonk the cumulative message
			if *mode == "bonk" || *mode == "honk" {
				prevMessage, _ = bonkProc(a, prevMessage)
			}
			// then make new audit message
			a = AuditMessageBonk{}
			err := a.InitAuditMessage(string(rawEvent.Data))
			if err != nil && *verbose {
				fmt.Print(err)
			}
		} else {
			// otherwise just append to audit class
			err := a.InitAuditMessage(string(rawEvent.Data))
			if err != nil && *verbose {
				fmt.Print(err)
			}
		}

	}
}
