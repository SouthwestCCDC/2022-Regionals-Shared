package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

var (
	// auditIDRule = regexp.MustCompile("(:)(.*?)())")
	msgRule = regexp.MustCompile(`audit\((.*?)\)`)
	// syscall     = regexp.MustCompile("syscall=[0-9]{0,3}")

	terminalRule  = regexp.MustCompile(`terminal=([\w\\/]+)`)
	ttyRule       = regexp.MustCompile(`tty=([\w\\/]+)`)
	exeRule       = regexp.MustCompile(`exe="(.*?)"`)
	keyRule       = regexp.MustCompile(`key="(.*?)"`)
	pidRule       = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule      = regexp.MustCompile(`ppid=([\d]+)`)
	nameRule      = regexp.MustCompile(`name=\"(.*?)\"`)
	auidRule      = regexp.MustCompile(`auid=([\d].?)+`)
	uidRule       = regexp.MustCompile(`uid=([\d].?)+`)
	auidRuleAlpha = regexp.MustCompile(`AUID="(.*?)"`)
	proctileRule  = regexp.MustCompile(`proctitle=(([\w].?)+)`)
	// Rules        = make(map[*regexp.Regexp]string)
)

// func init() {
// 	Rules[terminalRule] = "terminal="
// 	Rules[ttyRule] = "tty="
// 	Rules[exeRule] = "exe="
// 	Rules[keyRule] = "key="
// 	Rules[pidRule] = "pid="
// 	Rules[ppidRule] = "ppid="
// 	Rules[nameRule] = "name="
// 	Rules[auidRule] = "auid="
// 	Rules[proctileRule] = "proctitle="
// }

type AuditMessageBonk struct {
	// msg=audit(1364481363.243:24287):
	AuditIDRaw string `json:"-"`
	AuditID    string `json:"auditID"`
	Timestamp  string `json:"timestamp"`

	// syscall=2 (not used)
	Syscall int `json:"Syscall"`
	// success=no
	Success bool `json:"success"`

	// terminal=/dev/pts/0 (not found often ???)
	Terminal string `json:"terminal"`
	// tty=pts0
	Tty string `json:"tty"`
	// exe="/bin/cat"
	Exe string `json:"exe"`
	// key="sshd_config"
	Key string `json:"key"`

	// should be self explanatory
	Pid               int    `json:"pid"`
	PPid              int    `json:"ppid"`
	Auid              string `json:"auid"`
	Uid               string `json:"uid"`
	AuidHumanReadable string `json:"auid-hr"` //human readable

	// name="/home/kevin"
	Name string `json:"name"`

	// proctile=636174002F6574632F7373682F737368645F636F6E666967
	Proctile              string `json:"proctitle"`
	ProctileHumanreadable string `json:"-"`

	// Finished is the flag to say that it is done processing
	// Extras
	Finished bool `json:"-"`
}

func (a *AuditMessageBonk) InitAuditMessage(line string) error {
	a.AuditIDRaw = ParseAuditRuleRegex(msgRule, line, "")

	if a.AuditIDRaw != "" && len(a.AuditIDRaw) > 20 {
		a.Timestamp = a.AuditIDRaw[6:20]
		a.AuditID = a.AuditIDRaw[21:]
		a.AuditID = strings.Trim(a.AuditID, ")")
	} else {
		return nil
	}
	// fmt.Printf("%s\t%s\n", a.Timestamp, a.AuditID)

	// gross code. Take the regex from above along with the line and the key to remove
	if out := ParseAuditRuleRegex(terminalRule, line, "terminal="); out != "" {
		a.Tty = out
	}

	if out := ParseAuditRuleRegex(ttyRule, line, "tty="); out != "" {
		a.Tty = out
	}
	if out := ParseAuditRuleRegex(exeRule, line, "exe="); out != "" {
		a.Exe = out
	}
	if out := ParseAuditRuleRegex(keyRule, line, "key="); out != "" {
		a.Key = out
	}
	if out := ParseAuditRuleRegex(pidRule, line, "pid="); out != "" {
		pid2int, err := strconv.Atoi(out)
		if err != nil {
			return fmt.Errorf("error>\n%s", err)
		}
		a.Pid = pid2int
	}
	if out := ParseAuditRuleRegex(ppidRule, line, "ppid="); out != "" {
		pid2int, err := strconv.Atoi(out)
		if err != nil {
			return fmt.Errorf("error>\n%v", err)
		}

		a.PPid = pid2int
	}
	// a.Name = ParseAuditRuleRegex(nameRule, line, "name=")
	// a.Proctile = ParseAuditRuleRegex(proctileRule, line, "proctitle=")
	// a.ProctileHumanreadable = string(a.Proctile)

	if out := ParseAuditRuleRegex(nameRule, line, "name="); out != "" {
		a.Name = out
	}

	if out := ParseAuditRuleRegex(proctileRule, line, "proctitle="); out != "" {
		a.Proctile = out
		// a := "2F7573722F73686172652F636F64652F636F6465202D2D756E6974792D6C61756E6368"
		bs, err := hex.DecodeString(out)
		if err != nil {
			return fmt.Errorf("error>\n%v", err)
		}
		// out, err := strconv.Unquote("\"" + string(bs) + "\"")
		// if err != nil {
		// 	return fmt.Errorf("error>\n%v", err)
		// }
		a.Proctile = string(bs)

	}

	if out := ParseAuditRuleRegex(auidRule, line, "auid="); out != "" {
		// a.Auid = ParseAuditRuleRegex(auidRule, line, "auid=")

		// invalid username
		if out != "4294967295" && out != "0" {
			a.Auid = out
			user, err := user.LookupId(out)
			if err != nil {
				return fmt.Errorf("error>\n%s", err)
			}
			a.AuidHumanReadable = user.Username
		} else {
			a.Auid = ""
			a.AuidHumanReadable = ""
		}
	}

	if out := ParseAuditRuleRegex(uidRule, line, "uid="); out != "" {
		// a.Auid = ParseAuditRuleRegex(auidRule, line, "auid=")
		a.Uid = out

	}

	if out := ParseAuditRuleRegex(auidRuleAlpha, line, "AUID="); out != "" {
		fmt.Println(out)
		// TODO not found currently ??
		a.AuidHumanReadable = out
	}

	return nil

}

func ParseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
	// apply regex magic. Maybe could be better
	value := rules.Find([]byte(msg))

	/*
		The code below is necessary due to regex shenanigans. In order to use regex with lookaheads it violates golang's regex library promise to be o(n)
		Subsequently we must comply and write the following code to remove the characters upto the equal
		I could use regex+match second group but this works just fine!
		https://groups.google.com/g/golang-nuts/c/7qgSDWPIh_E
	*/

	// if it zero nothing found
	if len(value) == 0 {
		return ""
	}
	sizeOfRemove := len(remove)

	if sizeOfRemove > len(value) {
		log.Fatalf("REMOVE=%s is too long for msg=%s\n", remove, msg)
	}
	// trim first n characters just to have what is longer than the value
	output := string(value[sizeOfRemove:])

	// remove quotes
	if output[0] == '"' {
		outputWithoutQuotes := strings.Trim(output, "\"")
		return outputWithoutQuotes
	}

	return output

}

func (a AuditMessageBonk) IsNewAuditID(line string) bool {
	var AuditID string
	AuditIDRaw := ParseAuditRuleRegex(msgRule, line, "")
	if a.AuditIDRaw == "" {
		return true
	}

	if AuditIDRaw != "" && len(AuditIDRaw) > 20 {
		// Timestamp := a.AuditIDRaw[6:20]
		AuditID = AuditIDRaw[21:]
		AuditID = strings.Trim(AuditID, ")")
		if AuditID == a.AuditID {
			return false
		} else {
			return true
		}
	}
	return false

}
