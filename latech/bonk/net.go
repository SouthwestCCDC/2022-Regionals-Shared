package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	// "strings"
)

const (
	TCP_ESTABLISHED = iota + 1
	TCP_SYN_SENT    = iota + 1
	TCP_SYN_RECV    = iota + 1
	TCP_FIN_WAIT1   = iota + 1
	TCP_FIN_WAIT2   = iota + 1
	TCP_TIME_WAIT   = iota + 1
	TCP_CLOSE       = iota + 1
	TCP_CLOSE_WAIT  = iota + 1
	TCP_LAST_ACK    = iota + 1
	TCP_LISTEN      = iota + 1
	TCP_CLOSING     = iota + 1 /* Now a valid state */

	TCP_MAX_STATES = iota + 1 /* Leave at the end! */
)

// inspiration from https://blog.arkey.fr/2020/10/23/read-network-addresses-in-procfs/

func reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func parseHexIP(raw string) string {

	var octets []string
	var sb strings.Builder
	for _, d := range raw {
		if len(sb.String()) == 1 {
			sb.WriteString(string(d))
			octets = append(octets, sb.String())
			sb.Reset()
		} else {
			sb.WriteRune(d)
		}
	}

	revOctets := reverse(octets)

	var ipAddr strings.Builder
	for _, oct := range revOctets {
		o, _ := hex.DecodeString(oct)
		// fmt.Printf("%d\n", o)
		a := fmt.Sprintf("%d", o[len(o)-1])
		ipAddr.WriteString(a)
		ipAddr.WriteString(".")
	}
	// val := ipAddr.String()
	// fmt.Println(val)
	// fmt.Println(ipAddr)
	val := ipAddr.String()
	actual := val[:len(val)-1]
	return actual
}

func getIPfromPID(pid int) (map[string]int, error) {
	// open this file
	pid2str := strconv.Itoa(pid)
	file2open := fmt.Sprintf("/proc/%s/net/tcp", pid2str)

	file, err := os.Open(file2open)
	if err != nil {
		return nil, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	counter := 0
	// read through it
	ipAddresses := make(map[string]int)
	for scanner.Scan() {
		text := scanner.Text()
		// ignore header
		if counter != 0 {
			// some error handling. If the line is wacky make sure to break and not touch the following lines
			if len(text) < 38 {
				break
			}
			// this should catch reading from slice willy nilly
			defer func() {
				if err := recover(); err != nil {
					log.Println("panic occurred:", err)
				}
			}()
			// get remote address
			REMADDR := text[20:28]
			TCPStateStr := text[35:36]
			lower := strings.ToLower(TCPStateStr)
			TCPStateInt, _ := strconv.ParseInt(lower, 16, 64)

			data := parseHexIP(REMADDR)
			_ = data

			// only care about established TCP connections
			if TCPStateInt == TCP_ESTABLISHED {
				if _, exist := ipAddresses[data]; exist {
					ipAddresses[data] += 1
				} else {
					ipAddresses[data] = 0
				}
			}

		}

		counter++
	}

	return ipAddresses, nil

}
