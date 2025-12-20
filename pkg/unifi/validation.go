package unifi

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func isValidIP(s string) bool {
	if s == "" {
		return false
	}
	return net.ParseIP(s) != nil
}

func isValidCIDR(s string) bool {
	if s == "" {
		return false
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func isValidPort(p int) bool {
	return p >= 1 && p <= 65535
}

func isValidPortRange(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return false
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		return isValidPort(start) && isValidPort(end) && start <= end
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return isValidPort(port)
}

func isValidMAC(s string) bool {
	if s == "" {
		return false
	}
	return macRegex.MatchString(s)
}

func isOneOf(value string, allowed ...string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

var timeHHMMRegex = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]$`)

func isValidTimeHHMM(s string) bool {
	if s == "" {
		return false
	}
	return timeHHMMRegex.MatchString(s)
}
