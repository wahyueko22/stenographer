
%{
// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package query

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

%}

%union {
    num int
    ip net.IP
    str string
    query Query
    dur time.Duration
    time time.Time
    mac net.HardwareAddr
}

%type   <query> top expr expr2
%type   <time> timestamp
%type   <mac> macaddr

%token <str> HOST PORT PROTO AND OR NET MASK TCP UDP ICMP BEFORE AFTER IPP AGO VLAN MPLS MAC
%token <ip> IP
%token <num> NUM
%token <dur> DURATION
%token <time> TIME
%token <mac> MACADDR

%%

top:
   expr
{
    parserlex.(*parserLex).out = $1
}

expr:
    expr2
|   expr AND expr2
{
    $$ = intersectQuery{$1, $3}
}
|   expr OR expr2
{
    $$ = unionQuery{$1, $3}
}

expr2:
    HOST IP
{
    $$ = ipQuery{$2, $2}
}
|   MAC macaddr
{
    $$ = macQuery($2)
}
|   MAC macaddr MASK macaddr
{
    from, to, err := macsFromMask($2, $4)
    if err != nil {
        parserlex.Error(err.Error())
    }
    $$ = macRangeQuery{from: macQuery(from), to: macQuery(to)}
}
|   PORT NUM
{
	if $2 < 0 || $2 >= 65536 {
		parserlex.Error(fmt.Sprintf("invalid port %v", $2))
	}
	$$ = portQuery($2)
}
|   VLAN NUM
{
	if $2 < 0 || $2 >= 65536 {
		parserlex.Error(fmt.Sprintf("invalid vlan %v", $2))
	}
	$$ = vlanQuery($2)
}
|   MPLS NUM
{
	if $2 < 0 || $2 >= (1 << 20) {
		parserlex.Error(fmt.Sprintf("invalid mpls %v", $2))
	}
	$$ = mplsQuery($2)
}
|   IPP PROTO NUM
{
	if $3 < 0 || $3 >= 256 {
		parserlex.Error(fmt.Sprintf("invalid proto %v", $3))
	}
	$$ = protocolQuery($3)
}
|   NET IP '/' NUM
{
		mask := net.CIDRMask($4, len($2) * 8)
		if mask == nil {
			parserlex.Error(fmt.Sprintf("bad cidr: %v/%v", $2, $4))
		}
		from, to, err := ipsFromNet($2, mask)
		if err != nil {
			parserlex.Error(err.Error())
		}
		$$ = ipQuery{from, to}
}
|   NET IP MASK IP
{
		from, to, err := ipsFromNet($2, net.IPMask($4))
		if err != nil {
			parserlex.Error(err.Error())
		}
		$$ = ipQuery{from, to}
}
|   '(' expr ')'
{
	$$ = $2
}
|   TCP
{
	$$ = protocolQuery(6)
}
|   UDP
{
	$$ = protocolQuery(17)
}
|   ICMP
{
	$$ = protocolQuery(1)
}
|   BEFORE timestamp
{
	var t timeQuery
	t[1] = $2
	$$ = t
}
|   AFTER timestamp
{
	var t timeQuery
	t[0] = $2
	$$ = t
}


timestamp:
    TIME
{
	$$ = $1
}
|   DURATION AGO
{
	$$ = parserlex.(*parserLex).now.Add(-$1)
}

macaddr:
    MACADDR
{
    $$ = $1
}

%%

// macQuery represents a query for a specific MAC address.
type macQuery net.HardwareAddr

func (q macQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
    defer log(q, index, &bp, &err)()
    return index.MACPositions(ctx, net.HardwareAddr(q))
}

func (q macQuery) String() string { return fmt.Sprintf("mac %s", net.HardwareAddr(q).String()) }

func (q macQuery) base() bool { return true }

// macRangeQuery represents a query for a range of MAC addresses
type macRangeQuery struct {
    from, to macQuery
}

func (q macRangeQuery) LookupIn(ctx context.Context, index *indexfile.IndexFile) (bp base.Positions, err error) {
    defer log(q, index, &bp, &err)()
    
    fromPos, err := q.from.LookupIn(ctx, index)
    if err != nil {
        return nil, err
    }
    
    toPos, err := q.to.LookupIn(ctx, index)
    if err != nil {
        return nil, err
    }
    
    return fromPos.Union(toPos), nil
}

func (q macRangeQuery) String() string {
    return fmt.Sprintf("mac %s mask %s", net.HardwareAddr(q.from).String(), net.HardwareAddr(q.to).String())
}

func (q macRangeQuery) base() bool { return true }

// macsFromMask calculates the range of MAC addresses given a MAC and its mask
func macsFromMask(mac, mask net.HardwareAddr) (from, to net.HardwareAddr, _ error) {
    if len(mac) != 6 || len(mask) != 6 {
        return nil, nil, fmt.Errorf("invalid MAC address or mask length")
    }
    
    from = make(net.HardwareAddr, 6)
    to = make(net.HardwareAddr, 6)
    
    for i := 0; i < 6; i++ {
        from[i] = mac[i] & mask[i]
        to[i] = mac[i] | ^mask[i]
    }
    
    return from, to, nil
}


func ipsFromNet(ip net.IP, mask net.IPMask) (from, to net.IP, _ error) {
	if len(ip) != len(mask) || (len(ip) != 4 && len(ip) != 16) {
		return nil, nil, fmt.Errorf("bad IP or mask: %v %v", ip, mask)
	}
	from = make(net.IP, len(ip))
	to = make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		from[i] = ip[i] & mask[i]
		to[i] = ip[i] | ^mask[i]
	}
	return
}


// Enhanced parserLex struct with MAC address support
type parserLex struct {
    now time.Time
    in string
    pos int
    out Query
    err error
}

// Enhanced tokens map with MAC keyword
var tokens = map[string]int{
    "after": AFTER,
    "ago": AGO,
    "&&": AND,
    "and": AND,
    "before": BEFORE,
    "host": HOST,
    "icmp": ICMP,
    "ip": IPP,
    "mask": MASK,
    "mac": MAC,
    "net": NET,
    "||": OR,
    "or": OR,
    "port": PORT,
    "vlan": VLAN,
    "mpls": MPLS,
    "proto": PROTO,
    "tcp": TCP,
    "udp": UDP,
}

// parseMACAddress parses a MAC address string into net.HardwareAddr
func parseMACAddress(s string) (net.HardwareAddr, error) {
    // Replace hyphens with colons for consistent parsing
    s = strings.ReplaceAll(s, "-", ":")
    
    // Parse using net.ParseMAC which handles various formats
    mac, err := net.ParseMAC(s)
    if err != nil {
        return nil, fmt.Errorf("invalid MAC address format: %v", err)
    }
    
    // Ensure we have a 6-byte MAC address
    if len(mac) != 6 {
        return nil, fmt.Errorf("invalid MAC address length: got %d bytes, want 6", len(mac))
    }
    
    return mac, nil
}

// Enhanced Lex method with MAC address support
func (x *parserLex) Lex(yylval *parserSymType) (ret int) {
    for x.pos < len(x.in) && unicode.IsSpace(rune(x.in[x.pos])) {
        x.pos++
    }
    for t, i := range tokens {
        if strings.HasPrefix(x.in[x.pos:], t) {
            x.pos += len(t)
            return i
        }
    }
    
    s := x.pos
    var isIP, isDuration, isTime, isMAC bool
L:
    for x.pos < len(x.in) {
        switch c := x.in[x.pos]; c {
        case ':':
            if x.pos-s == 2 {
                isMAC = true
            }
            isIP = !isMAC
            x.pos++
        case '-':
            if x.pos-s == 2 {
                isMAC = true
            }
            x.pos++
        case '.':
            isIP = true
            x.pos++
        case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F':
            x.pos++
        case 'm', 'h':
            x.pos++
            isDuration = true
            break L
        case 'T', '+', 'Z':
            x.pos++
            isTime = true
        default:
            break L
        }
    }
    
    part := x.in[s:x.pos]
    switch {
    case isMAC:
        mac, err := parseMACAddress(part)
        if err != nil {
            x.Error(fmt.Sprintf("bad MAC address %q: %v", part, err))
            return -1
        }
        yylval.mac = mac
        return MACADDR
    case isTime:
		t, err := time.Parse(time.RFC3339, part)
		if err != nil {
			x.Error(fmt.Sprintf("bad time %q", part))
		}
		yylval.time = t
		return TIME
	case isIP:
		yylval.ip = net.ParseIP(part)
		if yylval.ip == nil {
			x.Error(fmt.Sprintf("bad IP %q", part))
			return -1
		}
		if ip4 := yylval.ip.To4(); ip4 != nil {
			yylval.ip = ip4
		}
		return IP
	case isDuration:
		duration, err := time.ParseDuration(part)
		if err != nil {
			x.Error(fmt.Sprintf("bad duration %q", part))
		}
		yylval.dur = duration
		return DURATION
	case x.pos != s:
		n, err := strconv.Atoi(part)
		if err != nil { return -1 }
		yylval.num = n
		return NUM
	case x.pos >= len(x.in):
		return 0
	}
	switch c := x.in[x.pos]; c {
	case ':', '.', '(', ')', '/':
		x.pos++
		return int(c)
	}
	return -1
}

// Error is called by the parser on a parse error.
func (x *parserLex) Error(s string) {
	if x.err == nil {
		x.err = fmt.Errorf("%v at character %v (%q HERE %q)", s, x.pos, x.in[:x.pos], x.in[x.pos:])
	}
}

// parse parses an input string into a Query.
func parse(in string) (Query, error) {
	lex := &parserLex{in: in, now: time.Now()}
	parserParse(lex)
	if lex.err != nil {
		return nil, lex.err
	}
	return lex.out, nil
}
