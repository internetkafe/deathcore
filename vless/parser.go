package vless

import (
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "net/url"
    "strings"
)

// ==================== Common config types ====================

type OutboundConfig struct {
    Tag           string         `json:"tag"`
    Protocol      string         `json:"protocol"`
    Mux           MuxConfig      `json:"mux"`
    Settings      interface{}    `json:"settings"`
    StreamSetting *StreamSetting `json:"streamSettings,omitempty"`
}

type MuxConfig struct {
    Enabled     bool `json:"enabled"`
    Concurrency int  `json:"concurrency"`
}

type StreamSetting struct {
    Network         string         `json:"network"`
    Security        string         `json:"security"`
    TlsSettings     *TlsConfig     `json:"tlsSettings,omitempty"`
    RealitySettings *RealityConfig `json:"realitySettings,omitempty"`
    WsSettings      *WsConfig      `json:"wsSettings,omitempty"`
    XhttpSettings   *XhttpConfig   `json:"xhttpSettings,omitempty"`
    GRPCConfig      *GRPCConfig    `json:"grpcSettings,omitempty"`
    SocketOpt       SocketOpt      `json:"sockopt"`
}

type TlsConfig struct {
    ServerName    string   `json:"serverName"`
    AllowInsecure bool     `json:"allowInsecure"`
    Alpn          []string `json:"alpn,omitempty"`
    Fingerprint   string   `json:"fingerprint,omitempty"`
    Encryption    string   `json:"encryption,omitempty"`
}

type RealityConfig struct {
    ServerName  string `json:"serverName"`
    PublicKey   string `json:"publicKey"`
    ShortId     string `json:"shortId"`
    Fingerprint string `json:"fingerprint"`
    SpiderX     string `json:"spiderX,omitempty"`
    Encryption  string `json:"encryption,omitempty"`
}

type WsConfig struct {
    Path string `json:"path"`
    Host string `json:"host,omitempty"`
}

type XhttpConfig struct {
    Mode  string     `json:"mode,omitempty"`
    Path  string     `json:"path,omitempty"`
    Host  string     `json:"host,omitempty"`
    Extra *ExtraOpts `json:"extra,omitempty"`
}

type ExtraOpts struct {
    XpaddingBytes string `json:"xPaddingBytes,omitempty"`
}

type GRPCConfig struct {
    ServiceName string `json:"serviceName,omitempty"`
    Authority   string `json:"authority,omitempty"`
    Mode        string `json:"mode,omitempty"`
}

type SocketOpt struct {
    DomainStrategy string         `json:"domainStrategy"`
    HappyEyeballs  *HappyEyeballs `json:"happyEyeballs,omitempty"`
}

type HappyEyeballs struct {
    Interleave       int  `json:"interleave"`
    MaxConcurrentTry int  `json:"maxConcurrentTry"`
    PrioritizeIPv6   bool `json:"prioritizeIPv6"`
    TryDelayMs       int  `json:"tryDelayMs"`
}

// ===== Settings: VLESS / VMess =====

type VnextSettings struct {
    Vnext []Vnext `json:"vnext"`
}

type Vnext struct {
    Address string `json:"address"`
    Port    int    `json:"port"`
    Users   []User `json:"users"`
}

type User struct {
    Id         string `json:"id"`
    Encryption string `json:"encryption"`
    Level      int    `json:"level"`
}

type VMessSettings struct {
    Vnext []VMessVnext `json:"vnext"`
}

type VMessVnext struct {
    Address string      `json:"address"`
    Port    int         `json:"port"`
    Users   []VMessUser `json:"users"`
}

type VMessUser struct {
    Id       string `json:"id"`
    AlterId  int    `json:"alterId"`
    Security string `json:"security"`
}

// ===== Settings: SS / Trojan / Hy2 / Tuic =====

type ServerSettings struct {
    Servers []ServerEntry `json:"servers"`
}

type ServerEntry struct {
    Address               string   `json:"address"`
    Port                  int      `json:"port"`
    Method                string   `json:"method,omitempty"`
    Password              string   `json:"password"`
    Sni                   string   `json:"sni,omitempty"`
    AllowInsecure         bool     `json:"allowInsecure,omitempty"`
    Obfs                  string   `json:"obfs,omitempty"`
    ObfsPassword          string   `json:"obfsPassword,omitempty"`
    Uuid                  string   `json:"uuid,omitempty"`
    CongestionControlType string   `json:"congestionControlType,omitempty"`
    UdpRelayMode          string   `json:"udpRelayMode,omitempty"`
    Alpn                  []string `json:"alpn,omitempty"`
}

// ==================== Helpers ====================

func getParam(params url.Values, key, fallback string) string {
    if val, ok := params[key]; ok && len(val) > 0 && val[0] != "" {
        return val[0]
    }
    return fallback
}

func getBoolParam(params url.Values, key string, fallback bool) bool {
    val := getParam(params, key, "")
    if val == "1" || strings.ToLower(val) == "true" {
        return true
    }
    if val == "0" || strings.ToLower(val) == "false" {
        return false
    }
    return fallback
}

func getAlpnParam(params url.Values, key string) []string {
    val := getParam(params, key, "")
    if val == "" {
        return nil
    }
    return strings.Split(val, ",")
}

func decodeBase64(s string) ([]byte, error) {
    s = strings.ReplaceAll(s, "\n", "")
    s = strings.ReplaceAll(s, "\r", "")
    s = strings.ReplaceAll(s, " ", "")
    s = strings.TrimSpace(s)

    if len(s)%4 != 0 {
        s += strings.Repeat("=", 4-len(s)%4)
    }

    if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
        return decoded, nil
    }
    if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
        return decoded, nil
    }
    if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
        return decoded, nil
    }
    return nil, fmt.Errorf("base64 decode failed")
}

func defaultSocketOpt() SocketOpt {
    return SocketOpt{
        DomainStrategy: "UseIP",
        HappyEyeballs: &HappyEyeballs{
            Interleave:       2,
            MaxConcurrentTry: 4,
            PrioritizeIPv6:   false,
            TryDelayMs:       250,
        },
    }
}

func defaultMux() MuxConfig {
    return MuxConfig{Enabled: false, Concurrency: -1}
}

// ==================== Dispatcher ====================

func Parse(rawURL string) (*OutboundConfig, error) {
    switch {
    case strings.HasPrefix(rawURL, "vless://"):
        return ParseVLESS(rawURL)
    case strings.HasPrefix(rawURL, "vmess://"):
        return ParseVMess(rawURL)
    case strings.HasPrefix(rawURL, "ss://"):
        return ParseShadowsocks(rawURL)
    case strings.HasPrefix(rawURL, "trojan://"):
        return ParseTrojan(rawURL)
    case strings.HasPrefix(rawURL, "hysteria2://"), strings.HasPrefix(rawURL, "hy2://"):
        return ParseHy2(rawURL)
    case strings.HasPrefix(rawURL, "tuic://"):
        return ParseTuic(rawURL)
    }
    return nil, fmt.Errorf("unknown protocol scheme")
}

// ==================== VLESS ====================

func ParseVLESS(rawURL string) (*OutboundConfig, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, fmt.Errorf("invalid URL: %w", err)
    }
    if u.Scheme != "vless" {
        return nil, errors.New("only vless:// supported")
    }
    uuid := u.User.Username()
    if uuid == "" {
        return nil, errors.New("UUID missing")
    }
    host := u.Hostname()
    port := 443
    if p := u.Port(); p != "" {
        fmt.Sscanf(p, "%d", &port)
    }
    q := u.Query()

    transport := q.Get("type")
    if transport == "" {
        transport = "tcp"
    }
    security := q.Get("security")
    enc := q.Get("encryption")
    if enc == "" {
        enc = "none"
    }

    stream := &StreamSetting{
        Network:   transport,
        Security:  security,
        SocketOpt: defaultSocketOpt(),
    }

    switch transport {
    case "ws":
        ws := &WsConfig{Path: getParam(q, "path", "/")}
        if host := getParam(q, "host", ""); host != "" {
            ws.Host = host
        }
        stream.WsSettings = ws
    case "grpc":
        grpc := &GRPCConfig{}
        if sn := getParam(q, "serviceName", ""); sn != "" {
            grpc.ServiceName = sn
        }
        if auth := getParam(q, "authority", ""); auth != "" {
            grpc.Authority = auth
        }
        if mode := getParam(q, "mode", ""); mode != "" {
            grpc.Mode = mode
        }
        stream.GRPCConfig = grpc
    case "xhttp", "splithttp":
        xhttp := &XhttpConfig{Path: getParam(q, "path", "/")}
        if host := getParam(q, "host", ""); host != "" {
            xhttp.Host = host
        }
        if mode := getParam(q, "mode", ""); mode != "" {
            xhttp.Mode = mode
        }
        if extraStr := getParam(q, "extra", ""); extraStr != "" {
            unesc, err := url.QueryUnescape(extraStr)
            if err == nil {
                var m map[string]string
                if json.Unmarshal([]byte(unesc), &m) == nil {
                    if pad, ok := m["xPaddingBytes"]; ok {
                        xhttp.Extra = &ExtraOpts{XpaddingBytes: pad}
                    }
                }
            }
        }
        stream.XhttpSettings = xhttp
    }

    if security == "reality" {
        pbk := getParam(q, "pbk", "")
        if pbk != "" {
            stream.RealitySettings = &RealityConfig{
                ServerName:  getParam(q, "sni", ""),
                PublicKey:   pbk,
                ShortId:     getParam(q, "sid", ""),
                Fingerprint: getParam(q, "fp", "chrome"),
                SpiderX:     getParam(q, "spx", ""),
            }
        }
    } else if security == "tls" {
        tls := &TlsConfig{
            ServerName:    getParam(q, "sni", ""),
            AllowInsecure: getBoolParam(q, "allowInsecure", false),
        }
        if alpn := getAlpnParam(q, "alpn"); alpn != nil {
            tls.Alpn = alpn
        }
        if fp := getParam(q, "fp", ""); fp != "" {
            tls.Fingerprint = fp
        }
        stream.TlsSettings = tls
    }

    return &OutboundConfig{
        Tag:           "proxy",
        Protocol:      "vless",
        Mux:           defaultMux(),
        StreamSetting: stream,
        Settings: VnextSettings{
            Vnext: []Vnext{{
                Address: host,
                Port:    port,
                Users: []User{{
                    Id:         uuid,
                    Encryption: enc,
                    Level:      8,
                }},
            }},
        },
    }, nil
}

// ==================== VMess ====================

type vmessLink struct {
    V    string `json:"v"`
    Ps   string `json:"ps"`
    Add  string `json:"add"`
    Port string `json:"port"`
    Id   string `json:"id"`
    Aid  string `json:"aid"`
    Scy  string `json:"scy"`
    Net  string `json:"net"`
    Type string `json:"type"`
    Host string `json:"host"`
    Path string `json:"path"`
    Tls  string `json:"tls"`
    Sni  string `json:"sni"`
    Alpn string `json:"alpn"`
    Fp   string `json:"fp"`
}

func ParseVMess(rawURL string) (*OutboundConfig, error) {
    if !strings.HasPrefix(rawURL, "vmess://") {
        return nil, fmt.Errorf("not vmess")
    }
    b64 := strings.TrimPrefix(rawURL, "vmess://")

    decoded, err := decodeBase64(b64)
    if err != nil {
        return nil, err
    }

    var v vmessLink
    if err := json.Unmarshal(decoded, &v); err != nil {
        return nil, err
    }

    var portInt int
    fmt.Sscanf(v.Port, "%d", &portInt)
    aid := 0
    fmt.Sscanf(v.Aid, "%d", &aid)

    stream := &StreamSetting{
        Network:   v.Net,
        Security:  v.Tls,
        SocketOpt: defaultSocketOpt(),
    }

    switch v.Net {
    case "ws":
        ws := &WsConfig{Path: v.Path}
        if v.Host != "" {
            ws.Host = v.Host
        }
        stream.WsSettings = ws
    case "grpc":
        grpc := &GRPCConfig{}
        if v.Path != "" {
            grpc.ServiceName = v.Path
        }
        if v.Host != "" {
            grpc.Authority = v.Host
        }
        stream.GRPCConfig = grpc
    case "xhttp", "splithttp":
        xhttp := &XhttpConfig{}
        if v.Path != "" {
            xhttp.Path = v.Path
        }
        if v.Host != "" {
            xhttp.Host = v.Host
        }
        stream.XhttpSettings = xhttp
    }

    if v.Tls == "tls" {
        tls := &TlsConfig{
            ServerName:    v.Sni,
            AllowInsecure: false,
        }
        if v.Alpn != "" {
            tls.Alpn = strings.Split(v.Alpn, ",")
        }
        if v.Fp != "" {
            tls.Fingerprint = v.Fp
        }
        stream.TlsSettings = tls
    }

    return &OutboundConfig{
        Tag:           "proxy",
        Protocol:      "vmess",
        Mux:           defaultMux(),
        StreamSetting: stream,
        Settings: VMessSettings{
            Vnext: []VMessVnext{{
                Address: v.Add,
                Port:    portInt,
                Users: []VMessUser{{
                    Id:       v.Id,
                    AlterId:  aid,
                    Security: v.Scy,
                }},
            }},
        },
    }, nil
}

// ==================== Shadowsocks ====================

func ParseShadowsocks(rawURL string) (*OutboundConfig, error) {
    if !strings.HasPrefix(rawURL, "ss://") {
        return nil, fmt.Errorf("not ss")
    }

    uriWithoutScheme := strings.TrimPrefix(rawURL, "ss://")
    parts := strings.SplitN(uriWithoutScheme, "#", 2)
    mainPart := parts[0]

    var method, password, host, portStr string
    var decoded []byte
    var err error

    if strings.Contains(mainPart, "@") {
        sip002Parts := strings.SplitN(mainPart, "@", 2)
        if len(sip002Parts) != 2 {
            return nil, fmt.Errorf("invalid ss sip002 format")
        }

        decoded, err = decodeBase64(sip002Parts[0])
        if err != nil {
            return nil, fmt.Errorf("invalid ss sip002 base64: %v", err)
        }
        credParts := strings.SplitN(string(decoded), ":", 2)
        if len(credParts) != 2 {
            return nil, fmt.Errorf("invalid ss sip002 credentials")
        }
        method = credParts[0]
        password = credParts[1]
        host, portStr, err = net.SplitHostPort(sip002Parts[1])
        if err != nil {
            return nil, fmt.Errorf("invalid ss sip002 host:port: %v", err)
        }
    } else {
        decoded, err = decodeBase64(mainPart)
        if err != nil {
            return nil, fmt.Errorf("invalid ss legacy base64: %v", err)
        }
        decodedStr := string(decoded)

        atIdx := strings.LastIndex(decodedStr, "@")
        if atIdx == -1 {
            return nil, fmt.Errorf("invalid ss legacy format: no @")
        }

        credPart := decodedStr[:atIdx]
        hostPortStr := decodedStr[atIdx+1:]

        credParts := strings.SplitN(credPart, ":", 2)
        if len(credParts) != 2 {
            return nil, fmt.Errorf("invalid ss legacy credentials")
        }
        method = credParts[0]
        password = credParts[1]

        host, portStr, err = net.SplitHostPort(hostPortStr)
        if err != nil {
            return nil, fmt.Errorf("invalid ss legacy host:port: %v", err)
        }
    }

    var portInt int
    _, err = fmt.Sscanf(portStr, "%d", &portInt)
    if err != nil || portInt == 0 {
        return nil, fmt.Errorf("invalid ss port: %s", portStr)
    }

    return &OutboundConfig{
        Tag:      "proxy",
        Protocol: "shadowsocks",
        Mux:      defaultMux(),
        Settings: ServerSettings{
            Servers: []ServerEntry{{
                Address:  host,
                Port:     portInt,
                Method:   method,
                Password: password,
            }},
        },
    }, nil
}

// ==================== Trojan ====================

func ParseTrojan(rawURL string) (*OutboundConfig, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, err
    }
    password := u.User.Username()
    address := u.Hostname()
    portStr := u.Port()
    params := u.Query()

    var portInt int
    fmt.Sscanf(portStr, "%d", &portInt)

    netType := getParam(params, "type", "tcp")
    secType := getParam(params, "security", "tls")
    encryption := getParam(params, "encryption", "")

    stream := &StreamSetting{
        Network:   netType,
        Security:  secType,
        SocketOpt: defaultSocketOpt(),
    }

    switch netType {
    case "ws":
        ws := &WsConfig{Path: getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            ws.Host = host
        }
        stream.WsSettings = ws
    case "grpc":
        grpc := &GRPCConfig{}
        if sn := getParam(params, "serviceName", ""); sn != "" {
            grpc.ServiceName = sn
        }
        if auth := getParam(params, "authority", ""); auth != "" {
            grpc.Authority = auth
        }
        if mode := getParam(params, "mode", ""); mode != "" {
            grpc.Mode = mode
        }
        stream.GRPCConfig = grpc
    case "xhttp", "splithttp":
        xhttp := &XhttpConfig{Path: getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            xhttp.Host = host
        }
        if mode := getParam(params, "mode", ""); mode != "" {
            xhttp.Mode = mode
        }
        stream.XhttpSettings = xhttp
    }

    switch secType {
    case "tls":
        tls := &TlsConfig{
            ServerName:    getParam(params, "sni", address),
            AllowInsecure: getBoolParam(params, "allowInsecure", false),
        }
        if getBoolParam(params, "insecure", false) {
            tls.AllowInsecure = true
        }
        if alpn := getAlpnParam(params, "alpn"); alpn != nil {
            tls.Alpn = alpn
        }
        if fp := getParam(params, "fp", ""); fp != "" {
            tls.Fingerprint = fp
        }
        if encryption != "" {
            tls.Encryption = encryption
        }
        stream.TlsSettings = tls
    case "reality":
        pbk := getParam(params, "pbk", "")
        if pbk == "" {
            return nil, fmt.Errorf("no pbk for reality")
        }
        reality := &RealityConfig{
            ServerName:  getParam(params, "sni", ""),
            Fingerprint: getParam(params, "fp", "chrome"),
            PublicKey:   pbk,
            ShortId:     getParam(params, "sid", ""),
            SpiderX:     "",
        }
        if encryption != "" {
            reality.Encryption = encryption
        }
        stream.RealitySettings = reality
    }

    return &OutboundConfig{
        Tag:           "proxy",
        Protocol:      "trojan",
        Mux:           defaultMux(),
        StreamSetting: stream,
        Settings: ServerSettings{
            Servers: []ServerEntry{{
                Address:  address,
                Port:     portInt,
                Password: password,
            }},
        },
    }, nil
}

// ==================== Hysteria2 ====================

func ParseHy2(rawURL string) (*OutboundConfig, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, err
    }
    password := u.User.String()
    if strings.Contains(password, ":") {
        password = strings.Split(password, ":")[0]
    }
    address := u.Hostname()
    portStr := u.Port()
    params := u.Query()

    var portInt int
    fmt.Sscanf(portStr, "%d", &portInt)

    entry := ServerEntry{
        Address:  address,
        Port:     portInt,
        Password: password,
    }
    if sni := getParam(params, "sni", ""); sni != "" {
        entry.Sni = sni
    }
    if getBoolParam(params, "insecure", false) {
        entry.AllowInsecure = true
    }
    if obfs := getParam(params, "obfs", ""); obfs != "" {
        entry.Obfs = obfs
        entry.ObfsPassword = getParam(params, "obfs-password", "")
    }

    return &OutboundConfig{
        Tag:      "proxy",
        Protocol: "hysteria2",
        Mux:      defaultMux(),
        Settings: ServerSettings{
            Servers: []ServerEntry{entry},
        },
    }, nil
}

// ==================== TUIC ====================

func ParseTuic(rawURL string) (*OutboundConfig, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, err
    }
    uuid := u.User.Username()
    password, _ := u.User.Password()
    address := u.Hostname()
    portStr := u.Port()
    params := u.Query()

    var portInt int
    fmt.Sscanf(portStr, "%d", &portInt)

    entry := ServerEntry{
        Address:  address,
        Port:     portInt,
        Uuid:     uuid,
        Password: password,
    }
    if sni := getParam(params, "sni", ""); sni != "" {
        entry.Sni = sni
    }
    if alpn := getAlpnParam(params, "alpn"); alpn != nil {
        entry.Alpn = alpn
    }
    if cc := getParam(params, "congestion_control", ""); cc != "" {
        entry.CongestionControlType = cc
    }
    if uc := getParam(params, "udp_relay_mode", ""); uc != "" {
        entry.UdpRelayMode = uc
    }
    if getBoolParam(params, "allow_insecure", false) {
        entry.AllowInsecure = true
    }

    return &OutboundConfig{
        Tag:      "proxy",
        Protocol: "tuic",
        Mux:      defaultMux(),
        Settings: ServerSettings{
            Servers: []ServerEntry{entry},
        },
    }, nil
}
