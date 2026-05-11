package vless
import (
        "encoding/json"
        "errors"
        "fmt"
        "net/url"
)
type OutboundConfig struct {
        Tag           string        `json:"tag"`
        Protocol      string        `json:"protocol"`
        Mux           MuxConfig     `json:"mux"`
        Settings      Settings      `json:"settings"`
        StreamSetting StreamSetting `json:"streamSettings"`
}
type MuxConfig struct {
        Enabled     bool `json:"enabled"`
        Concurrency int  `json:"concurrency"`
}
type StreamSetting struct {
        Network         string         `json:"network"`
        Security        string         `json:"security"`
        RealitySettings *RealityConfig `json:"realitySettings,omitempty"`
        XhttpSettings   *XhttpConfig   `json:"xhttpSettings,omitempty"`
        GRPCConfig      *GRPCConfig    `json:"grpcSettings,omitempty"`
        SocketOpt       SocketOpt      `json:"sockopt"`
}
type RealityConfig struct {
        ServerName    string `json:"serverName"`
        PublicKey     string `json:"publicKey"`
        ShortId       string `json:"shortId"`
        Fingerprint   string `json:"fingerprint"`
        SpiderX       string `json:"spiderX,omitempty"`
        AllowInsecure bool   `json:"allowInsecure"`
        Show          bool   `json:"show"`
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
        Interleave        int  `json:"interleave"`
        MaxConcurrentTry  int  `json:"maxConcurrentTry"`
        PrioritizeIPv6    bool `json:"prioritizeIPv6"`
        TryDelayMs        int  `json:"tryDelayMs"`
}
type Settings struct {
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
// Parse разбирает VLESS‑URL и возвращает полный OutboundConfig.
func Parse(rawURL string) (*OutboundConfig, error) {
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
        // Берём encryption как есть (поддерживаем длинные ключи типа mlkem768...)
        enc := q.Get("encryption")
        if enc == "" {
                enc = "none"
        }
        stream := StreamSetting{
                Network:  transport,
                Security: security,
                SocketOpt: SocketOpt{
                        DomainStrategy: "UseIP",
                        HappyEyeballs: &HappyEyeballs{
                                Interleave:       2,
                                MaxConcurrentTry: 4,
                                PrioritizeIPv6:   false,
                                TryDelayMs:       250,
                        },
                },
        }
        if security == "reality" {
                stream.RealitySettings = &RealityConfig{
                        ServerName:    q.Get("sni"),
                        PublicKey:     q.Get("pbk"),
                        ShortId:       q.Get("sid"),
                        Fingerprint:   q.Get("fp"),
                        SpiderX:       q.Get("spx"),
                        AllowInsecure: false,
                        Show:          false,
                }
        }
        if transport == "xhttp" {
                xhttp := &XhttpConfig{
                        Mode: q.Get("mode"),
                        Path: q.Get("path"),
                        Host: q.Get("host"),
                }
                if extraStr := q.Get("extra"); extraStr != "" {
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
        } else if transport == "grpc" {
                stream.GRPCConfig = &GRPCConfig{
                        ServiceName: q.Get("serviceName"),
                        Authority:   q.Get("authority"),
                        Mode:        q.Get("mode"),
                }
        }
        return &OutboundConfig{
                Tag:      "proxy",
                Protocol: "vless",
                Mux: MuxConfig{
                        Enabled:     false,
                        Concurrency: -1,
                },
                StreamSetting: stream,
                Settings: Settings{
                        Vnext: []Vnext{{
                                Address: host,
                                Port:    port,
                                Users: []User{{
                                        Id:         uuid,
                                        Encryption: enc, // оригинальное значение из URL
                                        Level:      8,
                                }},
                        }},
                },
        }, nil
}
