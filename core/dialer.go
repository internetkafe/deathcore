package core
import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "os"
        "os/exec"
        "strconv"
        "time"
        "deathcore/vless"
)
type Dialer struct {
        cmd        *exec.Cmd
        socks5Port int
        configFile string
        closeFunc  func()
}
func NewDialer(outbound *vless.OutboundConfig) (*Dialer, error) {
        // Найти свободный порт для SOCKS5
        listener, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                return nil, fmt.Errorf("free port: %w", err)
        }
        port := listener.Addr().(*net.TCPAddr).Port
        listener.Close()
        // Формируем полный конфиг (как в рабочем примере)
        fullConfig := map[string]interface{}{
                "dns": map[string]interface{}{
                        "servers": []string{"1.1.1.1"},
                        "tag":     "dns-module",
                },
                "inbounds": []interface{}{
                        map[string]interface{}{
                                "listen":   "127.0.0.1",
                                "port":     port,
                                "protocol": "socks",
                                "settings": map[string]interface{}{
                                        "auth":      "noauth",
                                        "udp":       true,
                                        "userLevel": 8,
                                },
                                "sniffing": map[string]interface{}{
                                        "destOverride": []string{"http", "tls"},                                        "enabled":      true,
                                        "routeOnly":    true,
                                },
                                "tag": "socks",
                        },
                },
                "log": map[string]interface{}{
                        "loglevel": "none",
                },
                "outbounds": []interface{}{
                        outbound,
                        map[string]interface{}{
                                "protocol": "freedom",
                                "settings": map[string]interface{}{
                                        "domainStrategy": "UseIP",
                                },
                                "tag": "direct",
                        },
                        map[string]interface{}{
                                "protocol": "blackhole",
                                "settings": map[string]interface{}{
                                        "response": map[string]interface{}{
                                                "type": "http",
                                        },
                                },
                                "tag": "block",
                        },
                },
                "policy": map[string]interface{}{
                        "levels": map[string]interface{}{
                                "8": map[string]interface{}{
                                        "connIdle":     300,
                                        "downlinkOnly": 1,
                                        "handshake":    4,
                                        "uplinkOnly":   1,
                                },
                        },
                        "system": map[string]interface{}{
                                "statsOutboundUplink":   true,
                                "statsOutboundDownlink": true,
                        },
                },
                "routing": map[string]interface{}{
                        "domainStrategy": "IPOnDemand",
                        "rules": []interface{}{
                                map[string]interface{}{
                                        "type":        "field",
                                        "outboundTag": "proxy",
                                        "port":        "0-65535",
                                },
                        },
                },
                "stats": map[string]interface{}{},
        }
        jsonBytes, err := json.MarshalIndent(fullConfig, "", "  ")
        if err != nil {
                return nil, fmt.Errorf("marshal config: %w", err)
        }
        // Сохраняем во временный файл
        tmpFile, err := os.CreateTemp("", "deathcore-config-*.json")
        if err != nil {
                return nil, fmt.Errorf("create temp file: %w", err)
        }
        if _, err := tmpFile.Write(jsonBytes); err != nil {
                tmpFile.Close()
                os.Remove(tmpFile.Name())
                return nil, err
        }
        tmpFile.Close()
        fmt.Println("=== FULL XRAY CONFIG ===")
        fmt.Println(string(jsonBytes))
        fmt.Println("========================")
        fmt.Printf("Config saved to %s\n", tmpFile.Name())
        // Запускаем xray
        cmd := exec.Command("xray", "run", "-c", tmpFile.Name())
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        if err := cmd.Start(); err != nil {
                os.Remove(tmpFile.Name())
                return nil, fmt.Errorf("start xray: %w", err)
        }
        // Ждём, пока SOCKS5 порт не станет доступен
        if !waitForPort("127.0.0.1", port, 10*time.Second) {
                cmd.Process.Kill()
                os.Remove(tmpFile.Name())
                return nil, fmt.Errorf("xray SOCKS5 port %d not ready", port)
        }
        return &Dialer{
                cmd:        cmd,
                socks5Port: port,
                configFile: tmpFile.Name(),
                closeFunc: func() {
                        cmd.Process.Kill()
                        os.Remove(tmpFile.Name())
                },
        }, nil
}
func (d *Dialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
        host, portStr, err := net.SplitHostPort(addr)
        if err != nil {
                return nil, fmt.Errorf("bad addr: %w", err)
        }
        port, err := strconv.Atoi(portStr)
        if err != nil {
                return nil, fmt.Errorf("bad port: %w", err)
        }
        proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(d.socks5Port))
        var dialer net.Dialer
        conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
        if err != nil {
                return nil, err
        }
        if err := socks5Handshake(conn, host, port); err != nil {
                conn.Close()
                return nil, err
        }
        return conn, nil
}
func (d *Dialer) Close() error {
        d.closeFunc()
        return nil
}
func waitForPort(host string, port int, timeout time.Duration) bool {
        deadline := time.Now().Add(timeout)
        for time.Now().Before(deadline) {
                conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 500*time.Millisecond)
                if err == nil {
                        conn.Close()
                        return true
                }
                time.Sleep(200 * time.Millisecond)
        }
        return false
}
func socks5Handshake(conn net.Conn, dstHost string, dstPort int) error {
        if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
                return err
        }
        resp := make([]byte, 2)
        if _, err := io.ReadFull(conn, resp); err != nil {
                return err
        }
        if resp[0] != 0x05 || resp[1] != 0x00 {
                return fmt.Errorf("SOCKS5 greeting failed")
        }
        hostBytes := []byte(dstHost)
        req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
        req = append(req, hostBytes...)
        req = append(req, byte(dstPort>>8), byte(dstPort&0xFF))
        if _, err := conn.Write(req); err != nil {
                return err
        }
        resp = make([]byte, 4)
        if _, err := io.ReadFull(conn, resp); err != nil {
                return err
        }
        if resp[0] != 0x05 || resp[1] != 0x00 {
                return fmt.Errorf("SOCKS5 connect failed")
        }
        var err error
        switch resp[3] {
        case 0x01:
                skip := make([]byte, 6)
                _, err = io.ReadFull(conn, skip)
        case 0x03:
                lenB := make([]byte, 1)
                _, err = io.ReadFull(conn, lenB)
                if err == nil {
                        skip := make([]byte, int(lenB[0])+2)
                        _, err = io.ReadFull(conn, skip)
                }
        case 0x04:
                skip := make([]byte, 18)
                _, err = io.ReadFull(conn, skip)
        default:
                return fmt.Errorf("unsupported address type: %d", resp[3])
        }
        return err
}
