package config
import "time"
type Config struct {
        VLESSURL        string
        Workers         int
        AttackMode      string
        HTTPTemplate    string
        GRPCMessageFile string
        ReconnectDelay  time.Duration
        MaxBackoff      time.Duration
        ReadTimeout     time.Duration
        TargetAddr      string
}
