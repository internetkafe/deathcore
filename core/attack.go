package core
import (
        "bytes"
        "crypto/rand"
        "encoding/binary"
        "fmt"
        "os"
        "strings"
)
type PayloadGenerator interface {
        Next() ([]byte, error)
}
type FloodGenerator struct {
        size int
}
func NewFloodGenerator(size int) *FloodGenerator {
        if size < 65536 {
                size = 65536
        }
        return &FloodGenerator{size: size}
}
func (g *FloodGenerator) Next() ([]byte, error) {
        buf := make([]byte, g.size)
        _, err := rand.Read(buf)
        return buf, err
}
type HTTPGenerator struct {
        template string
        host     string
        path     string
}
func NewHTTPGenerator(template, host, path string) *HTTPGenerator {
        return &HTTPGenerator{template: template, host: host, path: path}
}
func (g *HTTPGenerator) Next() ([]byte, error) {
        req := g.template
        req = strings.ReplaceAll(req, "{{.Host}}", g.host)
        req = strings.ReplaceAll(req, "{{.Path}}", g.path)
        return []byte(req), nil
}
type GRPCGenerator struct {
        message []byte
}
func NewGRPCGenerator(filePath string) (*GRPCGenerator, error) {
        data, err := os.ReadFile(filePath)
        if err != nil {
                return nil, fmt.Errorf("read grpc file: %w", err)
        }
        return &GRPCGenerator{message: data}, nil
}
func (g *GRPCGenerator) Next() ([]byte, error) {
        buf := new(bytes.Buffer)
        buf.WriteByte(0) // no compression
        lenBuf := make([]byte, 4)
        binary.BigEndian.PutUint32(lenBuf, uint32(len(g.message)))
        buf.Write(lenBuf)
        buf.Write(g.message)
        return buf.Bytes(), nil
}
