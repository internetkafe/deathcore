<p align="center">
  <img src="https://img.shields.io/badge/status-destroying-red?style=for-the-badge" alt="status">
  <img src="https://img.shields.io/badge/protocol-VLESS-blue?style=for-the-badge" alt="protocol">
  <img src="https://img.shields.io/badge/transport-XHTTP%20%7C%20gRPC%20%7C%20TCP-green?style=for-the-badge" alt="transport">
  <img src="https://img.shields.io/badge/encryption-MLKEM768%2BX25519-purple?style=for-the-badge" alt="encryption">
  <img src="https://img.shields.io/badge/no%20mercy-%F0%9F%92%80-black?style=for-the-badge" alt="no-mercy">
</p>

<p align="center">
  <samp>
    ⚡ vless destroyer — load until it bleeds ⚡
  </samp>
</p>

---

## ⚠️ DISCLAIMER

**This tool generates extreme network load. Use ONLY on servers you own or have explicit permission to test. Unauthorized use may be illegal in your jurisdiction. The author is not responsible for misuse.**

---

## 💀 What is deathcore?

**deathcore** is a high-performance **stress testing tool** for VLESS tunnels.
It establishes **thousands of concurrent encrypted connections** and floods targets
through **XHTTP**, **gRPC**, **Reality**, and **post‑quantum encryption** (ML‑KEM768 + X25519).

Built on **Xray‑core**, it supports every modern VLESS feature out of the box:
no need to write protocol handlers — just pass a VLESS URL and let it rip.

---

## 🔥 Features

| Feature | Description |
|---------|-------------|
| 🔗 **VLESS URL parser** | Drop a full VLESS link — deathcore extracts all parameters automatically |
| 🚀 **Multi‑worker** | Thousands of goroutines, each holding a persistent connection |
| 🎯 **Attack modes** | `flood` (raw bytes) • `http` (custom templates) • `grpc` (protobuf) |
| 🔐 **Reality + XHTTP** | Full support for Reality TLS, XHTTP multiplexing, spiderX |
| 🧬 **Post‑quantum** | ML‑KEM768 + X25519 hybrid encryption (yes, those long keys work) |
| ♻️ **Zero‑delay reconnect** | Instant reconnection after drop — keeps pressure 24/7 |
| 📊 **Live stats** | Connections, active workers, total bytes sent (optional) |
| 🤫 **Silent mode** | Zero logging — just pure load |
| 📦 **Single binary** | One `go build` → one executable → ready to destroy |
