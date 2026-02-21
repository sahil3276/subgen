
<h1 align="center">SubGen - Smart Subdomain Wordlist Generator</h1>

<p align="center">
  <b>Generate intelligent, context-aware subdomain permutations for recon & attack surface discovery.</b>
</p>

<p align="center">
  <a href="#installation">Install</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#tiers">Tiers</a> •
  <a href="#demo">Demo</a> 
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
</p>

---

## 🤔 What is SubGen?

During recon, you find subdomains like `dev.target.com` or `staging.target.com` — but what about `dev-api.target.com`, `uat-portal.target.com`, or `staging2.target.com`?

**SubGen** takes your known domains/subdomains and generates smart permutations based on **real-world naming conventions** seen across thousands of organizations. It understands internal naming patterns (environment prefixes, numbered instances, region codes, service names) and creates a targeted wordlist you can feed into tools like `httpx`, `dnsx`, `massdns`, or `puredns`.

### Why not just use a static wordlist?

| Static Wordlist | SubGen |
|---|---|
| Same list for every target | Context-aware — adapts to your input |
| Generates `demo.demo.target.com` 🤦 | Smart skip — never duplicates existing parts |
| 1 million lines, mostly junk | Tiered output — 50 to 700+ words based on your scale |
| No dedup across inputs | Global dedup — `admin.target.com` appears once, not multiple times |

---

## 📦 Installation

### Using Go (Recommended)

```bash
go install github.com/sahil3276/subgen@latest
```

> Make sure `$GOPATH/bin` or `$HOME/go/bin` is in your `$PATH`.

### From Source

```bash
git clone https://github.com/sahil3276/subgen.git
cd subgen
go build -o subgen .
sudo mv subgen /usr/local/bin/  # optional: make it global
```


## 🚀 Quick Start

**I have a single domain:**
```bash
subgen -d target.com
```

**I have a file of subdomains from recon:**
```bash
subgen -l my-subdomains.txt -o permutations.txt
```

**I want to pipe it directly into httpx:**
```bash
subgen -l subs.txt -silent | httpx -silent -mc 200
```

That's it. SubGen figures out the rest.

---

## 📖 Usage

```
subgen [flags]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `-d` | Single target domain | — |
| `-l` | File with list of domains (one per line) | — |
| `-o` | Output file path | stdout |
| `-tier` | Wordlist tier: `1`, `2`, `3`, or `0` for auto | `0` (auto) |
| `-w` | Concurrent workers | `10` |
| `-wl` | Path to your own custom wordlist | — |
| `-mode` | Generation mode: `auto`, `root`, `sub` | `auto` |
| `-dedup-roots` | Deduplicate across domains sharing same root | `true` |
| `-silent` | Only output subdomains (no banner/stats) | `false` |
| `-v` | Verbose output | `false` |
| `-version` | Show version | — |

---

## 🎯 What Should I Do? 

### Scenario 1: "I have a root domain and want to discover subdomains"

You have: `target.com`

```bash
subgen -d target.com -tier 3 -o wordlist.txt
```

Use **tier 3** (exhaustive) since it's a single domain — you want maximum coverage.
Then resolve them:
```bash
puredns resolve wordlist.txt -r resolvers.txt -w alive.txt
```

---

### Scenario 2: "I ran subfinder/amass and got 500 subdomains"

You have: `recon-subs.txt` with lines like:
```
dev.target.com
api.target.com  
staging.target.com
portal.target.com
```

```bash
subgen -l recon-subs.txt -o permutations.txt
```

SubGen will **auto-select tier 2** and generate smart variations:
- `dev-api.target.com`, `dev-portal.target.com`
- `staging2.target.com`, `staging-api.target.com`
- `admin.target.com`, `vpn.target.com` (new siblings)
- But **NOT** `dev.dev.target.com` ✅

---

### Scenario 3: "I have Massive subdomains from a large program"

You have: `massive-list.txt` 

```bash
subgen -l massive-list.txt -tier 1 -o output.txt -silent
```

SubGen **auto-selects tier 1** (or you force it) — only ~50 high-value words per domain. This keeps output manageable and CPU-friendly.

With global dedup, many overlapping results are removed automatically.

---

### Scenario 4: "I have my own internal naming patterns"

You have a custom wordlist with org-specific prefixes:

```bash
subgen -d target.com -wl my-custom-words.txt -tier 2 -o output.txt
```

Your custom words are merged with SubGen's built-in list.

---

### Scenario 5: "I want to chain it with other tools"

```bash
# Generate → Resolve → Probe
subgen -l subs.txt -silent | dnsx -silent | httpx -silent -mc 200 -o live.txt

# Generate → MassDNS
subgen -d target.com -tier 3 -silent > wordlist.txt
massdns -r resolvers.txt -t A -o S wordlist.txt > resolved.txt

# Generate → PureDNS
subgen -l subs.txt -silent | puredns resolve -r resolvers.txt -w alive.txt
```

---

## 📊 Tiers Explained

SubGen uses a **tiered wordlist** system so you don't burn your CPU or get rate-limited.

| Tier | Words | Best For | What's Included |
|---|---|---|---|
| **1 : Fast** | ~50 | 2000+ input domains | `dev`, `staging`, `api`, `admin`, `vpn`, `mail`, `db`, `cdn`... Only the highest-hit words. |
| **2 : Balanced** | ~200 | 500–2000 input domains | Tier 1 + numbered variants (`app01`, `dev3`), CI/CD, security tools, more services. |
| **3 : Exhaustive** | ~700+ | <500 input domains | Everything. Region codes, org-specific patterns, cloud infra, deep niche services. |
| **0 : Auto** | — | Always works | SubGen picks the tier based on your input count. **Recommended.** |

### Rough output estimate:

| Input Domains | Tier | Output (approx) |
|---|---|---|
| 1 | 3 | ~2,000–4,000 |
| 100 | 3 | ~50,000–80,000 |
| 500 | 2 | ~80,000–120,000 |
| 4,000 | 1 | ~150,000–200,000 |

> With global dedup enabled, actual numbers are often **30-50% lower**.

---

## 🧠 Smart Features

### 1. Redundancy Detection
Input `demo.example.com` → SubGen knows `demo` exists and **skips** words that would create nonsense like `demo.demo.example.com`.

### 2. Context-Aware Mode
SubGen auto-detects whether your input is a root domain (`target.com`) or an existing subdomain (`dev.target.com`) and adjusts its generation strategy.

For `dev.target.com` it generates:
- Sibling subdomains: `staging.target.com`, `api.target.com`
- Deeper nesting: `admin.dev.target.com`
- Dashed variants: `dev-api.target.com`, `api-dev.target.com`

### 3. Global Dedup
If your list has `dev.target.com`, `staging.target.com`, and `api.target.com`, the sibling `admin.target.com` is generated **once**, not three times.

### 4. Auto Tier Selection
Don't want to think about tiers? Use `-tier 0` (default). SubGen picks the right tier based on your input size.

### 5. Multi-Part TLD Support
Handles `.co.uk`, `.com.au`, `.co.in`, `.com.br`, and 30+ multi-part TLDs correctly.

---
## ⚠️ Disclaimer

This tool is intended for **authorized security testing and reconnaissance only**. Always ensure you have proper authorization before scanning any target. The authors are not responsible for any misuse.

---

## 🎬 Demo

> 📹 **Watch the full walkthrough video:**



---


## 📜 License

This project is licensed under the [MIT License](LICENSE).

---




<p align="center">
  <b>If SubGen helped you find something cool, drop a ⭐ on the repo!</b>
</p>
