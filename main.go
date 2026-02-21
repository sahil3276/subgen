package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"
const banner = `
   _____ __  ______  ______          
  / ___// / / / __ )/ ____/__  ____  
  \__ \/ / / / __  / / __/ _ \/ __ \ 
 ___/ / /_/ / /_/ / /_/ /  __/ / / / 
/____/\____/_____/\____/\___/_/ /_/  
                                      
  Smart Subdomain Wordlist Generator %s
  github.com/sahil3276/subgen
`

// ────────────────────────────────────────────
// Tiered Wordlists (scored by real-world frequency)
// ────────────────────────────────────────────

// Tier 1: HIGH probability — seen in almost every org (~50 words)
var tier1 = []string{
	"dev", "staging", "stg", "uat", "qa", "prod", "preprod", "test", "demo",
	"api", "app", "web", "admin", "portal", "internal", "intranet", "vpn",
	"mail", "smtp", "webmail", "ftp", "sftp", "cdn", "static", "assets",
	"sso", "auth", "login", "dashboard", "monitor", "status", "docs", "wiki",
	"git", "jenkins", "ci", "db", "mysql", "redis", "cache", "mq",
	"grafana", "kibana", "elastic", "logs", "ns1", "ns2", "mx", "mx1",
	"sandbox", "beta", "stage",
}

// Tier 2: MEDIUM probability — common in mid/large orgs (~150 words)
var tier2 = []string{
	"dev1", "dev2", "dev3", "uat1", "uat2", "qa1", "qa2", "stg1", "stg2",
	"alpha", "canary", "preview", "rc", "hotfix", "sit", "oat", "devint",
	"perf", "loadtest", "stress", "e2e", "integration", "acceptance",
	"api-v1", "api-v2", "api-internal", "api-public", "gateway", "gw",
	"frontend", "backend", "proxy", "lb", "backend", "fe", "be",
	"app01", "app02", "app03", "web01", "web02", "web03",
	"srv01", "srv02", "srv03", "db01", "db02",
	"node01", "node02", "node03", "vm01", "vm02", "vm03",
	"worker01", "worker02", "worker03",
	"cms", "crm", "erp", "idp", "oauth", "iam", "console", "panel",
	"mgmt", "management", "monitoring", "observability", "prometheus",
	"alertmanager", "apm", "datadog", "newrelic", "syslog", "audit",
	"corp", "corporate", "office", "bastion", "jump", "jumpbox",
	"confluence", "jira", "bitbucket", "gitlab", "registry", "harbor",
	"nexus", "artifactory", "docker", "k8s", "kube", "rancher",
	"consul", "vault", "terraform", "ansible",
	"rabbitmq", "kafka", "celery", "scheduler", "cron", "batch",
	"exchange", "owa", "mx2", "relay", "newsletter", "notifications",
	"waf", "firewall", "siem", "splunk", "nessus", "qualys",
	"ssl", "cert", "pki", "ldap", "ad", "keycloak", "okta",
	"analytics", "metrics", "bi", "report", "reports", "data",
	"dns", "dns1", "dns2", "dhcp", "ntp", "dmz",
	"aws", "azure", "gcp", "cloudflare",
	"support", "help", "helpdesk", "config",
	"postgres", "postgresql", "mongo", "mongodb", "cassandra",
	"elasticsearch", "es", "s3", "storage", "backup", "archive",
	"nagios", "zabbix", "pagerduty", "statuspage", "uptime",
	"healthcheck", "health", "sonarqube",
	"hadoop", "spark", "airflow", "jupyter",
	"chat", "slack", "voip", "sip", "pbx",
	"dr", "drp", "failover",
	"ns3", "mx3",
	"legacy", "old", "new", "temp",
}

// Tier 3: LOW probability — exhaustive, niche, org-specific (~400+ words)
var tier3 = []string{
	// Extended numbered
	"dev4", "dev5", "dev6", "dev7", "dev8", "dev9", "dev10",
	"uat3", "uat4", "uat5", "uat6", "uat7", "uat8", "uat9", "uat10",
	"qa3", "qa4", "qa5", "qa6", "qa7", "qa8", "qa9", "qa10",
	"stg3", "stg4", "stg5", "stg6", "stg7", "stg8", "stg9", "stg10",
	"app04", "app05", "app06", "app07", "app08", "app09", "app10",
	"app11", "app12", "app13", "app14", "app15",
	"web04", "web05", "web06", "web07", "web08", "web09", "web10",
	"web11", "web12", "web13", "web14", "web15",
	"srv04", "srv05", "srv06", "srv07", "srv08", "srv09", "srv10",
	"srv11", "srv12", "srv13", "srv14", "srv15",
	"svr01", "svr02", "svr03", "svr04", "svr05", "svr06", "svr07",
	"svr08", "svr09", "svr10", "svr11", "svr12", "svr13", "svr14", "svr15",
	"host01", "host02", "host03", "host04", "host05", "host06", "host07",
	"host08", "host09", "host10", "host11", "host12", "host13", "host14", "host15",
	"vm04", "vm05", "vm06", "vm07", "vm08", "vm09", "vm10",
	"vm11", "vm12", "vm13", "vm14", "vm15",
	"worker04", "worker05", "worker06", "worker07", "worker08", "worker09", "worker10",
	"prod01", "prod02", "prod03", "prod04", "prod05", "prod06", "prod07",
	"prod08", "prod09", "prod10", "prod11", "prod12", "prod13", "prod14", "prod15",
	"db03", "db04", "db05", "db06", "db07", "db08", "db09", "db10",
	"cache01", "cache02", "cache03", "cache04", "cache05",
	"container01", "container02", "container03", "container04", "container05",
	"container06", "container07", "container08", "container09", "container10",
	"node04", "node05", "node06", "node07", "node08", "node09", "node10",
	"node11", "node12", "node13", "node14", "node15",
	"staging01", "staging02", "staging03", "staging04", "staging05",
	"staging06", "staging07", "staging08", "staging09", "staging10",
	// Org-specific codes
	"p1c", "p1cuat", "dre", "pdcocp4stg01", "pdcocp4stg02", "bdoc1", "bdoc2",
	"phx1", "phx2", "uat-bdoc1", "uat-bdoc2", "am", "am-uat", "pds", "pds-uat",
	"uat-pds", "ecm", "rdy", "sms", "dpp", "uat-dpp", "rp01", "rp02",
	"xsp", "uat-xsp", "xsp-uat", "kas",
	// Deep env stages
	"gamma", "delta", "epsilon", "nightly", "edge", "latest", "baseline",
	"golden", "blue", "green", "bluegreen", "blue-green", "a-b", "dark",
	"shadow", "mirror", "deprecated", "scratch", "poc", "spike", "prototype",
	"feature", "experimental", "lab", "labs", "research", "bench", "benchmark",
	"smoke", "regression", "ppe", "pte", "training", "trn",
	"stage1", "stage2", "stage3", "v1", "v2", "v3",
	// Extended CI/CD
	"cd", "build", "deploy", "release", "pipeline", "artifact",
	"bamboo", "teamcity", "gh-actions", "argocd", "circleci", "travis",
	"drone", "spinnaker", "octopus", "harness",
	// Extended infra regions
	"us-east", "us-east-1", "us-east-2", "us-west", "us-west-1", "us-west-2",
	"eu-west", "eu-west-1", "eu-west-2", "eu-central", "eu-central-1",
	"ap-south", "ap-south-1", "ap-southeast", "ap-southeast-1", "ap-southeast-2",
	"ap-northeast", "ap-northeast-1", "na", "emea", "apac", "latam",
	"dc1", "dc2", "dc3", "dc4", "dc5",
	"colo1", "colo2", "colo3", "az1", "az2", "az3",
	"rack1", "rack2", "rack3", "cluster1", "cluster2", "cluster3",
	"zone1", "zone2", "zone3", "region1", "region2", "region3",
	"pop1", "pop2", "pop3", "edge1", "edge2", "edge3",
	// Extended services
	"api-v3", "api-external", "api-private", "reverse-proxy", "rproxy",
	"nlb", "alb", "elb", "middleware", "mw", "www",
	"administrator", "auth0", "signin", "signup", "register",
	"account", "accounts", "identity", "cpanel", "whm", "plesk",
	"manage", "tracing", "jaeger", "zipkin", "dynatrace",
	"application", "service", "svc", "microservice", "ms",
	"rest", "graphql", "grpc", "soap", "wsdl", "webhook", "callback",
	// Extended DB/storage
	"db-master", "db-slave", "db-replica", "db-read", "db-write",
	"db-primary", "db-secondary", "db-standby", "mariadb",
	"oracle", "oracledb", "mssql", "sqlserver",
	"couchdb", "couchbase", "dynamodb", "memcached", "memcache",
	"solr", "lucene", "neo4j", "graphdb", "influxdb", "timescaledb", "clickhouse",
	"blob", "blobstore", "objectstore", "media", "files",
	"upload", "uploads", "images", "img", "video",
	"bkp", "bak", "nas", "san", "nfs", "cifs",
	"minio", "gluster", "ceph", "hdfs", "datalake", "datawarehouse", "dwh", "etl",
	// Extended internal tools
	"documentation", "github", "gitea", "gogs", "repo", "repository",
	"dockerhub", "sonatype", "openshift", "oc", "helm",
	"nomad", "puppet", "chef", "salt", "saltstack", "vagrant", "packer",
	"icinga", "opsgenie", "alive", "ready", "readiness", "liveness",
	"fortify", "checkmarx", "veracode", "snyk", "trivy",
	// Extended messaging
	"rmq", "activemq", "sqs", "sns", "pubsub", "eventbus", "event", "events",
	"broker", "messagebroker", "queue", "workers", "sidekiq",
	"crontab", "job", "jobs", "taskqueue", "zeromq", "nats", "pulsar",
	"mosquitto", "mqtt", "amqp", "stomp",
	// Extended mail
	"email", "imap", "pop3", "mailrelay", "notify", "push",
	"teams", "mattermost", "rocketchat", "xmpp", "jabber",
	"asterisk", "freeswitch", "ftps", "scp", "rsync", "webdav",
	// Extended security
	"fw", "ids", "ips", "qradar", "arcsight", "sec", "infosec", "cybersec",
	"pentest", "scan", "scanner", "sentinelone", "carbonblack", "tanium",
	"rapid7", "tenable", "burp", "acunetix", "openvas",
	"certs", "certificate", "tls", "ca", "ocsp", "crl", "kms", "hsm",
	"secrets", "secretsmanager", "2fa", "mfa", "otp", "radius", "activedirectory",
	// Extended analytics
	"stats", "statistics", "tableau", "powerbi", "looker", "superset",
	"redash", "metabase", "reporting", "bigdata",
	"flink", "presto", "hive", "pig", "ml", "ai", "machinelearning",
	"deeplearning", "model", "models", "prediction", "inference",
	"notebook", "notebooks", "rstudio", "sagemaker", "mlflow", "kubeflow",
	// Extended networking
	"snmp", "router", "switch", "core", "core1", "core2", "border",
	"bgp", "ospf", "vlan", "nat", "wan", "lan", "mpls", "sdwan", "ztna", "zerotrust",
	// Extended cloud
	"gcloud", "oci", "ibmcloud", "digitalocean", "do", "linode", "vultr",
	"heroku", "netlify", "vercel", "cf", "lambda", "functions",
	"serverless", "faas", "paas", "saas", "iaas", "cloudfront", "akamai", "fastly",
	"cloudrun", "ecs", "eks", "aks", "gke", "fargate", "beanstalk",
	"appengine", "compute", "ec2", "lightsail", "droplet",
	// Extended misc
	"test1", "test2", "test3", "temp1", "temp2", "debug", "verbose",
	"demo1", "demo2", "trial", "pilot", "insider", "early-access", "eap",
	"ga", "lts", "servicedesk", "ticketing", "zendesk", "freshdesk",
	"servicenow", "itsm", "cmdb", "itil", "sla", "runbook", "playbook",
	"configuration", "cfg", "settings", "preferences",
	"tenant", "tenant1", "tenant2", "multitenant",
	"shared", "dedicated", "onprem", "hybrid", "private", "public",
	"restricted", "confidential", "classified",
	"partner", "vendor", "supplier", "customer", "client", "external",
	"guest", "user", "users", "member", "members",
	"staff", "employee", "hr", "finance", "legal", "sales", "marketing",
	"engineering", "devops", "sre", "platform", "infra", "infrastructure",
	"ops", "operations", "noc", "soc", "cdev", "cen-dev", "central-dev",
	"test-dev", "sand", "local",
}

// ────────────────────────────────────────────
// Domain Parsing
// ────────────────────────────────────────────

// parseDomain breaks input into (subdomain_parts, base, tld)
// e.g. "demo.api.sahil.co.uk" -> (["demo","api"], "sahil", "co.uk")
// e.g. "sahil.com" -> ([], "sahil", "com")
func parseDomain(raw string) (subParts []string, base string, tld string, full string) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimSuffix(raw, "/")

	// Remove port
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		candidate := raw[idx+1:]
		allDigit := len(candidate) > 0
		for _, c := range candidate {
			if c < '0' || c > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			raw = raw[:idx]
		}
	}

	full = raw
	parts := strings.Split(raw, ".")
	if len(parts) <= 1 {
		return nil, raw, "", raw
	}

	// Detect multi-part TLD
	multiTLDs := []string{
		"co.uk", "co.in", "co.jp", "com.au", "com.br", "co.za",
		"org.uk", "net.au", "ac.uk", "gov.uk", "edu.au", "co.nz",
		"com.sg", "com.mx", "co.kr", "com.cn", "com.tw", "co.il",
		"com.ar", "org.au", "net.nz", "gov.in", "ac.in", "edu.in",
		"gov.au", "com.hk", "co.th", "com.tr", "com.pk", "com.ng",
	}

	for _, mt := range multiTLDs {
		if strings.HasSuffix(raw, "."+mt) {
			tld = mt
			remaining := strings.TrimSuffix(raw, "."+mt)
			rParts := strings.Split(remaining, ".")
			base = rParts[len(rParts)-1]
			if len(rParts) > 1 {
				subParts = rParts[:len(rParts)-1]
			}
			return
		}
	}

	// Standard TLD
	tld = parts[len(parts)-1]
	base = parts[len(parts)-2]
	if len(parts) > 2 {
		subParts = parts[:len(parts)-2]
	}
	return
}

// rootDomain returns base.tld (e.g. "sahil.com")
func rootDomain(base, tld string) string {
	if tld == "" {
		return base
	}
	return base + "." + tld
}

// ────────────────────────────────────────────
// Smart Generation Engine
// ────────────────────────────────────────────

func getWordsForTier(tier int) []string {
	switch tier {
	case 1:
		return tier1
	case 2:
		return append(tier1, tier2...)
	case 3:
		all := append(tier1, tier2...)
		all = append(all, tier3...)
		return all
	default:
		return tier1
	}
}

// existingParts extracts all "tokens" already present in the input domain
// so we can skip generating redundant combos.
// e.g. "dev.api.staging.sahil.com" -> {"dev":true, "api":true, "staging":true}
func existingParts(subParts []string, base string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range subParts {
		m[p] = true
		// Also handle dashed parts: "test-dev" -> "test", "dev"
		for _, seg := range strings.Split(p, "-") {
			if seg != "" {
				m[seg] = true
			}
		}
	}
	m[base] = true
	return m
}

// shouldSkip returns true if adding this word would be redundant
// given the existing subdomain parts.
func shouldSkip(word string, existing map[string]bool) bool {
	// Direct match — word already exists as a subdomain part
	if existing[word] {
		return true
	}
	// Check dashed components of the word
	// e.g. word="dev-api", existing has "dev" and "api" -> skip
	dashParts := strings.Split(word, "-")
	if len(dashParts) > 1 {
		allExist := true
		for _, dp := range dashParts {
			if !existing[dp] {
				allExist = false
				break
			}
		}
		if allExist {
			return true
		}
	}
	return false
}

// generateSmart creates subdomains intelligently for a single input domain.
func generateSmart(inputDomain string, words []string, mode string) []string {
	subParts, base, tld, _ := parseDomain(inputDomain)
	root := rootDomain(base, tld)
	existing := existingParts(subParts, base)

	seen := make(map[string]struct{})
	var results []string

	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			results = append(results, s)
		}
	}

	// ── Mode: "sub" — input is already a subdomain (e.g. demo.example.com)
	//    Generate variations ON this subdomain + sibling subdomains on root.
	//
	// ── Mode: "root" — input is a root domain (e.g. example.com)
	//    Generate prefix subdomains + dash variations.

	if mode == "auto" {
		if len(subParts) > 0 {
			mode = "sub"
		} else {
			mode = "root"
		}
	}

	switch mode {
	case "root":
		// Technique 1: word.root (dev.sahil.com)
		for _, w := range words {
			if shouldSkip(w, existing) {
				continue
			}
			add(w + "." + root)
		}

		// Technique 2: word-base.tld (dev-sahil.com) — only if tld present
		if tld != "" {
			for _, w := range words {
				if shouldSkip(w, existing) {
					continue
				}
				add(w + "-" + base + "." + tld)
			}
			// Technique 3: base-word.tld (sahil-dev.com)
			for _, w := range words {
				if shouldSkip(w, existing) {
					continue
				}
				add(base + "-" + w + "." + tld)
			}
		}

	case "sub":
		// Input is e.g. "demo.sahil.com" or "dev.api.sahil.com"
		// We generate:
		//   - sibling subdomains on root: word.sahil.com (skipping redundant)
		//   - deeper nesting on this sub: word.demo.sahil.com
		//   - variations of the existing sub: demo-word.sahil.com

		// Sibling subdomains on root
		for _, w := range words {
			if shouldSkip(w, existing) {
				continue
			}
			add(w + "." + root)
		}

		// Deeper nesting on existing subdomain path
		currentFull := strings.Join(subParts, ".") + "." + root
		for _, w := range words {
			if shouldSkip(w, existing) {
				continue
			}
			add(w + "." + currentFull)
		}

		// Dashed variations on the first subdomain part
		if len(subParts) > 0 {
			firstSub := subParts[0]
			restPath := root
			if len(subParts) > 1 {
				restPath = strings.Join(subParts[1:], ".") + "." + root
			}
			for _, w := range words {
				if shouldSkip(w, existing) {
					continue
				}
				add(firstSub + "-" + w + "." + restPath)
				add(w + "-" + firstSub + "." + restPath)
			}
		}
	}

	return results
}

// ────────────────────────────────────────────
// Smart Tier Selection
// ────────────────────────────────────────────

func autoSelectTier(domainCount int) int {
	switch {
	case domainCount > 2000:
		return 1
	case domainCount > 500:
		return 2
	default:
		return 3
	}
}

// ────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────

func printBanner() {
	fmt.Fprintf(os.Stderr, banner, version)
	fmt.Fprintln(os.Stderr)
}

func info(silent bool, format string, a ...interface{}) {
	if !silent {
		fmt.Fprintf(os.Stderr, "[INF] "+format+"\n", a...)
	}
}

func warn(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WRN] "+format+"\n", a...)
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERR] "+format+"\n", a...)
	os.Exit(1)
}

func loadLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	// Handle very long lines
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// ────────────────────────────────────────────
// Main
// ────────────────────────────────────────────

func main() {
	domainFlag := flag.String("d", "", "Single target domain (e.g. example.com or sub.example.com)")
	listFlag := flag.String("l", "", "File containing list of domains (one per line)")
	outputFlag := flag.String("o", "", "Output file (default: stdout)")
	tierFlag := flag.Int("tier", 0, "Wordlist tier: 1=fast(~50), 2=balanced(~200), 3=exhaustive(~700+), 0=auto based on input size")
	workersFlag := flag.Int("w", 10, "Concurrent workers")
	silentFlag := flag.Bool("silent", false, "Only output subdomains (no banner/stats)")
	verboseFlag := flag.Bool("v", false, "Verbose output")
	customWL := flag.String("wl", "", "Additional custom wordlist file")
	modeFlag := flag.String("mode", "auto", "Generation mode: auto, root, sub")
	uniqueRoots := flag.Bool("dedup-roots", true, "Deduplicate across domains sharing the same root")
	versionFlag := flag.Bool("version", false, "Show version")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  subgen -d example.com                     # root domain\n")
		fmt.Fprintf(os.Stderr, "  subgen -d demo.example.com                # smart: skips demo.demo.*\n")
		fmt.Fprintf(os.Stderr, "  subgen -l subdomains.txt -o output.txt    # bulk from file\n")
		fmt.Fprintf(os.Stderr, "  subgen -l large-list.txt -tier 1          # fast mode for big lists\n")
		fmt.Fprintf(os.Stderr, "  cat subs.txt | subgen -silent             # pipe-friendly\n\n")
		fmt.Fprintf(os.Stderr, "Tier Guide:\n")
		fmt.Fprintf(os.Stderr, "  1  Fast       ~50 words    Best for 2000+ input domains\n")
		fmt.Fprintf(os.Stderr, "  2  Balanced   ~200 words   Best for 500-2000 input domains\n")
		fmt.Fprintf(os.Stderr, "  3  Exhaustive ~700+ words  Best for <500 input domains\n")
		fmt.Fprintf(os.Stderr, "  0  Auto       Picks tier based on input count (default)\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("subgen version %s\n", version)
		os.Exit(0)
	}

	if !*silentFlag {
		printBanner()
	}

	// ── Collect input domains
	var domains []string
	if *domainFlag != "" {
		domains = append(domains, *domainFlag)
	}
	if *listFlag != "" {
		loaded, err := loadLinesFromFile(*listFlag)
		if err != nil {
			fatal("Failed to load domain list: %v", err)
		}
		domains = append(domains, loaded...)
	}
	// Stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				domains = append(domains, line)
			}
		}
	}

	if len(domains) == 0 {
		flag.Usage()
		fatal("No domains provided. Use -d, -l, or pipe via stdin.")
	}

	// Deduplicate input domains
	{
		seen := make(map[string]struct{})
		var deduped []string
		for _, d := range domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" {
				continue
			}
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				deduped = append(deduped, d)
			}
		}
		domains = deduped
	}

	// ── Select tier
	tier := *tierFlag
	if tier == 0 {
		tier = autoSelectTier(len(domains))
		info(*silentFlag, "Auto-selected tier %d based on %d input domains", tier, len(domains))
	}

	words := getWordsForTier(tier)

	// Load custom wordlist
	if *customWL != "" {
		cw, err := loadLinesFromFile(*customWL)
		if err != nil {
			warn("Failed to load custom wordlist: %v (continuing without it)", err)
		} else {
			words = append(words, cw...)
			info(*silentFlag, "Loaded %d custom words from %s", len(cw), *customWL)
		}
	}

	// Deduplicate words
	{
		seen := make(map[string]struct{})
		var deduped []string
		for _, w := range words {
			w = strings.TrimSpace(strings.ToLower(w))
			if w == "" {
				continue
			}
			if _, ok := seen[w]; !ok {
				seen[w] = struct{}{}
				deduped = append(deduped, w)
			}
		}
		words = deduped
	}

	info(*silentFlag, "Wordlist: %d unique words (tier %d)", len(words), tier)
	info(*silentFlag, "Input domains: %d", len(domains))
	info(*silentFlag, "Mode: %s", *modeFlag)

	// Estimate output
	avgPerDomain := len(words) * 2 // rough estimate (prefix + some combos)
	if *modeFlag != "root" {
		avgPerDomain = len(words) * 3
	}
	estimatedTotal := len(domains) * avgPerDomain
	info(*silentFlag, "Estimated output: ~%d subdomains (before global dedup)", estimatedTotal)

	// ── Setup output
	var writer *bufio.Writer
	if *outputFlag != "" {
		dir := filepath.Dir(*outputFlag)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fatal("Cannot create output directory: %v", err)
			}
		}
		f, err := os.Create(*outputFlag)
		if err != nil {
			fatal("Cannot create output file: %v", err)
		}
		defer f.Close()
		writer = bufio.NewWriter(f)
		defer writer.Flush()
	} else {
		writer = bufio.NewWriter(os.Stdout)
		defer writer.Flush()
	}

	// ── Generate
	start := time.Now()
	totalCount := 0

	// Global dedup across all domains (prevents dup when multiple subs share root)
	var globalSeen sync.Map
	useGlobalDedup := *uniqueRoots

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workersFlag)

	for _, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}

		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			results := generateSmart(d, words, *modeFlag)

			mu.Lock()
			for _, r := range results {
				if useGlobalDedup {
					if _, loaded := globalSeen.LoadOrStore(r, struct{}{}); loaded {
						continue // already emitted from another domain
					}
				}
				fmt.Fprintln(writer, r)
				totalCount++
			}
			mu.Unlock()

			if *verboseFlag {
				info(*silentFlag, "[%s] generated %d candidates", d, len(results))
			}
		}(domain)
	}

	wg.Wait()

	elapsed := time.Since(start)
	info(*silentFlag, "")
	info(*silentFlag, "✓ Total unique subdomains: %d", totalCount)
	info(*silentFlag, "✓ Time: %s", elapsed.Round(time.Millisecond))
	if *outputFlag != "" {
		info(*silentFlag, "✓ Saved to: %s", *outputFlag)
	}
}
