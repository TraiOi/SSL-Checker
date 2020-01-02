package sslchecker

import (
  "net"
  "time"
  "encoding/json"
  "crypto/x509"
  "crypto/tls"
  "log"
  "strings"
  "fmt"
)

const (
  DEFAULT_PORT = "443"
  TIMEOUT = 3
  SKIP_VERIFY = false
  PROTO = "tcp"
  UTC = false
)

func (this *SSLChecker) SetHostPort(hostport string) {
  this.Host, this.Port = this.SplitHostPort(hostport)
}

func (this *SSLChecker) SplitHostPort(hostport string) (string, string) {
  if !strings.Contains(hostport, ":") {
		return hostport, DEFAULT_PORT
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {	log.Fatal(err) }
	if port == "" {	port = DEFAULT_PORT }

	return host, port
}

func (this *SSLChecker) Conn() ([]*x509.Certificate) {
  var hostport = fmt.Sprintf("%s:%s", this.Host, this.Port)

  d := &net.Dialer{
    Timeout: time.Duration(TIMEOUT) * time.Second,
  }
  conn, err := tls.DialWithDialer(d, PROTO, hostport, &tls.Config{
    InsecureSkipVerify: SKIP_VERIFY,
  })
  if err != nil { log.Fatal(err) }
  defer conn.Close()

  addr := conn.RemoteAddr()
  this.ServerInfo.IP, _, _ = net.SplitHostPort(addr.String())
  cert := conn.ConnectionState().PeerCertificates
  return cert
}

func (this *SSLChecker) Join(list []string) string {
  return strings.Join(list, ", ")
}

func (this *SSLChecker) PrintIfExist(list []string, format string, content string) []string {
  if content != "" {
    list = append(list, fmt.Sprintf(format, Green(content)))
  }
  return list
}

func (this *SSLChecker) GetDays(date time.Time) string {
  var days = time.Until(date).Hours() / 24
  return fmt.Sprintf("%.0f", days)
}

func (this *SSLChecker) GetTimeExpiry(chain *x509.Certificate) string {
  var loc *time.Location
  loc = time.Local
  if UTC { loc = time.UTC }
  var nafter = chain.NotAfter.In(loc)
  return this.GetDays(nafter)
}

func (this *SSLChecker) GetCertChain(cert_chain []*x509.Certificate, index int) CertInfo {
  var loc *time.Location
  var chain = cert_chain[index]
  var cert CertInfo
  var location []string
  var country = this.Join(chain.Subject.Country)
  var locality = this.Join(chain.Subject.Locality)
  var province = this.Join(chain.Subject.Province)

  loc = time.Local
  if UTC { loc = time.UTC }
  var nbefore = chain.NotBefore.In(loc)
  var nafter = chain.NotAfter.In(loc)

  if locality != "" { location = append(location, locality) }
  if province != "" { location = append(location, province) }
  if country != "" { location = append(location, country) }

  cert.CNAME = chain.Subject.CommonName
  cert.SANs = this.Join(chain.DNSNames)
  cert.Org = this.Join(chain.Subject.Organization)
  cert.OrgUnit = this.Join(chain.Subject.OrganizationalUnit)
  cert.Location = this.Join(location)
  cert.NotBefore = nbefore.String()
  cert.NotAfter = nafter.String()
  cert.Expiry = this.GetTimeExpiry(chain)
  cert.Issuer = chain.Issuer.CommonName

  return cert
}

func (this *SSLChecker) TemplateHeaderJSON(chain *x509.Certificate) string {
  var result []byte
  var issuer = this.Join(chain.Issuer.Organization)
  var serverinfo = &ServerInfo {
    IP: this.ServerInfo.IP,
    Type: "Nginx",
    Expiry: this.GetTimeExpiry(chain),
    Issuer: issuer,
  }
  result, _ = json.Marshal(serverinfo)
  return string(result)
}

func (this *SSLChecker) TemplateChainJSON(cert CertInfo) string {
  var result []byte
  var certinfo = &CertInfo {
    CNAME: cert.CNAME,
    SANs: cert.SANs,
    Org: cert.Org,
    OrgUnit: cert.OrgUnit,
    Location: cert.Location,
    NotBefore: cert.NotBefore,
    NotAfter: cert.NotAfter,
    Expiry: cert.Expiry,
    Issuer: cert.Issuer,
  }
  result, _ = json.Marshal(certinfo)
  return string(result)
}

func (this *SSLChecker) TemplateChainRaw(cert CertInfo) string {
  var content []string
  var bytes = []byte(this.TemplateChainJSON(cert))
  var certinfo CertInfo
  var err = json.Unmarshal(bytes, &certinfo)
  if err != nil { log.Fatal(err) }
  content = this.PrintIfExist(content, "Common Name: %s\n", certinfo.CNAME)
  content = this.PrintIfExist(content, "SANs: %s\n", certinfo.SANs)
  content = this.PrintIfExist(content, "Organization: %s\n", certinfo.Org)
  content = this.PrintIfExist(content, "Org. Unit: %s\n", certinfo.OrgUnit)
  content = this.PrintIfExist(content, "Location: %s\n", certinfo.Location)
  content = this.PrintIfExist(content, "Not Before: %s\n", certinfo.NotBefore)
  content = this.PrintIfExist(content, "Not After: %s\n", certinfo.NotAfter)
  content = this.PrintIfExist(content, "Expiry: %s\n", certinfo.Expiry)
  content = this.PrintIfExist(content, "Issuer: %s\n", certinfo.Issuer)
  return strings.Join(content, "")
}

func (this *SSLChecker) TemplateHeaderRaw(chain *x509.Certificate) string {
  var content []string
  var header = []byte(this.TemplateHeaderJSON(chain))
  var serverinfo ServerInfo
  var err = json.Unmarshal(header, &serverinfo)
  if err != nil { log.Fatal(err) }
  content = this.PrintIfExist(content, "%s ", this.Host)
  content = this.PrintIfExist(content, "resolves to %s.\n", serverinfo.IP)
  content = this.PrintIfExist(content, "Server Type: %s.\n", serverinfo.Type)
  content = this.PrintIfExist(content, "The certificate was issued by %s.\n", serverinfo.Issuer)
  content = this.PrintIfExist(content, "The certificate will expire in %s days\n", serverinfo.Expiry)
  return strings.Join(content, "")
}

func (this *SSLChecker) GetCertInfo(choice string) {
  var c = strings.ToLower(choice)
  var cert_chain = this.Conn()
  var cert CertInfo
  switch c {
		case "json":
			var body []string
			var chain = cert_chain[0]
			fmt.Printf("[")
			fmt.Printf(this.TemplateHeaderJSON(chain))
			fmt.Printf(",")
      for i := 0; i < len(cert_chain); i++ {
        cert = this.GetCertChain(cert_chain, i)
        body = append(body, this.TemplateChainJSON(cert))
			}
			fmt.Printf(strings.Join(body, ","))
			fmt.Printf("]")
    default:
      var chain = cert_chain[0]
      fmt.Printf("######################\n")
      fmt.Printf(this.TemplateHeaderRaw(chain))
      fmt.Printf("\n---------------------\n")
      fmt.Printf("%s\n", Green("SERVER CHAIN"))
      fmt.Printf("----------------------\n")
      cert = this.GetCertChain(cert_chain, 0)
      fmt.Printf(this.TemplateChainRaw(cert))
      for i := 1; i < len(cert_chain); i++ {
        fmt.Printf("---------------------\n")
        fmt.Printf("CHAIN\n")
        fmt.Printf("----------------------\n")
        cert = this.GetCertChain(cert_chain, i)
        fmt.Printf(this.TemplateChainRaw(cert))
      }
  }
}

func (this *SSLChecker) Init(choice string) {
  this.GetCertInfo(choice)
}
