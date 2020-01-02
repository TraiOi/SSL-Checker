package sslchecker

type SSLChecker struct {
	Host string
	Port string
	CertInfo
	ServerInfo
}

type ServerInfo struct {
	IP string `json: ip`
	Type string `json: type`
	Expiry string `json: expiry`
	IsExpired string `json: isexpired`
	Issuer string `json: issuer`
}

type CertInfo struct {
	CNAME string `json: cname`
	SANs string `json: sans`
	Org string `json: org`
	OrgUnit string `json: orgunit`
	Location string `json: location`
	NotBefore string `json: notbefore`
	NotAfter string `json: notafter`
	Expiry string `json: expiry`
	Issuer string `json: issuer`
}