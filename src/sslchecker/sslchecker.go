package sslchecker

func SSLCheck(host string, choice string) {
	traioi := new(SSLChecker)
	traioi.SetHostPort(host)
	traioi.Init(choice)
}