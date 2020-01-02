package main

import (
	"sslchecker"
	"os"
)

func main() {
	var args = os.Args
	if len(args) == 2	{
		sslchecker.SSLCheck(args[1], "")
	} else if len(args) == 3 {
		if args[2] == "json" {
			sslchecker.SSLCheck(args[1], "json")
		}
	}
}