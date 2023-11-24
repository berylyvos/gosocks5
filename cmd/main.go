package main

import (
	"log"
	"os"

	"github.com/berylyvos/gosocks5"
)

var authorizedUsers = map[string]string{
	"admin":  "123456",
	"bryce":  "111111",
	"shingo": "gnix.com",
}

func main() {
	var method gosocks5.Method
	var passwordChecker gosocks5.PasswordChecker

	if len(os.Args) > 1 {
		if os.Args[1] == "-m" {
			if len(os.Args) != 3 {
				log.Fatalln("usage: -m [noauth | pwd]")
				return
			}
			if os.Args[2] != "noauth" && os.Args[2] != "pwd" {
				log.Fatalln("usage: -m [noauth | pwd]")
				return
			}
			if os.Args[2] == "noauth" {
				method = gosocks5.MethodNoAuth
			} else {
				method = gosocks5.MethodPassword
				passwordChecker = func(uname, pwd string) bool {
					expectPwd, ok := authorizedUsers[uname]
					if !ok {
						return false
					}
					return expectPwd == pwd
				}
			}
		}
	}

	server := gosocks5.S5Server{
		IP:   "localhost",
		Port: 1080,
		Config: &gosocks5.Config{
			AuthMethod: method,
			PwdChecker: passwordChecker,
		},
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
