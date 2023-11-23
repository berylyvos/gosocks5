package main

import (
	"log"

	"github.com/berylyvos/gosocks5"
)

func main() {
	authorizedUsers := map[string]string{
		"admin":  "123456",
		"bryce":  "2222",
		"shingo": "gnix.com",
	}

	server := gosocks5.S5Server{
		IP:   "localhost",
		Port: 1080,
		Config: &gosocks5.Config{
			AuthMethod: gosocks5.MethodPassword,
			PasswordChecker: func(uname, pwd string) bool {
				expectPwd, ok := authorizedUsers[uname]
				if !ok {
					return false
				}
				return expectPwd == pwd
			},
		},
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
