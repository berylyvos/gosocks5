## Usage

**No Authentication**

```
> go run ./cmd/main.go [-m noauth]
```

**Uername/Password**

```
> go run ./cmd/main.go -m pwd
```

### Client

#### curl

```
> curl --proxy socks5://shingo:gnix.com@localhost:1080 https://github.com/berylyvos/gosocks5 -v 
*   Trying 127.0.0.1:1080...
* SOCKS5 connect to IPv4 20.205.243.166:443 (locally resolved)
* SOCKS5 request granted.
* Connected to (nil) (127.0.0.1) port 1080 (#0)
* ALPN: offers h2
* ALPN: offers http/1.1
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Finished (20):
...
< HTTP/2 200 
< server: GitHub.com
< date: Thu, 23 Nov 2023 14:40:50 GMT
< content-type: text/html; charset=utf-8
...
```

#### Chrome & SwitchyOmega proxy

**OmegaProfile_proxy.pac**

```JavaScript
var FindProxyForURL = function(init, profiles) {
    return function(url, host) {
        "use strict";
        var result = init, scheme = url.substr(0, url.indexOf(":"));
        do {
            result = profiles[result];
            if (typeof result === "function") result = result(url, host, scheme);
        } while (typeof result !== "string" || result.charCodeAt(0) === 43);
        return result;
    };
}("+proxy", {
    "+proxy": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";
        return "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";
    }
});
```