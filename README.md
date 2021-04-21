# firebase-auth REST API

## Dependencies

| Library |  dev-files | Description |
| :--- | :--- | :--- |
| libjson-c.so | libjson-c-dev | encode/decode json object |
| libcurl.so | libcurl4-gnutls-dev | http client |
| libpcre.so | libpcre3-dev | regular expression |

```
$ sudo apt-get update
$ (optional) sudo apt-get install build-essential  
$ sudo apt-get install libjson-c-dev libcurl4-gnutls-dev libpcre3-dev
```

\( libcurl:  use libcurl4-openssl-dev if OpenSSL flavour. \)

## Build

```bash
$ git clone https://github.com/chehw/firebase-auth.git
$ cd firebase-auth
$ make clean all

# tests:  tests/make.sh [module_name]
$ tests/make.sh firebase-auth
$ tests/make.sh regex
```



