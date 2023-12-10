# ビルド方法

```
$ git submodule update --init --recursive
$ cd quicly
$ cmake .
$ make

$ cd ./deps/picotls/
$ cmake .
$ make
```


# 証明書の作成

```
$ openssl req  -nodes -new -x509  -keyout server.key -out server.cert
```


## とりあえず試す

```
$ git clone --recursive https://github.com/cloudflare/quiche
$ cd quiche/
$ cargo build
$ ./target/debug/quiche-client --http-version HTTP/3 --wire-version 1  --no-verify http://127.0.0.1:4433/hoge1.html http://127.0.0.1:4433/hoge2.html
```
