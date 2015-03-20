# wechat-crypto
微信开放平台加解密库 (Golang)

## Usage

```bash
$ go get github.com/heroicyang/wechat-crypto
```

```go
import "github.com/heroicyang/wechat-crypto"

token := "RMNlACHlV5ThzfRlVS4D4"
corpID := "wx5823bf96d3bd56c7"
encodingAESKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"

wechatMsgCrypt, _ := crypto.NewWechatCrypto(token, encodingAESKey, corpID)
message, corpID, err := wechatMsgCrypt.Decrypt("msgEncrypt")
```

## Doc
[http://godoc.org/github.com/heroicyang/wechat-crypto](http://godoc.org/github.com/heroicyang/wechat-crypto)
