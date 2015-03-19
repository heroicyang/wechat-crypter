package crypto

import (
	"encoding/xml"
	"testing"
)

func TestDecryptMsg(t *testing.T) {
	token := "RMNlACHlV5ThzfRlVS4D4"
	corpID := "wx5823bf96d3bd56c7"
	encodingAESKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
	msgEncrypt := "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="

	wechatMsgCrypt, _ := NewWechatCrypto(token, encodingAESKey, corpID)

	_, corpIDDecrypted, err := wechatMsgCrypt.Decrypt(msgEncrypt)
	if err != nil {
		t.Fatal("Decrypt Message error:", err)
	}

	if corpIDDecrypted != corpID {
		t.Errorf("CorpID: want[%s], but actually[%s]", corpID, corpIDDecrypted)
	}
}

func TestEcryptMsg(t *testing.T) {
	token := "RMNlACHlV5ThzfRlVS4D4"
	corpID := "wx5823bf96d3bd56c7"
	encodingAESKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"

	msgText := `<xml>
		<ToUserName><![CDATA[wx5823bf96d3bd56c7]]></ToUserName>
		<FromUserName><![CDATA[heroic]]></FromUserName>
		<CreateTime>1426498001</CreateTime>
		<MsgType><![CDATA[text]]></MsgType>
		<Content><![CDATA[hello world]]></Content>
		<MsgId>000001</MsgId>
		<AgentID>3</AgentID>
		</xml>`

	wechatMsgCrypt, _ := NewWechatCrypto(token, encodingAESKey, corpID)

	msgEncrypt, err := wechatMsgCrypt.Encrypt(msgText)
	if err != nil {
		t.Fatal("Ecrypt Message error:", err)
	}

	message, corpIDDecrypted, err := wechatMsgCrypt.Decrypt(msgEncrypt)
	if err != nil {
		t.Fatal("Decrypt Message error:", err)
	}

	var recvMsg = struct {
		ToUserName   string
		FromUserName string
		CreateTime   int
		MsgType      string
		Content      string
		MsgID        uint64
		AgentID      int
	}{}

	err = xml.Unmarshal(message, &recvMsg)
	if err != nil {
		t.Fatal("Xml decoding error:", err)
	}

	if corpIDDecrypted != corpID {
		t.Errorf("CorpID: want[%s], but actually[%s]", corpID, corpIDDecrypted)
	}

	if recvMsg.Content != "hello world" {
		t.Errorf("Message: want[%s], but actually[%s]", "hello world", recvMsg.Content)
	}
}
