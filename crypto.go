package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WechatMsgCrypt 结构体用于保存微信开放平台加解密所需的信息
type WechatMsgCrypt struct {
	token string
	appID string
	key   []byte
	iv    []byte
}

// NewWechatCrypt 方法用于创建 WechatMsgCrypt 实例
//
// token 为开发者在微信开放平台上设置的 Token，
// encodingAESKey 为开发者在微信开放平台上设置的 EncodingAESKey，
// appID 为企业号的 CorpId 或者 AppId
func NewWechatCrypt(token, encodingAESKey, appID string) (WechatMsgCrypt, error) {
	var key []byte
	var err error

	if key, err = base64.StdEncoding.DecodeString(encodingAESKey + "="); err != nil {
		return WechatMsgCrypt{}, err
	}

	if len(key) != 32 {
		return WechatMsgCrypt{}, errors.New("encodingAESKey invalid")
	}

	iv := key[:16]

	return WechatMsgCrypt{
		token,
		appID,
		key,
		iv,
	}, nil
}

// GetSignature 方法用于返回签名
func (w WechatMsgCrypt) GetSignature(timestamp, nonce, encrypt string) string {
	sl := []string{w.token, timestamp, nonce, encrypt}
	sort.Strings(sl)

	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))

	return fmt.Sprintf("%x", s.Sum(nil))
}

// Decrypt 方法用于对密文进行解密
//
// 返回解密后的消息，CropId/AppId, 或者错误信息
func (w WechatMsgCrypt) Decrypt(text string) ([]byte, string, error) {
	var message []byte
	var id string

	deciphered, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, "", err
	}

	c, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, "", err
	}

	cbc := cipher.NewCBCDecrypter(c, w.iv)
	cbc.CryptBlocks(deciphered, deciphered)

	decoded := PKCS7Decode(deciphered)

	buf := bytes.NewBuffer(decoded[16:20])

	var msgLen int32
	binary.Read(buf, binary.BigEndian, &msgLen)

	message = decoded[20 : 20+msgLen]
	id = string(decoded[20+msgLen:])

	return message, id, nil
}

// Encrypt 方法用于对明文进行加密
func (w WechatMsgCrypt) Encrypt(text string) (string, error) {
	message := []byte(text)

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(len(message))); err != nil {
		return "", err
	}

	msgLen := buf.Bytes()

	randBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		return "", err
	}

	messageBytes := bytes.Join([][]byte{randBytes, msgLen, message, []byte(w.appID)}, nil)

	encoded := PKCS7Encode(messageBytes)

	c, err := aes.NewCipher(w.key)
	if err != nil {
		return "", err
	}

	cbc := cipher.NewCBCEncrypter(c, w.iv)
	cbc.CryptBlocks(encoded, encoded)

	return base64.StdEncoding.EncodeToString(encoded), nil
}
