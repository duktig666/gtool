// description:
// @author renshiwei
// Date: 2022/7/21 20:53

package cryptor

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDESCrypto(t *testing.T) {
	key := []byte("12345678")
	src := []byte("ab34ac553a9d1980846efacc8d73abc79dd6ebafd93cd64db21e0ced2a6595a8d9fd8131e0aad021259d429f48ebf944")

	// ECB 加密
	cipher := DesECBEncrypt(src, key)

	// 转base64
	bs64 := base64.StdEncoding.EncodeToString(cipher)
	fmt.Println(bs64)
	fmt.Println(len(bs64))

	// 转回byte
	bt, err := base64.StdEncoding.DecodeString(bs64)
	assert.NoError(t, err)

	// ECB 解密
	str := DesECBDecrypter(bt, key)
	fmt.Println(string(str))
}

func TestAESECBCrypto(t *testing.T) {
	key := []byte("1234567812345678")
	src := []byte("ab34ac553a9d1980846efacc8d73abc79dd6ebafd93cd64db21e0ced2a6595a8d9fd8131e0aad021259d429f48ebf944")

	// ECB 加密
	cipher := AesEncryptByECB(src, key)

	fmt.Println(string(cipher))

	// ECB 解密
	str := AesDecryptByECB(cipher, key)
	fmt.Println(string(str))
}
