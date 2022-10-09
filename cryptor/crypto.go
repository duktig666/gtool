// description: 加解密工具
// @author renshiwei
// Date: 2022/7/21 20:47

package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
)

//pkcs5补码算法
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

//pkcs5减码算法
func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// --------------AES 加密 -----------------

// AesEncryptByECBBase64
//---------------AES ECB加密 Base64--------------------
// data: 明文数据
// key: 密钥字符串
// 返回密文数据
func AesEncryptByECBBase64(data, key string) string {
	// 判断key长度
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		panic("key长度必须是 16、24、32 其中一个")
	}
	// 密钥和待加密数据转成[]byte
	originByte := []byte(data)
	keyByte := []byte(key)
	// 创建密码组，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取密钥长度
	blockSize := block.BlockSize()
	// 补码
	originByte = pkcs5Padding(originByte, blockSize)
	// 创建保存加密变量
	encryptResult := make([]byte, len(originByte))
	// CEB是把整个明文分成若干段相同的小段，然后对每一小段进行加密
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encryptResult[bs:be], originByte[bs:be])
	}
	return base64.StdEncoding.EncodeToString(encryptResult)
}

// AesDecryptByECBBase64
//---------------AES ECB解密 Base64--------------------
// data: 密文数据
// key: 密钥字符串
// 返回明文数据
func AesDecryptByECBBase64(data, key string) string {
	// 判断key长度
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		panic("key长度必须是 16、24、32 其中一个")
	}
	// 反解密码base64
	originByte, _ := base64.StdEncoding.DecodeString(data)
	// 密钥和待加密数据转成[]byte
	keyByte := []byte(key)
	// 创建密码组，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取密钥长度
	blockSize := block.BlockSize()
	// 创建保存解密变量
	decrypted := make([]byte, len(originByte))
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], originByte[bs:be])
	}
	// 解码
	return string(pkcs5UnPadding(decrypted))
}

// AesEncryptByECB
//---------------AES ECB加密--------------------
// data: 明文数据
// key: 密钥字符串
// 返回密文数据
func AesEncryptByECB(data, key []byte) []byte {
	// 判断key长度
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		panic("key长度必须是 16、24、32 其中一个")
	}
	// 密钥和待加密数据转成[]byte
	originByte := data
	keyByte := key
	// 创建密码组，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取密钥长度
	blockSize := block.BlockSize()
	// 补码
	originByte = pkcs5Padding(originByte, blockSize)
	// 创建保存加密变量
	encryptResult := make([]byte, len(originByte))
	// CEB是把整个明文分成若干段相同的小段，然后对每一小段进行加密
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encryptResult[bs:be], originByte[bs:be])
	}
	//return base64.StdEncoding.EncodeToString(encryptResult)
	return encryptResult
}

// AesDecryptByECB
//---------------AES ECB解密--------------------
// data: 密文数据
// key: 密钥字符串
// 返回明文数据
func AesDecryptByECB(data, key []byte) []byte {
	// 判断key长度
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		panic("key长度必须是 16、24、32 其中一个")
	}
	// 反解密码base64
	//originByte, _ := base64.StdEncoding.DecodeString(data)
	originByte := data
	// 密钥和待加密数据转成[]byte
	keyByte := key
	// 创建密码组，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取密钥长度
	blockSize := block.BlockSize()
	// 创建保存解密变量
	decrypted := make([]byte, len(originByte))
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], originByte[bs:be])
	}
	// 解码
	return pkcs5UnPadding(decrypted)
}

// --------------AES 加密结束 -----------------

// --------------DES 加密 -----------------

// DesECBEncrypt
//---------------DES ECB加密--------------------
// data: 明文数据
// key: 密钥字符串
// 返回密文数据
func DesECBEncrypt(data, key []byte) []byte {
	//NewCipher创建一个新的加密块
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	bs := block.BlockSize()
	// pkcs5填充
	data = pkcs5Padding(data, bs)
	if len(data)%bs != 0 {
		return nil
	}

	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		//Encrypt加密第一个块，将其结果保存到dst
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return out
}

// DesECBDecrypter
//---------------DES ECB解密--------------------
// data: 密文数据
// key: 密钥字符串
// 返回明文数据
func DesECBDecrypter(data, key []byte) []byte {
	//NewCipher创建一个新的加密块
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil
	}

	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		//Encrypt加密第一个块，将其结果保存到dst
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}

	// pkcs5填充
	out = pkcs5UnPadding(out)

	return out
}

// DesCBCEncrypt
//---------------DES CBC加密--------------------
// data: 明文数据
// key: 密钥字符串
// iv:iv向量
// 返回密文数据
func DesCBCEncrypt(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	// pkcs5填充
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cryptText, data)
	return cryptText
}

// DesCBCDecrypter
//---------------DES CBC解密--------------------
// data: 密文数据
// key: 密钥字符串
// iv:iv向量
// 返回明文数据
func DesCBCDecrypter(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	cryptText := make([]byte, len(data))
	blockMode.CryptBlocks(cryptText, data)
	// pkcs5填充
	cryptText = pkcs5UnPadding(cryptText)

	return cryptText
}

// DesCTREncrypt
//---------------DES CTR加密--------------------
// data: 明文数据
// key: 密钥字符串
// iv:iv向量
// 返回密文数据
func DesCTREncrypt(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	// pkcs5填充
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewCTR(block, iv)
	blockMode.XORKeyStream(cryptText, data)
	return cryptText
}

// DesCTRDecrypter
//---------------DES CTR解密--------------------
// data: 密文数据
// key: 密钥字符串
// iv:iv向量
// 返回明文数据
func DesCTRDecrypter(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	blockMode := cipher.NewCTR(block, iv)
	cryptText := make([]byte, len(data))
	blockMode.XORKeyStream(cryptText, data)

	// pkcs5填充
	cryptText = pkcs5UnPadding(cryptText)

	return cryptText
}

// DesOFBEncrypt
//---------------DES OFB加密--------------------
// data: 明文数据
// key: 密钥字符串
// iv:iv向量
// 返回密文数据
func DesOFBEncrypt(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	// pkcs5填充
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewOFB(block, iv)
	blockMode.XORKeyStream(cryptText, data)
	return cryptText
}

// DesOFBDecrypter
//---------------DES OFB解密--------------------
// data: 密文数据
// key: 密钥字符串
// iv:iv向量
// 返回明文数据
func DesOFBDecrypter(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	blockMode := cipher.NewOFB(block, iv)
	cryptText := make([]byte, len(data))
	blockMode.XORKeyStream(cryptText, data)

	// pkcs5填充
	cryptText = pkcs5UnPadding(cryptText)

	return cryptText
}

// DesCFBEncrypt
//---------------DES CFB加密--------------------
// data: 明文数据
// key: 密钥字符串
// iv:iv向量
// 返回密文数据
func DesCFBEncrypt(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	// pkcs5填充
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewCFBDecrypter(block, iv)
	blockMode.XORKeyStream(cryptText, data)
	return cryptText
}

// DesCFBDecrypter
//---------------DES CFB解密--------------------
// data: 密文数据
// key: 密钥字符串
// iv:iv向量
// 返回明文数据
func DesCFBDecrypter(data, key, iv []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}

	blockMode := cipher.NewCFBEncrypter(block, iv)
	cryptText := make([]byte, len(data))
	blockMode.XORKeyStream(cryptText, data)

	// pkcs5填充
	cryptText = pkcs5UnPadding(cryptText)

	return cryptText
}
