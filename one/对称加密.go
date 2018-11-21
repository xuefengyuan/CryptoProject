package main

import (
    "bytes"
    "crypto/cipher"
    "crypto/des"
    "crypto/aes"
)

/*
  1、填充函数

  2、如果最后一个分组字节数组不够，填充。

  3、如果最后一个字节数组刚好合适，添加一个新的数组

  4、填充的字节值等于缺少的字节数
*/
func paddingLastGroup(plainText []byte, bloclSize int) []byte {
    // 1、求出最后一个组中剩余的字节数
    padNum := bloclSize - len(plainText)%bloclSize
    // 2、创建新的切片，长度等于padNum,每个字节值byte[padNun]
    char := []byte{byte(padNum)}
    // 创建新的切片并初始化
    newPlain := bytes.Repeat(char, padNum)
    // 3、新创建的切片到原始明文的后边
    newText := append(plainText, newPlain...)
    return newText
}

/* 去掉明文填充的数据 */
func unPaddingLastGroup(plainText []byte) []byte {
    // 1、拿出切片中最后的一个字节
    length := len(plainText)
    lastChar := plainText[length-1]
    // 2、获取明文尾部填充的个数
    number := int(lastChar)
    // 3、去年明文的填充字节
    return plainText[:length-number]
}

/* DES加密 */
func DesEncrtpy(plainText, key []byte) []byte {
    // 1、创建一个底层使用DES的密码接口
    block, err := des.NewCipher(key)
    if err != nil {
        panic(err)
    }
    // 2、明文填充
    newText := paddingLastGroup(plainText, block.BlockSize())
    // 3、创建一个使用CBC的分组接口
    iv := []byte("12345678")
    blockMode := cipher.NewCBCEncrypter(block, iv)
    // 4、加密
    cipherText := make([]byte, len(newText))
    blockMode.CryptBlocks(cipherText, newText)
    return cipherText
}

/* DES解密 */
func DesDecrypt(cipherText, key []byte) []byte {

    // 1、创建一个底层使用DES的密码接口
    block, err := des.NewCipher(key)
    if err != nil {
        panic(err)
    }
    // 2、创建一个使用CBC的分组接口
    iv := []byte("12345678")
    blockMode := cipher.NewCBCDecrypter(block, iv)
    // 3、解密
    blockMode.CryptBlocks(cipherText, cipherText)

    // 4、去除明文填充
    plainText := unPaddingLastGroup(cipherText)
    return plainText

}

/* AES加密 */
func AesEncrtpy(plainText, key []byte) []byte {


    // 1、创建一个底层使用DES的密码接口
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    // 2、创建一个使用CBC的分组接口
    iv := []byte("12345678yhjkiokj")
    stream := cipher.NewCTR(block, iv)
    // 3、加密
    cipherText := make([]byte, len(plainText))
    stream.XORKeyStream(cipherText, plainText)
    return cipherText
}

/* AES解密 */
func AesDecrypt(cipherText, key []byte) []byte {

    // 1、创建一个底层使用DES的密码接口
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    // 2、创建一个使用CBC的分组接口
    iv := []byte("12345678yhjkiokj")
    stream := cipher.NewCTR(block, iv)
    // 3、解密
    stream.XORKeyStream(cipherText, cipherText)
    return cipherText
}
