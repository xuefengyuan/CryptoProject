package main

import "fmt"

func main() {
    fmt.Println("des 加解密")
    key := []byte("1234abcd")
    src := []byte("Block接口代表一个使用特定密钥的底层块加/解密器。它提供了加密和解密独立数据块的能力。")
    cipherText := DesEncrtpy(src, key)
    plainText := DesDecrypt(cipherText, key)

    fmt.Printf("Des 解密后的数据： %s\n", string(plainText))

    fmt.Println("aes 加解密 ctr模式 ... ")

    key1 :=[]byte("1234abcd1234abcd")
    cipherText = AesEncrtpy(src,key1)
    plainText = AesDecrypt(cipherText,key1)
    fmt.Printf("Aes 解密后的数据： %s\n", string(plainText))
}
