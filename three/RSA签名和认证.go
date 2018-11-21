package main

import (
    "os"
    "encoding/pem"
    "crypto/x509"
    "crypto/sha512"
    "crypto/rsa"
    "crypto/rand"
    "crypto"
)

// RSA签名 - 私钥
func SignatureRSA(plainText []byte, fileName string) []byte{
    // 1. 打开磁盘的私钥文件
    file, err := os.Open(fileName)
    if err != nil {
        panic(err)
    }
    fileInfo, err := file.Stat()
    if err != nil {
        panic(err)
    }
    buf := make([]byte, fileInfo.Size())
    // 2. 将私钥文件中的内容读出
    file.Read(buf)
    file.Close()

    // 3. 使用pem对数据解码, 得到了pem.Block结构体变量
    block, _ := pem.Decode(buf)
    // 4. x509将数据解析成私钥结构体 -> 得到了私钥
    privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        panic(err)
    }
    // 5. 创建一个哈希对象 -> md5/sha1
    myhash := sha512.New()
    // 6. 给哈希对象添加数据
    myhash.Write(plainText)

    // 7. 计算哈希值
    hashText := myhash.Sum(nil)
    // 8. 使用rsa中的函数对散列值签名
    sigText,err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, hashText)
    if err != nil {
        panic(err)
    }
    return sigText
}

// RSA签名验证
func VerifyRsa(plainText,sigText []byte,fileName string) bool  {
    // 1. 打开公钥文件, 将文件内容读出 - []byte
    file, err := os.Open(fileName)
    if err != nil {
        panic(err)
    }
    fileInfo, err := file.Stat()
    if err != nil {
        panic(err)
    }
    buf := make([]byte, fileInfo.Size())
    // 将私钥文件中的内容读出
    file.Read(buf)
    file.Close()

    // 2. 使用pem解码 -> 得到pem.Block结构体变量
    block, _ := pem.Decode(buf)
    // 3. 使用x509对pem.Block中的Bytes变量中的数据进行解析 ->  得到一接口
    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        panic(err)
    }
    // 4. 进行类型断言 -> 得到了公钥结构体
    publicKey := pubInterface.(*rsa.PublicKey)
    // 5. 对原始消息进行哈希运算(和签名使用的哈希算法一致) -> 散列值
    // 1. 创建哈希接口
    myHash := sha512.New()
    //hashText := sha512.Sum512(plainText)
    // 2. 添加数据
    myHash.Write(plainText)
    // 3. 哈希运算
    hashText := myHash.Sum(nil)
    // 6. 签名认证 - rsa中的函数
    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashText[:], sigText)
    if err == nil {
        return true
    }
    return false
}
