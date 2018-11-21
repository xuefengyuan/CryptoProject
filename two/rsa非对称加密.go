package main

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "os"
    "fmt"
    "crypto/sha256"
    "encoding/hex"
)

// 生成rsa的密钥对, 并且保存到磁盘文件中
func GenerateRsaKey(keySize int) {
    // 这里判断文件还不靠谱，因为对应生成的密钥长度可能会变
    rsaPrivatePath := "./two/rsa_private.pem"
    rsapublicPath := "./two/rsa_public.pem"

    privateIsExist, _ := IsExistFile(rsaPrivatePath)
    publicIsExist, _ := IsExistFile(rsapublicPath)
    // 如果 私钥和公钥都存在了，就不再创建了
    if privateIsExist == true && publicIsExist == true {
        fmt.Println("公钥和私钥文件都存在")
        return
    }

    // 1. 使用rsa中的GenerateKey方法生成私钥
    privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
    if err != nil {
        panic(err)
    }
    // 2. 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
    derText := x509.MarshalPKCS1PrivateKey(privateKey)
    // 3. 要组织一个pem.Block(base64编码)
    block := pem.Block{
        Type : "rsa private key", // 这个地方写个字符串就行
        Bytes : derText,
    }
    // 4. pem编码
    file, err := os.Create(rsaPrivatePath)
    if err != nil {
        panic(err)
    }
    pem.Encode(file, &block)
    file.Close()

    // ============ 公钥 ==========
    // 1. 从私钥中取出公钥
    publicKey := privateKey.PublicKey
    // 2. 使用x509标准序列化
    derstream, err := x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        panic(err)
    }
    // 3. 将得到的数据放到pem.Block中
    block = pem.Block{
        Type : "rsa public key",
        Bytes : derstream,
    }
    // 4. pem编码
    file, err  = os.Create(rsapublicPath)
    if err != nil {
        panic(err)
    }
    pem.Encode(file, &block)
    file.Close()
}


/** 判断文件是否存在 */
func IsExistFile(path string) (bool, error) {
   // 使用os的Stat方法返回的错误值进行判断
   _, err := os.Stat(path)
   // err等于空，则表示文件存在
   if err == nil {
       return true, nil
   }
   // 返回的错误类型使用os.IsNotExist()判断为true,说明文件或文件夹不存在
   if os.IsExist(err) {
       return false, nil
   }
   // 其它类型的错误，表示不确定文件是否存在
   return false, err
}

/** RSA公钥加密 */
func RSAPublicEncrypt(plainText []byte, fileName string) []byte {

   // 1、打开公钥文件
   file, err := os.Open(fileName)
   if err != nil {
       panic(err)
   }
   fileInfo, err := file.Stat()
   if err != nil {
       panic(err)
   }
   // 创建一个byte数组，长度为文件长度
   buf := make([]byte, fileInfo.Size())
   file.Read(buf)
   file.Close()
   // 2、pem解码
   block, _ := pem.Decode(buf)

   pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
   if err != nil {
       panic(err)
   }
   // 类型判断，是否是RSA的公钥
   pubKey := pubInterface.(*rsa.PublicKey)
   // 3、使用公钥加密
   cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
   if err != nil {
       panic(err)
   }
   return cipherText
}

/** RSA私钥解密 */
func RSAPrivateDecrypt(cipherText []byte, fileName string) []byte {

   // 1、打开私钥文件
   file, err := os.Open(fileName)
   if err != nil {
       panic(err)
   }
   fileInfo, err := file.Stat()
   if err != nil {
       panic(err)
   }
   // 创建一个byte数组，长度为文件长度
   buf := make([]byte, fileInfo.Size())
   file.Read(buf)
   file.Close()
   // 2、pem解码
   block, _ := pem.Decode(buf)
   privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
       panic(err)
   }
   // 3、使用私钥解密
   plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherText)
   if err != nil {
       panic(err)
   }
   return plainText
}

/** 哈希加密 */
func HasEncrypt(plainText []byte) string {
    // 获取sha接口
    mySha := sha256.New()
    // 写入数据
    mySha.Write(plainText)
    // 计算结果
    res := mySha.Sum(nil)
    // 转换成16进制形式
    myStr := hex.EncodeToString(res)
    return myStr
}