package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "os"
    "crypto/sha1"
    "math/big"
)

/** 生成密钥对 */
func GenerateEccKey() {

    // 1使用ecdsa生成密钥对
    privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
    if err != nil {
        panic(err)
    }
    // 2. 将私钥写入磁盘
    // 使用x509进行序列化
    dreText, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {
        panic(err)
    }
    // 使用pem编码
    block := pem.Block{
        Type:  "ecdsa private key",
        Bytes: dreText,
    }
    file, err := os.Create("./three/ecc_private.pem")
    // 编码并写入文件
    pem.Encode(file, &block)

    file.Close()

    //3. 将公钥写入磁盘
    //- 从私钥中得到公钥
    publicKey := privateKey.PublicKey
    //- 使用x509进行序列化
    dreText, err = x509.MarshalPKIXPublicKey(&publicKey)
    if err != nil {
        panic(err)
    }
    //- 将得到的切片字符串放入pem.Block结构体中
    block = pem.Block{
        Type:  "ecdsa public key",
        Bytes: dreText,
    }
    file, err = os.Create("./three/ecc_public.pem")
    if err != nil {
        panic(err)
    }
    pem.Encode(file, &block)
    file.Close()

}

/** ecc签名 私钥 */
func EccSignature(plainText []byte, privName string) (rText, sText []byte) {
    //1. 打开私钥文件, 将内容读出来 ->[]byte
    file, err := os.Open(privName)
    if err != nil {
        panic(err)
    }
    fileInfo, err := file.Stat()
    if err != nil {
        panic(err)
    }
    buf := make([]byte, fileInfo.Size())
    file.Read(buf)
    file.Close()
    //2. 使用pem进行数据解码 -> pem.Decode()
    block, _ := pem.Decode(buf)
    //3. 使用x509, 对私钥进行还原
    privateKey, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        panic(err)
    }
    //4. 对原始数据进行哈希运算 -> 散列值
    hashText := sha1.Sum(plainText)
    //5. 进行数字签名
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
    if err != nil {
        panic(err)
    }
    // 6. 对r, s内存中的数据进行格式化 -> []byte
    rText, err = r.MarshalText()
    if err != nil {
        panic(err)
    }
    sText, err = s.MarshalText()
    if err != nil {
        panic(err)
    }
    return
}

/** ecc签名认证 */
func EccVerify(plainText, rText, sText []byte, pubName string) bool {
    //1. 打开公钥文件, 将里边的内容读出 -> []byte
    file, err := os.Open(pubName)
    if err != nil{
        panic(err)
    }
    fileInfo, err := file.Stat()
    if err != nil {
        panic(err)
    }
    buf := make([]byte,fileInfo.Size())
    file.Read(buf)
    file.Close()
    //2. pem解码 -> pem.Decode()
    block, _ := pem.Decode(buf)
    //3. 使用x509对公钥还原
    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        panic(err)
    }
    //4. 将接口 -> 公钥
    publicKey := pubInterface.(*ecdsa.PublicKey)
    //5. 对原始数据进行哈希运算 -> 得到散列值
    hashText := sha1.Sum(plainText)
    // 将rText, sText -> int数据
    var r,s big.Int
    r.UnmarshalText(rText)
    s.UnmarshalText(sText)

    bl := ecdsa.Verify(publicKey, hashText[:], &r, &s)
    return bl
}
