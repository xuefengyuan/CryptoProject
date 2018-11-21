package main

import (
    _ "encoding/hex"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

/** 生成消息认证码 */
func Generatehamc(plainText, key []byte) string {
    // 1.创建哈希接口, 需要指定使用的哈希算法, 和秘钥
    myHash := hmac.New(sha256.New, key)

    // 2. 给哈希对象添加数据
    myHash.Write(plainText)
    // 3. 计算散列值
    hashText := myHash.Sum(nil)
    //return hashText
    // 需要网络通信，转成16进制，如果是不是网络通信，则直接使用byte切片
    myStr := hex.EncodeToString(hashText)
    return myStr
}

/** 验证消息认证码 */
func VerifyHamc(plainText, key []byte, hashText string) bool{
    // 把需要转码的16进制字符串转成byte切片
    hmac2,_ := hex.DecodeString(hashText)
    // 1.创建哈希接口, 需要指定使用的哈希算法, 和秘钥
    myHash := hmac.New(sha256.New, key)
    // 2. 给哈希对象添加数据
    myHash.Write(plainText)
    // 3. 计算散列值
    hmac1 := myHash.Sum(nil)
    // 4. 校验散列值
    return hmac.Equal(hmac2,hmac1)
}
