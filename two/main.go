package main

import (
    "fmt"
)

func main() {
    GenerateRsaKey(4096)
    src := []byte("《无双》讲述了以代号“画家”（周润发 饰）为首的犯罪团伙，掌握了制造伪钞技术，难辨真伪，并在全球进行交易获取利益，引起警方高度重视。")
    cipherText := RSAPublicEncrypt(src, "./two/rsa_public.pem")
    plainText := RSAPrivateDecrypt(cipherText, "./two/rsa_private.pem")
    fmt.Println(string(plainText))

    myStr := HasEncrypt(src)
    fmt.Println(myStr)
}



