package main

import "fmt"

func main() {
    str := []byte("满屏的横肉脸，大肚子。男主角就不能找个稍微形象好点的？连女主角都不怎么地！ 剧情：中规中矩，时长158分40秒一点都没浪费，不过废戏实在太多，且无聊。")
    key := []byte("abcdefghijk123")
    hamc1 := Generatehamc(str, key)
    isOk := VerifyHamc(str, key, hamc1)
    fmt.Println(isOk)
    fmt.Println("=============")
    sigText := SignatureRSA(str, "./three/rsa_private.pem")
    isOk = VerifyRsa(str, sigText, "./three/rsa_public.pem")
    fmt.Println(isOk)

    fmt.Println("=============")
    GenerateEccKey()
    rText,sText:=EccSignature(str,"./three/ecc_private.pem")
    str = []byte("满屏的横肉脸，大肚子。男主角就不能找个稍微形象好点的？连女主角都不怎么地！剧情：中规中矩，时长158分40秒一点都没浪费，不过废戏实在太多，且无聊。")
    isOk = EccVerify(str,rText,sText,"./three/ecc_public.pem")
    fmt.Println(isOk)
}
