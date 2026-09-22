package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const ( argonMemory=64*1024; argonIterations=3; argonParallelism=2; argonKeyLen=32 )

func RandomToken(n int) (string,error) { b:=make([]byte,n); if _,e:=rand.Read(b);e!=nil{return "",e}; return base64.RawURLEncoding.EncodeToString(b),nil }
func RandomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func SHA256String(v string) string { h:=sha256.Sum256([]byte(v)); return base64.RawURLEncoding.EncodeToString(h[:]) }

func HashPassword(password string)(string,error){
	if len(password)<12{return "",errors.New("password must contain at least 12 characters")}
	salt:=make([]byte,16); if _,e:=rand.Read(salt);e!=nil{return "",e}
	hash:=argon2.IDKey([]byte(password),salt,argonIterations,argonMemory,argonParallelism,argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",argonMemory,argonIterations,argonParallelism,base64.RawStdEncoding.EncodeToString(salt),base64.RawStdEncoding.EncodeToString(hash)),nil
}

func VerifyPassword(encoded,password string) bool {
	p:=strings.Split(encoded,"$"); if len(p)!=6||p[1]!="argon2id"||p[2]!="v=19"{return false}
	var m,t,par uint64
	for _,item:=range strings.Split(p[3],","){kv:=strings.SplitN(item,"=",2);if len(kv)!=2{return false};n,e:=strconv.ParseUint(kv[1],10,32);if e!=nil{return false};switch kv[0]{case"m":m=n;case"t":t=n;case"p":par=n;default:return false}}
	salt,e:=base64.RawStdEncoding.DecodeString(p[4]);if e!=nil{return false}; expected,e:=base64.RawStdEncoding.DecodeString(p[5]);if e!=nil{return false}
	actual:=argon2.IDKey([]byte(password),salt,uint32(t),uint32(m),uint8(par),uint32(len(expected)))
	return subtle.ConstantTimeCompare(expected,actual)==1
}
