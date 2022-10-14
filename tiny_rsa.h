#include "bn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//tiny_rsa定义(只支持1024位)
typedef struct tiny_rsa {
    //公私钥中共用模数
    struct bn n;
    //公钥指数
    struct bn e;
    //私钥指数
    struct bn d;
    /** methods **/
    //公钥加密
    void (*pub_encrypt)(struct tiny_rsa * this, char *in, char *out);
    //公钥解密
    void (*pub_decrypt)(struct tiny_rsa * this, char *in, char *out);
    //私钥加密
    void (*priv_encrypt)(struct tiny_rsa * this, char *in, char *out);
    //私钥解密
    void (*priv_decrypt)(struct tiny_rsa * this, char *in, char *out);
} tiny_rsa, *p_tiny_rsa;

//初始化rsa
int init_tiny_rsa(p_tiny_rsa this, char *n_hexstr, int e, char *d_hexstr);
//公钥加密
void pub_encrypt(p_tiny_rsa this, char *in, char *hex_out);
//公钥解密
void pub_decrypt(p_tiny_rsa this, char *hex_in, char *out);
//私钥加密
void priv_encrypt(p_tiny_rsa this, char *in, char *hex_out);
//私钥解密
void priv_decrypt(p_tiny_rsa this, char *hex_in, char *out);
//hexstr转char, 返回outbuf的字符串长度
int hexstr2char(char *in_hex, char *outbuf);
