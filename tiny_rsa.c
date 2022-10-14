#include "bn.h"
#include "tiny_rsa.h"


/** 
 * 快速幂取横运算, 用于rsa的加解密。
 * O(log n)
 * res = a ^ b % n
 * 
 **/
static void pow_mod_faster(struct bn* a, struct bn* b, struct bn* n, struct bn* res) {
    bignum_from_int(res, 1); /* r = 1 */

    struct bn tmpa;
    struct bn tmpb;
    struct bn tmp;
    bignum_assign(&tmpa, a);
    bignum_assign(&tmpb, b);

    /* debug
    char buf[1024];
    bignum_to_string(&tmpa, buf, sizeof(buf));
    printf("pow mmmmmmmmmm: %s \n", buf);
    bignum_to_string(&tmpb, buf, sizeof(buf));
    printf("pow eeeeeeeeee: %s \n", buf);
    bignum_to_string(n, buf, sizeof(buf));
    printf("pow nnnnnnnnnn: %s \n", buf);

    bignum_to_string(&tmpa, buf, sizeof(buf));
    printf("pow mod num: %s \n", buf);
    */

    bignum_mod(&tmpa, n, &tmp);
    bignum_assign(&tmpa, &tmp);
    //int i = 0;
    while (!bignum_is_zero(&tmpb)) {
        if (tmpb.array[0] & 1) {     /* if (b % 2) */
            bignum_mul(res, &tmpa, &tmp);  /*   r = r * a % n */
            bignum_mod(&tmp, n, res);
        }
        bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
        bignum_assign(&tmpb, &tmp);

        bignum_mul(&tmpa, &tmpa, &tmp);
        bignum_mod(&tmp, n, &tmpa);
        //i++;
    }
    //printf("count while is: %d", i);
    //bignum_mod(res, n, &tmp);
    //bignum_assign(res, &tmp);

    /* 原始慢速的幂取模
       struct bn tmp_zero;
       bignum_init(&tmp_zero);
       int i=0;
       while (LARGER == bignum_cmp(&tmpb, &tmp_zero)) {
       bignum_mul(res, &tmpa, &tmp);
       bignum_mod(&tmp, n, res);
       bignum_dec(&tmpb);
       i++;
       }
       printf("count while is: %d\n", i);
       */

    /* debug
    bignum_to_string(res, buf, sizeof(buf));
    printf("pow resssssssssss: %s \n", buf);
    */
}
//对齐
char *align_hexstr(char *in, char *buf, int buf_size) {
    int slen = strlen(in);
    int hplen = slen % (sizeof(DTYPE) * 2);
    hplen =  hplen > 0 ? ((sizeof(DTYPE) * 2) - hplen) : 0;
    if ((hplen+slen) > buf_size) {
        return NULL;
    }
    //结束符
    buf[hplen] = '\0';
    //前面由0填充
    for (hplen--; hplen > 0; hplen--) {
        buf[hplen] = '0';
    }
    return strcat(buf, in);
}

//初始化rsa
int init_tiny_rsa(p_tiny_rsa this, char *n_hexstr, int e, char *d_hexstr) {
    /*
    p_tiny_rsa ptrsa = &tiny_rsa{ n, e , d, 
        pub_encrypt, pub_decrypt, priv_encrypt, priv_decrypt,
    };
    */  
    //赋值公钥指数
    bignum_from_int(&(this->e), e);
    char buf[264];
    if ( NULL == align_hexstr(n_hexstr, buf, sizeof(buf))) {
        return -1;
    }
    //赋值共用模数
    bignum_from_string(&(this->n), buf, strlen(buf));
    if ( NULL == align_hexstr(d_hexstr, buf, sizeof(buf))) {
        return -1;
    }
    //赋值私钥指数
    bignum_from_string(&(this->d), buf, strlen(buf));
    return 0;
}


/** 
 * pkcs1 pad2的填充: EB = 00+BT+PS+00+D, 
 * BT 为02， PS为随机产生的非0x00的字节数据。
 * 只支持1024的rsa, D只能为127-3-8 = 117 个字节
 *
 */
char *pkcs1_pad2(char *in, char *buf, int *wlen) {
    buf[0] = 0x00;
    //BT
    buf[1] = 0x02;
    int i, rnum;
    //生成PS
    srand((unsigned int)time(NULL));
    for (i = 2; i < 10 ; ) {
        rnum = rand()&0xFF;
        if (rnum == 0x00) {
            continue;
        }
        buf[i] = rnum;
        //printf("debug padding char[%d]\n", rnum);
        i++;
    }
    buf[10] = 0x00;
    //D
    for (rnum = 0; in[rnum] != '\0'; rnum++) {
        buf[++i] = in[rnum];
        //printf("debug padding d [%c]\n", in[rnum]);
    }
    *wlen = i+1;
    //printf("debug padding wlen [%d]\n", *wlen);
    return buf;
}
//去掉padding
char *pkcs1_unpad2(char *in) {
    int i = 0, j;
    for (j=11; j<128; j++) {
        in[i++] = in[j];
        if ( '\0' == in[j] ) {
            break;
        }
    }
    return in;
}
//去掉bignum_to_string返回的hexstr格式的padding
char *pkcs1_unpad2_hexstr(char *in) {
    int i = 0, j;
    //bignum_to_string已经将前面为0的去掉了
    for (j=19; j<256; j++) {
        in[i++] = in[j];
        if ( '\0' == in[j] ) {
            break;
        }
    }
    return in;
}
//字符串转hex字符串格式
char *char2hexstr(char *inbuf, int in_len, char *outbuf) {
    int i, j=0;
    //printf("debug inbuf text [%s]\n", inbuf);
    for (i = 0; i < in_len; i++) {
        sprintf(outbuf+j, "%.02x", (unsigned char)inbuf[i]);
        j += 2;
    }
    outbuf[j] = '\0';
    char tbuf[264];
    //printf("debug outbuf text [%s]\n", outbuf);
    if ( NULL == align_hexstr(outbuf, tbuf, sizeof(tbuf))) {
        return NULL;
    }
    //printf("debug outbuf text [%s] end\n", outbuf);
    strcpy(outbuf, tbuf);
    return outbuf;
}
//hex字符串格式转字符串
int hexstr2char(char *in_hex, char *outbuf) {
    pkcs1_unpad2_hexstr(in_hex);
    int i=0, j=0;
    while (in_hex[i] != '\0') {
        //sscanf(&in_hex[i], "%2hhx", outbuf +j);
        outbuf[j] = (in_hex[i] % 32 + 9) % 25 * 16 + (in_hex[i+1] % 32 + 9) % 25;
        //printf("====%.02x\n", outbuf[j]);
        i += 2;
        j++;
    }
    outbuf[j] = '\0';
    return j;
}

//加密
static void encrypt(p_tiny_rsa this, char *in, char *hex_out, uint8_t pub) {
    char ibuf[128];
    char obuf[512];
    int plen;
    struct bn m; /* clear text message */
    struct bn c; /* cipher text */
    pkcs1_pad2(in, ibuf, &plen);
    //printf("debug ibuf [%d]\n", plen);
    char2hexstr(ibuf, plen, obuf);
    bignum_from_string(&m, obuf, strlen(obuf));
    //test int
    /*
    int x = 54321;
    bignum_init(&m);
    bignum_from_int(&m, x);
    bignum_to_string(&m, obuf, sizeof(obuf));
    printf("m = %s \n", obuf);
    */
    //加密
    pow_mod_faster(&m, 
            pub == 0 ? &(this->d) : &(this->e), 
            &(this->n), &c);
    bignum_to_string(&c, hex_out, 512);
    //hexstr2char(obuf, out);
}
//解密
static void decrypt(p_tiny_rsa this, char *hex_in, char *out, uint8_t pub) {
    char buf[512];
    //char obuf[512];
    struct bn m; /* clear text message */
    struct bn c; /* cipher text */
    /*
    char2hexstr(hex_in, strlen(hex_in), obuf);
    bignum_from_string(&c, obuf, strlen(obuf));
    */
    if ( NULL == align_hexstr(hex_in, buf, sizeof(buf))) {
        return ;
    }
    bignum_from_string(&c, buf, strlen(buf));
    //解密
    pow_mod_faster(&c, 
            pub == 0 ? &(this->d) : &(this->e), 
            &(this->n), &m);
    bignum_to_string(&m, buf, 512);
    hexstr2char(buf, out);
}

//公钥加密
void pub_encrypt(p_tiny_rsa this, char *in, char *hex_out) {
    encrypt(this, in, hex_out, 1);
}

//公钥解密
void pub_decrypt(p_tiny_rsa this, char *in, char *out) {
    decrypt(this, in, out, 1);
}
//私钥加密
void priv_encrypt(p_tiny_rsa this, char *in, char *hex_out) {
    encrypt(this, in, hex_out, 0);
}
//私钥解密
void priv_decrypt(p_tiny_rsa this, char *in, char *out) {
    decrypt(this, in, out, 0);
}
