#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} SHA256_CTX;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2) ^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ROTR(x,11)^ROTR(x,25))
#define SIG0(x)(ROTR(x,7) ^ROTR(x,18)^((x)>>3))
#define SIG1(x)(ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *data) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i;
    for(i=0;i<16;i++){
        m[i] =((uint32_t)data[i*4+0])<<24
              |((uint32_t)data[i*4+1])<<16
              |((uint32_t)data[i*4+2])<<8
              |((uint32_t)data[i*4+3]);
    }
    for(;i<64;i++)
        m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];
    c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];
    g=ctx->state[6];h=ctx->state[7];
    for(i=0;i<64;i++){
        t1=h+EP1(e)+CH(e,f,g)+K[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;
        d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;
    ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;
    ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx){
    ctx->count=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len){
    size_t i;
    for(i=0;i<len;i++){
        ctx->buf[ctx->count%64]=data[i];
        ctx->count++;
        if(ctx->count%64==0)
            sha256_transform(ctx,ctx->buf);
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t *hash){
    uint32_t i=ctx->count%64;
    ctx->buf[i++]=0x80;
    if(i>56){
        while(i<64)ctx->buf[i++]=0;
        sha256_transform(ctx,ctx->buf);
        i=0;
    }
    while(i<56)ctx->buf[i++]=0;
    uint64_t bits=ctx->count*8;
    ctx->buf[56]=(bits>>56)&0xff;ctx->buf[57]=(bits>>48)&0xff;
    ctx->buf[58]=(bits>>40)&0xff;ctx->buf[59]=(bits>>32)&0xff;
    ctx->buf[60]=(bits>>24)&0xff;ctx->buf[61]=(bits>>16)&0xff;
    ctx->buf[62]=(bits>> 8)&0xff;ctx->buf[63]= bits     &0xff;
    sha256_transform(ctx,ctx->buf);
    for(i=0;i<4;i++){
        hash[i+0] =(ctx->state[0]>>(24-i*8))&0xff;
        hash[i+4] =(ctx->state[1]>>(24-i*8))&0xff;
        hash[i+8] =(ctx->state[2]>>(24-i*8))&0xff;
        hash[i+12]=(ctx->state[3]>>(24-i*8))&0xff;
        hash[i+16]=(ctx->state[4]>>(24-i*8))&0xff;
        hash[i+20]=(ctx->state[5]>>(24-i*8))&0xff;
        hash[i+24]=(ctx->state[6]>>(24-i*8))&0xff;
        hash[i+28]=(ctx->state[7]>>(24-i*8))&0xff;
    }
}

static void sha256_to_hex(const uint8_t *hash, char *out){
    int i;
    for(i=0;i<32;i++) sprintf(out+i*2,"%02x",hash[i]);
    out[64]='\0';
}

#endif
