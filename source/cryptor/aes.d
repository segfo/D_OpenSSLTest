module cryptor.AES;
import core.exception;
import std.stdio;
import deimos.openssl.evp;
import cryptor.Random;
import cryptor.Exception;
import cryptor.Digest;
import std.digest.sha;
import util.Util;

// AES-CBCモード用インタフェース
interface IAES_CBC_CipherBase{
    public enum HashAlgorithm{MD5,SHA1,SHA224,SHA256,SHA512}
    /////////////////////////////////////
    // 暗号化用インタフェース
    /////////////////////////////////////
    // IV自動生成
    void    beginEncrypt(ubyte[] key);
    ubyte[]  putEncrypt(ubyte[] data);
    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endEncrypt();
    /////////////////////////////////////
    // 復号用インタフェース
    /////////////////////////////////////
    // IVは必ず要求
    void    beginDecrypt(ubyte[] iv,ubyte[] key);
    ubyte[]  putDecrypt(ubyte[] data);
    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endDecrypt();
    size_t  getBlockSize();
    ubyte[] getIV();
    void setHashIteration(ulong hashIterationCount);
    ulong getHashIteration();
    void setHashAlgorithmForKDF(HashAlgorithm algorithm);
    size_t getChunkSize();
}

// AES-CBCモードで暗号化する。
// 鍵長はサブクラスから指定する。
protected abstract class AES_CBC_CipherBase:IAES_CBC_CipherBase
{
    protected static immutable ulong HASH_ITERATION_COUNT=100_000;
    protected static immutable size_t INTERNAL_BUFFER_SIZE=4096;
    protected static immutable int OPENSSL_CALL_SUCCESS=1;
    protected static immutable int OPENSSL_CALL_FAILURE=0;
    private EVP_CIPHER_CTX ctx;
    private const EVP_CIPHER* mode;
    private const EVP_MD* digest;
    private ubyte[8] salt;
    private size_t BlockSize;
    private ubyte[] buffer;
    private ulong hashIterationCount=1; // キーのハッシュ反復回数

    this(const EVP_CIPHER* mode,const EVP_MD* digest,
            size_t internalBufferSize = INTERNAL_BUFFER_SIZE,
            ulong hashIterationCount = HASH_ITERATION_COUNT){
        if(hashIterationCount==0){
            hashIterationCount = HASH_ITERATION_COUNT;
        }
        this.mode = mode;
        this.digest = cast(EVP_MD*)digest;
        this.BlockSize = EVP_CIPHER_block_size(mode);

        if( internalBufferSize == 0 ){
            internalBufferSize = INTERNAL_BUFFER_SIZE;
        }
        this.buffer = new ubyte[internalBufferSize];
        this.hashIterationCount = hashIterationCount;
    }

    size_t getChunkSize(){
        return buffer.length;
    }

    size_t  getBlockSize(){
        return  BlockSize;
    }

    ////////////////////////////////////
    // 鍵導出関数のアルゴリズムを設定する
    ////////////////////////////////////
    alias extern(C) const(EVP_MD)* function() HASH_FUNCTION;
    private HASH_FUNCTION[] f=[
        HashAlgorithm.MD5:&EVP_md5,
        HashAlgorithm.SHA1:&EVP_sha1,
        HashAlgorithm.SHA224:&EVP_sha224,
        HashAlgorithm.SHA256:&EVP_sha256,
        HashAlgorithm.SHA512:&EVP_sha512
    ];
    void setHashAlgorithmForKDF(HashAlgorithm algorithm){
        if( 0 <= algorithm && algorithm < HashAlgorithm.max ){
            cast(EVP_MD*)digest = cast(EVP_MD*)f[algorithm]();
        }
    }
    // 鍵導出関数の繰り返し回数を設定
    void setHashIteration(ulong hashIterationCount){
        this.hashIterationCount = hashIterationCount;
    }
    // 鍵導出関数の繰り返し回数を取得
    ulong getHashIteration(){
        return this.hashIterationCount;
    }

    // ソルトを取得する
    ubyte[] getIV(){
        return salt;
    }

    // OpenSSLのリソース解放メソッド
    private void resourcesDespose(){
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    /////////////////////////////////////
    // 暗号化用インタフェース
    /////////////////////////////////////
    void    beginEncrypt(ubyte[] keyByte){
        EVP_CIPHER_CTX_init(&ctx);
        ubyte[EVP_MAX_KEY_LENGTH] key;
        ubyte[EVP_MAX_IV_LENGTH] iv;
        // https://www.openssl.org/docs/man1.0.1/crypto/EVP_BytesToKey.html
        // The salt parameter is used as a salt in the derivation:
        // it should point to an 8 byte buffer or NULL if no salt is used. 
        getRandom(salt);
        EVP_BytesToKey(mode,digest,salt.ptr,
            keyByte.ptr,keyByte.length,
            cast(uint)hashIterationCount,key.ptr,iv.ptr);
        EVP_EncryptInit_ex(&ctx, mode, null, key.ptr,iv.ptr);
    }
    
    ubyte[]  putEncrypt(ubyte[] data){
        int cipherLen;
        scope(failure){
            resourcesDespose();
        }
        if( data.length > this.buffer.length ){
            throw new RangeError("internal buffer out of range.");
        }
        int status = EVP_EncryptUpdate(&ctx, this.buffer.ptr, &cipherLen, data.ptr, cast(int)data.length);
        if(status == OPENSSL_CALL_FAILURE){
            throw new CryptorException("EVP_EncryptUpdate failure.");
        }
        return this.buffer[0..cipherLen];
    }

    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endEncrypt(){
        int cipherLen;
        scope(exit){
            resourcesDespose();
        }
        int succ = EVP_EncryptFinal_ex(&ctx,this.buffer.ptr,&cipherLen);
        if(succ == OPENSSL_CALL_FAILURE){
            throw new CryptorException("EVP_EncryptUpdate failure.");
        }
        return this.buffer[0..cipherLen];
    }

    /////////////////////////////////////
    // 復号用インタフェース
    /////////////////////////////////////
    void    beginDecrypt(ubyte[] salt,ubyte[] keyByte){
        EVP_CIPHER_CTX_init(&ctx);
        ubyte[EVP_MAX_KEY_LENGTH] key;
        ubyte[EVP_MAX_IV_LENGTH] iv;
        EVP_BytesToKey(mode,digest,salt.ptr,
            keyByte.ptr,keyByte.length,
            cast(uint)hashIterationCount,key.ptr,iv.ptr);
        EVP_DecryptInit_ex(&ctx, mode, null, key.ptr,iv.ptr);
    }
    
    ubyte[]  putDecrypt(ubyte[] data){
        int plainLen;
        scope(failure){
            resourcesDespose();
        }
        if( data.length > this.buffer.length ){
            throw new RangeError("internal buffer out of range.");
        }
        int status = EVP_DecryptUpdate(&ctx, this.buffer.ptr,&plainLen, data.ptr, cast(int)data.length);
        if(status == OPENSSL_CALL_FAILURE){
            throw new CryptorException("EVP_DecryptUpdate failure.");
        }
        return this.buffer[0..plainLen];
    }

    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endDecrypt(){
        int plainLen;
        scope(exit){
            resourcesDespose();
        }
        int succ = EVP_DecryptFinal_ex(&ctx,this.buffer.ptr,&plainLen);
        if(succ == OPENSSL_CALL_FAILURE){
            throw new CryptorException("EVP_DecryptUpdate failure.");
        }
        return this.buffer[0..plainLen];
    }
}

class AES256_CBC:AES_CBC_CipherBase
{
    this(ulong hashIterationCount=AES_CBC_CipherBase.HASH_ITERATION_COUNT,
        size_t internalBufferSize=AES_CBC_CipherBase.INTERNAL_BUFFER_SIZE){
        super(EVP_aes_256_cbc(),EVP_sha256(),internalBufferSize,hashIterationCount);
    }
}

class AES192_CBC:AES_CBC_CipherBase
{
    this(ulong hashIterationCount=AES_CBC_CipherBase.HASH_ITERATION_COUNT,
        size_t internalBufferSize=AES_CBC_CipherBase.INTERNAL_BUFFER_SIZE){
        super(EVP_aes_192_cbc(),EVP_sha256(),internalBufferSize,hashIterationCount);
    }
}

class AES128_CBC:AES_CBC_CipherBase
{
    this(ulong hashIterationCount=AES_CBC_CipherBase.HASH_ITERATION_COUNT,
        size_t internalBufferSize=AES_CBC_CipherBase.INTERNAL_BUFFER_SIZE){
        super(EVP_aes_128_cbc(),EVP_sha256(),internalBufferSize,hashIterationCount);
    }
}
