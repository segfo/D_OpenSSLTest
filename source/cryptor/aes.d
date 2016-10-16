module cryptor.AES;
import core.exception;
import std.stdio;
import deimos.openssl.evp;
import cryptor.Random;
import cryptor.Exception;
import cryptor.Digest;
import std.digest.sha;
import util.Util;

// 実際に暗号化をする際はこのクラスのラッパーを呼ぶ。
// このインタフェースを直接使うのは面倒なので非推奨

// AES-CBCモード用インタフェース
interface IAES_CBC_Cryptor{
    /////////////////////////////////////
    // 暗号化用インタフェース
    /////////////////////////////////////
    // IV自動生成
    void    beginEncrypt(ubyte[] key);
    // データがブロック長の整数倍の長さでない場合はエラー
    ubyte[]  putEncrypt(ubyte[] data);
    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endEncrypt();
    /////////////////////////////////////
    // 復号用インタフェース
    /////////////////////////////////////
    // IVは必ず要求
    void    beginDecrypt(ubyte[] iv,ubyte[] key);
    // データがブロック長の整数倍の長さでない場合はエラー
    ubyte[]  putDecrypt(ubyte[] data);
    // データがブロック長の整数倍の長さでない場合はパディングされる
    ubyte[]  endDecrypt();
    size_t  getBlockSize();
    ubyte[] getIV();
}

// AES-CBCモードで暗号化する。
// 鍵長はサブクラスから指定する。
protected abstract scope class AES_CBC_Cryptor(T) if(isDigest!T):IAES_CBC_Cryptor
{
    private immutable int OPENSSL_CALL_SUCCESS=1;
    private immutable int OPENSSL_CALL_FAILURE=0;
    private EVP_CIPHER_CTX ctx;
    private const EVP_CIPHER* mode;
    private size_t BlockSize;
    private size_t KeyLength;
    private ubyte[] iv;
    private Hash!T digest;
    private ubyte[] buffer;

    this(const EVP_CIPHER* mode){
        this.mode = mode;
        this.digest = new Hash!T();
        this.BlockSize = EVP_CIPHER_block_size(mode);
        this.KeyLength = EVP_CIPHER_key_length(mode);
    }
    this(const EVP_CIPHER* mode ,ubyte[] internalBuffer){
        this(mode);
        this.buffer = internalBuffer;
    }

    this(const EVP_CIPHER* mode,size_t internalBufferSize){
        this(mode);
        // 繰り上げ
        internalBufferSize = (BlockSize*((internalBufferSize+BlockSize-1) / BlockSize));
        this.buffer = new ubyte[internalBufferSize];
    }

    size_t  getBlockSize(){
        return  BlockSize;
    }
    ubyte[] getIV(){
        return iv;
    }
    // OpenSSLのリソース解放メソッド
    private void resourcesDespose(){
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    /////////////////////////////////////
    // 暗号化用インタフェース
    /////////////////////////////////////
    // IV自動生成(ブロックサイズが違う可能性があるため、子クラスに任せる)
    // ※OpenSSLは16バイトのはずだが念のため
    void    beginEncrypt(ubyte[] key){
        EVP_CIPHER_CTX_init(&ctx);
        this.iv = new ubyte[BlockSize];
        getRandom(iv);
        ubyte[] keyHash = digest.getHash(key).rawDigest();
        if(keyHash.length<(KeyLength)){
            throw new CryptorException("key length error.");
        }else{
            keyHash = keyHash[0..KeyLength];
        }
        EVP_EncryptInit_ex(&ctx, mode, null, keyHash.ptr,iv.ptr);
    }
    
    // データがブロック長の整数倍の長さでない場合はエラー
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
    void    beginDecrypt(ubyte[] iv,ubyte[] key){
        EVP_CIPHER_CTX_init(&ctx);
        this.iv = iv;
        ubyte[] keyHash = digest.getHash(key).rawDigest();
        if(keyHash.length<(KeyLength)){
            throw new CryptorException("key length error.");
        }else{
            keyHash = keyHash[0..KeyLength];
        }
        EVP_DecryptInit_ex(&ctx, mode, null, keyHash.ptr,iv.ptr);
    }
    
    // データがブロック長の整数倍の長さでない場合はエラー
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

scope class AES256_CBC:AES_CBC_Cryptor!SHA256
{
    this(){
        this(4096);
    }
    this(ubyte[] internalBuffer){
        super(EVP_aes_256_cbc(),internalBuffer);
    }
    this(size_t internalBufferSize){
        super(EVP_aes_256_cbc(),internalBufferSize);
    }
}

scope class AES192_CBC:AES_CBC_Cryptor!SHA224
{
    this(){
        this(4096);
    }
    this(size_t internalBufferSize){
        super(EVP_aes_192_cbc(),internalBufferSize);
    }
}

scope class AES128_CBC:AES_CBC_Cryptor!SHA224
{
    this(){
        this(4096);
    }
    this(size_t internalBufferSize){
        super(EVP_aes_128_cbc(),internalBufferSize);
    }
}
