module app;
import std.stdio;
import std.traits;
import std.range;
import std.digest.sha;
import cryptor.Random;
import cryptor.Digest;
import cryptor.AES;
import util.Util;
import util.FileProvider;

void main()
{
    File f=File("C:\\Windows\\System32\\calc.exe","rb");
    scope(exit){f.close();}
/*    
    {
        scope auto c = new AES_CBC_Cipher!AES256_CBC(16);
        ubyte[] data = cast(ubyte[])"AAAABBBBCCCCDDDDFDDF";
        auto cipher = c.encrypt(cast(ubyte[])"key",data);
        dump(cipher);
        auto plain = c.decrypt(cast(ubyte[])"key",c.getIV(),cipher);
        dump(plain);
    }
    */
    {
        scope auto c = new AES_CBC_Cipher!AES256_CBC();
        c.encrypt(cast(ubyte[])"key",
            "openssltest.exe","crypt.ct");
        c.decrypt(cast(ubyte[])"key",
            "openssltest.exe","crypt.ct");
    }
    writeln("shutdown.");
}

scope class AES_CBC_Cipher(T){
    T prov;

    this(size_t bufSize){
        prov = new T(bufSize);
    }

    this(){
        prov = new T();
    }

    ubyte[] getIV(){
        return prov.getIV();
    }

    ubyte[] encrypt(ubyte[] key, ubyte[] plainText){
        prov.beginEncrypt(key);
        ubyte[] cipherText;
        foreach(ubyte[] chunk; chunks(plainText,prov.getChunkSize)){
            cipherText ~= prov.putEncrypt(chunk).dup();
        }
        cipherText ~= prov.endEncrypt().dup();
        return cipherText;
    }

    ubyte[] decrypt(ubyte[] key,ubyte[] iv, ubyte[] cipherText){
        prov.beginDecrypt(iv,key);
        ubyte[] plainText;
        foreach(ubyte[] chunk; chunks(cipherText ,prov.getChunkSize)){
            plainText ~= prov.putDecrypt(chunk).dup();
        }
        plainText ~= prov.endDecrypt().dup();
        return plainText;
    }
    
    void encrypt(ubyte[] key,string plainFileName,string cipherFileName){
        scope File plainFile = File(plainFileName,"rb");
        scope FileProvider bfw = new FileProviderWindows(cipherFileName);
        CipherDataHeader header = new CipherDataHeader(bfw);
        // 暗号化開始
        prov.beginEncrypt(key);
        header.writeHeader(prov.getIV());
        
        ubyte[] cipherText;
        ulong cryptedDataLength = 0;
        foreach(ubyte[] chunk; chunks(plainFile,prov.getChunkSize)){
            auto data = prov.putEncrypt(chunk);
            cryptedDataLength += data.length;
            bfw.write(data);
        }
        auto data = prov.endEncrypt();
        cryptedDataLength += data.length;
        bfw.write(data);
        header.headerFinalize(cryptedDataLength);
    }

    void decrypt(ubyte[] key,string plainFileName,string cipherFileName){
        File plainFile = File(plainFileName,"rb");
        writeln(cipherFileName);
        FileProvider bfw = new FileProviderWindows(cipherFileName);
        // 構造体を読み込む
        CipherDataHeader header = new CipherDataHeader(bfw);
        header.readHeader();
        // 
/*
        prov.beginDecrypt(iv,key);
        ubyte[] plainText;
        foreach(ubyte[] chunk; chunks(cipherFile ,prov.getChunkSize)){
            plainFile.rawWrite(prov.putDecrypt(chunk).dup());
        }
        plainFile.rawWrite(prov.endDecrypt().dup());
        */
    }
}

class CipherDataHeader{
    private immutable ubyte[6] sign = cast(ubyte[6])"CFT\xCC\xFF\x77";
    ulong cryptDataOffset;
    ulong ivOffset;
    ulong ivLength;
    ulong cryptDataLength; // 暗号化データの長さ
    ushort majorVersion = 1;
    ushort minorVersion = 1;

    // 暗号化データの長さが格納された位置 / 一時変数
    private ulong cryptDataLenPos;

    FileProvider fp;
    this(FileProvider fp){
        this.fp = fp;
    }

    void writeHeader(ubyte[] iv){
        ulong cryptDataOffsetPos;
        fp.write(sign);
        cryptDataOffsetPos = fp.getCurrentPosition();
        fp.write([cryptDataOffset]); // 予約領域
        fp.write([majorVersion]);
        fp.write([minorVersion]);
        cryptDataLenPos = fp.getCurrentPosition(); // 暗号化されたデータサイズは後で書く
        fp.write([cryptDataLength]); // 暗号化されたデータのサイズ
        ivLength = cast(ulong)iv.length; // ivの長さ
        fp.write([ivLength]);
        fp.write(iv);
        // ヘッダの構築はここまでで終了
        // ここより後は暗号化されたデータが書き込まれる
        // 書き込み準備を行う。
        cryptDataWritingPreparation(cryptDataOffsetPos);
    }

    // 暗号化データ書き込み準備を行う
    // ※暗号化データの位置の記録をする
    private void cryptDataWritingPreparation(ulong cryptDataOffsetPos){
        ulong encDataPos = fp.getCurrentPosition();
        // 暗号化データ開始位置の記録
        fp.pushSeek(cryptDataOffsetPos);
        fp.write([encDataPos]); // 暗号化データの位置をメモする
        fp.popSeek(); // ヘッダの終端へ戻す
    }
    // ヘッダのファイナライズを行う
    // ※暗号化データの長さの書き込み
    void headerFinalize(ulong cryptDataLength){
        fp.pushSeek(cryptDataLenPos);
        fp.write([cryptDataLength]);
        fp.popSeek();
    }
    
    void readHeader(){
        fp.seek(0);
        ubyte[6] sign;
        fp.read(sign);
        if(this.sign != sign){
            throw new Exception("invalid file type.");
        }
        cryptDataOffset = (cast(ulong[])fp.read(new ulong[1]))[0];
        majorVersion = (cast(ushort[])fp.read(new ushort[1]))[0];
        minorVersion = (cast(ushort[])fp.read(new ushort[1]))[0];
        cryptDataLength = (cast(ulong[])fp.read(new ulong[1]))[0];
        ivLength = (cast(uint[])fp.read(new uint[1]))[0];
        ubyte[] iv = cast(ubyte[]) fp.read(new ubyte[cast(uint)ivLength]);
    }
}

unittest
{
    
}