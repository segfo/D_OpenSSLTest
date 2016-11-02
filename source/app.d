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
    try{
        scope auto c = new AES_CBC_Cipher!AES256_CBC();

        c.encrypt(cast(ubyte[])"key",
            "dub.json",
            "crypt.ct",&progressCallback);
            
        writeln();
        c.decrypt(cast(ubyte[])"key",
            "decode.bin",
            "crypt.ct",&progressCallback);
    }catch(Exception ex){
        writeln(ex.msg);
    }
    writefln("\nshutdown.");
}

void progressCallback(ulong processedSize,ulong totalSize){
    writef("processing ... %d %%\r",(processedSize*100) / totalSize);
}

scope class AES_CBC_Cipher(T){
    T prov;
    this(ulong iteration,size_t bufSize=0){
        prov = new T(iteration,bufSize);
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
    
    private void defaultCallback(ulong processedSize ,ulong  totalSize){}

    void encrypt(ubyte[] key,string plainFileName,string cipherFileName, void function(ulong,ulong) progressCallback=&this.defaultCallback){
        scope File plainFile = File(plainFileName,"rb");
        scope FileProvider bfw = new FileProviderWindows(cipherFileName);
        CipherDataHeader header = new CipherDataHeader(bfw);
        // 暗号化開始
        prov.beginEncrypt(key);
        header.writeHeader(prov.getIV(),prov.getHashIteration());
        
        ubyte[] cipherText;
        ulong cryptedDataLength = 0;
        ulong plainFileSize = plainFile.size();
        foreach(ubyte[] chunk; chunks(plainFile,prov.getChunkSize)){
            progressCallback(cryptedDataLength,plainFileSize);
            auto data = prov.putEncrypt(chunk);
            cryptedDataLength += data.length;
            bfw.write(data);
        }
        auto data = prov.endEncrypt();
        cryptedDataLength += data.length;
        bfw.write(data);
        header.headerFinalize(cryptedDataLength);
        progressCallback(cryptedDataLength,plainFileSize);
    }

    void decrypt(ubyte[] key,string plainFileName,string cipherFileName,void function(ulong,ulong) progressCallback=&this.defaultCallback){
        File plainFile = File(plainFileName,"wb");
        FileProvider bfw = new FileProviderWindows(cipherFileName);
        // 構造体を読み込む
        CipherDataHeader header = new CipherDataHeader(bfw);
        header.readHeader();
        // OpenSSLのファイルだったら、
        // 鍵導出関数(KDF)のハッシュアルゴリズムをMD5にする。
        if(header.isOpenSSL){
            prov.setHashAlgorithmForKDF(prov.HashAlgorithm.MD5);
        }
        prov.setHashIteration(header.iteration);
        // 
        prov.beginDecrypt(header.iv,key);
        scope ubyte[] buf = new ubyte[prov.getChunkSize];
        size_t readedSize = size_t.max;
        ulong plainFileSize = bfw.size();
        ulong processedSize = header.cryptDataOffset;
        for (ulong readData=0; readData <= header.cryptDataLength ; readData += readedSize){
            progressCallback(processedSize,plainFileSize);
            bfw.read(buf,&readedSize);
            if(readedSize == 0){break;}
            plainFile.rawWrite(prov.putDecrypt(buf[0..readedSize]));
            processedSize+=readedSize;
        }
        plainFile.rawWrite(prov.endDecrypt());
        progressCallback(processedSize,plainFileSize);
    }
}

class CipherDataHeader{
    private immutable SignLength = 8;
    private immutable OpenSSLSaltLength = 8;
    // ファイル判別用シグネチャ（なんでもいい）
    // CDF\0 = Cipher Data File（超適当）
    private immutable ubyte[SignLength] sign = 
        cast(ubyte[SignLength])"CDF\x00\xCC\xDD\xFF\x00";
    private immutable ubyte[SignLength] OpenSSLSign = 
        cast(ubyte[SignLength])"Salted__";
    ulong cryptDataOffset;
    ulong ivOffset;
    ulong ivLength;
    ulong iteration; // ハッシュ反復数（キー生成）
    ulong cryptDataLength; // 暗号化データの長さ
    ushort majorVersion = 1;
    ushort minorVersion = 0;
    ubyte[] iv;
    bool isOpenSSL=false;

    // 暗号化データの長さが格納された位置 / 一時変数
    private ulong cryptDataLenPos;

    FileProvider fp;
    this(FileProvider fp){
        this.fp = fp;
    }

    void writeHeader(ubyte[] iv,ulong iteration){
        ulong cryptDataOffsetPos;
        fp.setLength(0);    // ファイルを空にする
        fp.write(sign);
        cryptDataOffsetPos = fp.getCurrentPosition();
        fp.write([cryptDataOffset]); // 予約領域
        fp.write([majorVersion]);
        fp.write([minorVersion]);
        cryptDataLenPos = fp.getCurrentPosition(); // 暗号化されたデータサイズは後で書く
        fp.write([cryptDataLength]); // 暗号化されたデータのサイズ
        fp.write([iteration]); // ハッシュ反復数（キー生成）
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
        ulong size = fp.size();
        ubyte[SignLength] sign;
        fp.read(sign);
        if( sign != this.sign ){
            readHeaderOpenSSL(sign);
            return;
        }
        cryptDataOffset = readStruct!ulong(fp);
        majorVersion = readStruct!ushort(fp);
        minorVersion = readStruct!ushort(fp);
        cryptDataLength = readStruct!ulong(fp);
        iteration = readStruct!ulong(fp);
        ivLength = readStruct!ulong(fp);
        if(ivLength > ubyte.max){
            throw new Exception("too large initial vector.");
        }
        iv = cast(ubyte[]) fp.read(new ubyte[cast(ubyte)ivLength]);
    }
    void readHeaderOpenSSL(ubyte[] sign){
        if( sign != this.OpenSSLSign ){
            throw new Exception("invalid file type.");
        }
        cryptDataLength = fp.size()-(OpenSSLSign.length+OpenSSLSaltLength);
        ivLength = OpenSSLSaltLength;
        iteration = 1;
        iv = cast(ubyte[]) fp.read(new ubyte[OpenSSLSaltLength]);
        cryptDataOffset = fp.getCurrentPosition();
        isOpenSSL=true;
    }
}

unittest
{

}