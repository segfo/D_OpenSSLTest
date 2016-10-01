module app;
import std.stdio;
import std.digest.sha;
import cryptor.Random;
import cryptor.Digest;

void main()
{
    // 適当なファイルを読む
    File f=File("./libs/x86/libcrypto.lib","rb");
    scope(exit){f.close();}
    // std.digestにあるアルゴリズムならなんでも使える
    auto digest = new Hash!SHA1();
    writef("%s\n",digest.classinfo);
    // ファイルをハッシュ
    writef("%s:%s\n",f.name(),digest.getHash(f).hexDigest());
    // 文字列をハッシュ
    writef("susono: %s\n",digest.getHash("susono").hexDigest());
    // スライスをハッシュ
    ubyte[] ubyteSlice=[10,20,30];
    writef("ubyteSlice[10,20,30]: %s\n",digest.getHash(ubyteSlice).hexDigest());

    // OpenSSLのリンクテスト
    // 任意の乱数列を得ることができる。
    ubyte[3] random;
    getRandom(random);
    write("random(OpenSSL) : ");
    writeln(random);
}
