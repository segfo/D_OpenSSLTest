module app;
import std.stdio;
import std.digest.sha;
import cryptor.Random;
import cryptor.Digest;

void main()
{
    // 
    File f=File("./libs/x86/libcrypto.lib","rb");
    scope(exit){f.close();}
    // std.digestにあるアルゴリズムならなんでも使える
    auto digest = new Hash!SHA1();
    writef("%s\n",digest.classinfo);
    writef("%s:%s\n",f.name(),digest.getHash(f).hexDigest());
    writef("susono: %s\n",digest.getHash("susono").hexDigest());
    writef("hoge: %s\n",digest.getHash("hoge").hexDigest());
    // OpenSSLのリンクテスト
    // 任意の乱数列を得ることができる。
    ubyte[3] random;
    getRandom(random);
    writeln(random);

}
