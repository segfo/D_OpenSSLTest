module app;
import std.stdio;
import std.digest.sha;
import cryptor.Random;
import cryptor.Digest;
import cryptor.AES;
import util.Util;

void main()
{
    File f=File("C:\\Windows\\System32\\calc.exe","rb");
    
    scope(exit){f.close();}
    {
        ubyte[] data = cast(ubyte[])"AAAABBBBCCCCDDDDF";

        scope IAES_CBC_Cryptor aes=new AES256_CBC();
        aes.beginEncrypt(cast(ubyte[])"key");
        auto z = aes.putEncrypt(data[0..4]);
        z ~= aes.putEncrypt(data[4..data.length]);
        z ~= aes.endEncrypt();

        aes.beginDecrypt(aes.getIV(),cast(ubyte[])"key");
        z = aes.putDecrypt(z);
        z ~= aes.endDecrypt();
    }
    writeln("shutdown.");
}
