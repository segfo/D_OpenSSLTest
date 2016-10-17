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
        scope IAES_CBC_Cryptor aes = new AES256_CBC();
        aes.beginEncrypt(cast(ubyte[])"key");
        dump(data[0..4]~data[4..data.length]);
        auto z = aes.putEncrypt(data[0..4]).dup();
        z ~= aes.putEncrypt(data[4..data.length]).dup();
        z ~= aes.endEncrypt().dup();
        dump(z);

        aes.beginDecrypt(aes.getIV(),cast(ubyte[])"key");
        z = aes.putDecrypt(z).dup();
        z ~= aes.endDecrypt().dup();
        dump(z);
    }
    writeln("shutdown.");
}
