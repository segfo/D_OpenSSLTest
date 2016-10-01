module cryptor.Digest;
import std.digest.sha;
import std.file;
import std.stdio;

class Hash(T){
    WrapperDigest!T digest;
    ubyte[] hash;
    immutable size_t DEFAULT_CHUNKS=1024;
    this(){
        digest = new WrapperDigest!T();
    }
    Hash getHash(ubyte[] data){
        digest.put(data);
        hash = digest.finish();
        return this;
    }
    Hash getHash(string data){
        digest.put(cast(ubyte[])data);
        hash = digest.finish();
        return this;
    }
    // 1chunk = 4kb
    Hash getHash(File file,size_t chunkSize){
        if(!file.isOpen){
            throw new FileException("file not opened.");
        }
        if(chunkSize == 0){
            chunkSize = DEFAULT_CHUNKS;
        }
        chunkSize *= 0x1000;
        foreach(chunk;file.byChunk(chunkSize)){
            digest.put(chunk);
        }
        hash = digest.finish();
        file.seek(0);
        return this;
    }
    
    Hash getHash(File file){
        getHash(file,DEFAULT_CHUNKS);
        return this;
    }
    string hexDigest(){
        return toHexString(hash);
    }
    ubyte[] rawDigest(){
        return hash;
    }
}