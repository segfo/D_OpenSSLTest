module cryptor.Random;
import deimos.openssl.rand;

int getRandom(ubyte[] random){
    return RAND_bytes(random.ptr, cast(int)random.length);
}
