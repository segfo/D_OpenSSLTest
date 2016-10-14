module util.Util;
import std.stdio;

void dump(ubyte[] data){
    immutable size_t Line = 16;
    int line=0;
    write("----:");
    for(int i=0;i<16;i++){
        writef(" %0.2x",i);
    }
    writef("\n=====");
    for(int i=0;i<16;i++){
        writef("===",i);
    }
    for(int i = 0; i<data.length;i++){
        if((i%Line)==0){
            writef("\n%0.4x: ",line);
            line+=0x10;
        }
        writef("%0.2x ",data[i]);
    }
    writeln("\n");
}