module util.Util;
import std.stdio;

void dump(ubyte[] data){
    dump("",data);
}

void dump(string msg,ubyte[] data){
    immutable size_t Line = 16;
    int line=0;
    writef("[ %s ]\n",msg);
    write("----:");
    for(int i=0;i<Line;i++){
        writef(" %0.2x",i);
    }
    writef("  | 0123456789abcdef\n=====");
    for(int i=0;i<Line;i++){
        writef("===",i);
    }
    write(" ");
    for(int i = 0; i < data.length; i++){
        if((i%Line)==0){
            writef(" | ");
            if(i==0){
                write("================");
            }else{
                for(int j = i-Line; j < i; j++){
                    if((0x20<=data[j]&&data[j]<=0x7f)){
                        writef("%c",cast(char)data[j]);
                    }else{
                        write(".");
                    }
                }
            }
            writef("\n%0.4x: ",line);
            line+=0x10;
        }
        writef("%0.2x ",data[i]);
    }
    line-=0x10;
    for(int i = Line - (data.length - line); i > 0 ; i--){ 
        write("   ");
    }
    write(" | ");
    for(int i = line ; i < data.length ; i++){
        if((0x20<=data[i]&&data[i]<=0x7f)){
            writef("%c",cast(char)data[i]);
        }else{
            write(".");
        }
    }
    writeln("\n");
}