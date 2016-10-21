module util.FileProvider;
import util.Stack;
import core.sys.windows.windows;
import std.string;
import std.utf;

class FileProviderException:Exception{
    this(string msg){
        super(msg);
    }
}

interface FileProvider{
    enum SeekMethod{
        SEEK_BEGIN=FILE_BEGIN,SEEK_CURRENT=FILE_CURRENT,SEEK_END=FILE_END
    }
    void write(const void[] v);
    void[] read(void[] buf);
    void seek(long pos,SeekMethod moveMethod=SeekMethod.SEEK_BEGIN);
    void pushSeek(long pos,SeekMethod moveMethod=SeekMethod.SEEK_BEGIN);
    void popSeek();
    void seekEnd();
    ulong size();
    ulong getCurrentPosition();
}

class FileProviderWindows:FileProvider{
    ulong currentPos;
    Stack!long seekerStack;
    HANDLE fh;
    immutable static string[] reservedFiles = [
        "nul", "con", "prn", "aux", "com1", "com2", "com3",
        "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6",
        "lpt7", "lpt8", "lpt9"
    ];
    this(string path,size_t stackSize){
        if(isReservedName(path)==true){
            throw new FileProviderException("Invalid file name.");
        }
        fh = CreateFileW(toUTF16z(path),GENERIC_WRITE|GENERIC_READ,
            FILE_SHARE_READ,NULL,
            OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,
            null);
        if(fh == NULL){
            throw new FileProviderException("CreateFileW Failure");
        }
        if( GetFileType(fh) != FILE_TYPE_DISK ){
            throw new FileProviderException("Invalid file type.");
        }
        // とりあえずどんなファイルでも先頭にシークしとく
        currentPos=0;
        this.seek(currentPos,SeekMethod.SEEK_BEGIN);
        seekerStack = new Stack!long(stackSize);
    }
    this(string path){
        this(path,4096);
    }
    ~this(){
        if(fh!=null){
            CloseHandle(fh);
        }
    }
    void write(const void[] v){
        uint writted;
        ulong writeSize = v.length;
        int status = WriteFile(fh,v.ptr,cast(uint)writeSize,&writted,null);
        if(status == 0){
            throw new FileProviderException("WriteFile Failure.");
        }
    }
    void[] read(void[] buf){
        uint readed;
        ulong readSize = buf.length;
        auto currentPos = getCurrentPosition();
        auto status = ReadFile(fh,buf.ptr,cast(uint)readSize,&readed,null);
        if( status == 0 || readSize > readed ){
            seek(currentPos);
            throw new FileProviderException("ReadFile Failure.");
        }
        return buf;
    }
    
    void seek(long pos,FileProvider.SeekMethod moveMethod=SeekMethod.SEEK_CURRENT){
        int fptrH = cast(int)(pos>>32);
        int fptrL = cast(int)pos;
        SetFilePointer(fh,fptrL,&fptrH,cast(uint)moveMethod);
    }
    void pushSeek(long pos,SeekMethod moveMethod=SeekMethod.SEEK_CURRENT){
        seekerStack.push(getCurrentPosition());
        seek(pos,moveMethod);
    }
    void popSeek(){
        seek(seekerStack.pop(),SeekMethod.SEEK_BEGIN);
    }
    void seekEnd(){
        SetFilePointer(fh,0,null,cast(uint)SeekMethod.SEEK_END);
    }
    ulong size(){
        ulong high;
        ulong fileSize = GetFileSize(fh,cast(uint*)&high);
        fileSize |= high << 32; 
        return fileSize;
    }    
    ulong getCurrentPosition(){
        ulong currentOffset;
        ulong currentOffsetH;
        currentOffset = SetFilePointer(fh,0,cast(int*)&currentOffsetH,FILE_CURRENT);
        return currentOffset|currentOffsetH<<32;
    }
    private bool isReservedName(string path){
        bool ret = false;
        if(path.length >= 4){
            if("\\\\.\\"==path[0..4]){
                return true;
            }
        }
        for (int i = 0; !ret && i < reservedFiles.length ; ++i) {
            if (0 == cmp(toLower(path), reservedFiles[i])) {
                ret = true;
            }
        }
        return ret;
    }
}
