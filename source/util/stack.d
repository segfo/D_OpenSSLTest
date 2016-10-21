module util.Stack;

class StackException:Exception{
    this(string msg){
        super(msg);
    }
}

class Stack(T)
{
    T[] buf;
    sizediff_t stackPtr;
    this(T[] buf){
        this.buf = buf;
    }
    this(){
        this.buf = new T[4096];
    }
    this(size_t stackSize){
        this.buf = new T[stackSize];
    }
    void push(T data){
        if( stackPtr < buf.length ){
            buf[stackPtr++] = data;
        }else{
            throw new StackException("Stack is full.");
        }
    }
    T pop(){
        T data;
        if( stackPtr > 0 ){
            data = buf[--stackPtr];
        }else{
            throw new StackException("Stack is empty.");
        }
        return data;
    }
}
