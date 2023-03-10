export const buffer2Hex = (b:Uint8Array,pos?:number,len?:number) =>{
    const _str:Array<string> = [];
    const _pos = pos||0;
    const _len = len||b.length;
    for(let i=0;i<_len;i++){
        if(typeof b[_pos+i] === "number"){
            _str.push(b[_pos+i].toString(16).padStart(2,'0'))
        }
    }
    return _str.join('');
}
export const hex2buffer = (hex:string) => {
    const hexMap = hex.match(/.{1,2}/g);
    if(!hexMap){
        return new Uint8Array(0);
    }
    return Uint8Array.from(hexMap.map((byte) => parseInt(byte, 16)));
}
export const getTimeStr = (millis?:boolean) =>{
    const n = new Date();
    return `${n.getUTCFullYear().toString()}${(n.getUTCMonth()+1).toString().padStart(2,'0')}${n.getUTCDate().toString().padStart(2,'0')}`
    +`${n.getUTCHours().toString().padStart(2,'0')}${n.getUTCMinutes().toString().padStart(2,'0')}${n.getUTCSeconds().toString().padStart(2,'0')}`
    +(millis?`.${n.getMilliseconds().toString()}Z`:`Z`);
}
export const getASN1Len = (len:number) => {
    if(len<128){
        return new Uint8Array([len]);
    }else{
        const lenlen = Math.floor(len/256)+1;
        const lenBuf = new Uint8Array(1+lenlen);
        lenBuf[0] = 128+lenlen;
        const lenHex = (()=>{
            const _h = len.toString(16);
            return _h.length%2?_h:`0${_h}`;
        })();
        return hex2buffer(lenHex);
    }
}

export const contentType = {
    octStream:'application/octet-stream',
    timestampQuery:'application/timestamp-query',
}
export const oid = {
    SPC_TIME_STAMP_REQUEST_OBJID:"1.3.6.1.4.1.311.3.2.1",
}