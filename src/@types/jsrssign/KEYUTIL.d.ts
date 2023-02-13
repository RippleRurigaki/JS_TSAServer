declare namespace jsrsasign{
    export class KEYUTIL{
        static version:string;
        static getKey(param:KJUR_KeyObject, passcode?:string, hextype?:string):RSAKey|KJUR.crypto.DSA|KJUR.crypto.ECDSA;
        static getPEM(keyObjOrHex:string|RSAKey|KJUR.crypto.DSA|KJUR.crypto.ECDSA,formatType:string,passwd?:string,encAlg?:string,hexType?:string,ivsaltHex?:string):string;
    }
}