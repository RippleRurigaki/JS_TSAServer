declare namespace jsrsasign{
    export class X509 {
        constructor(pram?:string);

        hex:string;
        
        getExtAIAInfo():AIAExtensionPrams;
        getExtCRLDistributionPoints():CRLDistributionPointsPrams;
        getInfo():string;
        getIssuer(flagCanon?:boolean,flagHex?:boolean):issuerfield;
        getIssuerHex():string;
        getExtKeyUsage():undefined|KeyUsageStr;
        getExtExtKeyUsage():undefined|ExKeyUsageStr;
        getSerialNumberHex():string;

    }
}

interface AIAExtensionPrams{
    ocsp:Array<string>,
    caissuer:Array<string>,
}

interface CRLDistributionPointsPrams{
    array: Array<{dpname: {full: Array<{uri: string}>}}>,
    critical: boolean
}

interface KeyUsageStr{
    critical: boolean,
    names:Array<string>,
}
interface ExKeyUsageStr{
    critical: boolean,
    array:Array<string>,
}