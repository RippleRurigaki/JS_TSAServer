declare namespace jsrsasign{
    namespace KJUR.asn1.ocsp{
        class OCSPUtil{
            static getRequestHex(issuerCert:string,subjectCert:string,algName?:string):string;
        }
    }
}