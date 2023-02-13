declare namespace jsrsasign{
    namespace KJUR.asn1.cms{
        class SignedData extends KJUR.asn1.ASN1Object{
            constructor(pram:SignPrams);
            getContentInfoEncodedHex():string;
        }
        class SigningTime extends KJUR.asn1.ASN1Object{
          constructor(pram?:SigningTimePram)
        }
    }
}

type SignPrams = {
    version: number,
    hashalgs: Array<JSRSASIGN_SupportHashAlg>,
    econtent?: {
      type?:string,
      content?: JSRSASIGN_DER_OctetString,
      isDetached?:boolean
    },
    certs?:Array<string>,
    revinfos?: {array:Array<Revinfos>},
    sinfos: [{
      version: number,
      id: {type:string, issuer: JSRSASIGN_DER_OctetString, serial: JSRSASIGN_DER_Integer},
      hashalg: JSRSASIGN_SupportHashAlg,
      sattrs?: {array:Array<{ //ToDo:Check 
        attr?:string,
        str?:string,
        type?:string,
        hex?:string,
      }>},
      sigalg?: string,
      signkey?:string,
    }],
    fixed?:boolean,
}
type Revinfos = {crl:string}|{ocsp:string};

interface SigningTimePram{
  type?:"gen",
  str?:string,
}