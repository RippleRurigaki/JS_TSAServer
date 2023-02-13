import {KJUR,X509,KEYUTIL,ASN1HEX,hextob64} from "jsrsasign";
import {SrvStatus} from "./serverStatus";
import {buffer2Hex,getTimeStr, hex2buffer,getASN1Len,oid} from "./utils";

const paseErrMes = "Unsupport MS-TSAS Request";
export const sign_MSTSAS = (request:Uint8Array,serverStatus:SrvStatus,hashAlgorythm?:"sha1"|"sha256"|"sha512") => {
    try{
        const requestData = ASN1HEX.parse(buffer2Hex(request));
        if(requestData.seq && requestData.seq[0]?.oid === oid.SPC_TIME_STAMP_REQUEST_OBJID){
            //Microsoft Authenticode TimeStamp
            //https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures
            if(requestData.seq[1].seq && requestData.seq[1].seq[0].oid === "data"){
                if(requestData.seq[1].seq[1].tag?.obj?.octstr?.obj){
                    const targetData = requestData.seq[1].seq[1].tag.obj.octstr.obj;
                    if(!targetData.seq){
                        throw new Error(paseErrMes);
                    }
                    const x509 = new X509(serverStatus.getCert());
                    const issuer = {str: x509.getIssuer().str, serial: x509.getSerialNumberHex()};
                    const keyObj = KEYUTIL.getKey(serverStatus.getKey());
                    const keyType = keyObj.type==='EC'?'ECDSA':keyObj.type;
                    const hashAlg = hashAlgorythm||"sha256";
                    const signAlg = `${hashAlg.toUpperCase()}with${keyType}`;
                    const signContent = KJUR.asn1.ASN1Util.jsonToASN1HEX(targetData);
                    const signeture = [targetData.seq[0]?.int?.hex,targetData.seq[1]?.int?.hex];
                    if(!signeture[0] || !signeture[1]){
                        throw new Error(paseErrMes);
                    }
                    const signetureBuf = [hex2buffer(signeture[0]),hex2buffer(signeture[1])];
                    const objLens = [getASN1Len(signetureBuf[0].length),getASN1Len(signetureBuf[1].length)];
                    const objs = [new Uint8Array([...objLens[0],...signetureBuf[0]]),new Uint8Array([...objLens[1],...signetureBuf[1]])];
                    const contxLen = getASN1Len(2+objs[0].length+objs[1].length);
                    const contxBuf = new Uint8Array([0x30,...contxLen,0x02,...objs[0],0x02,...objs[1]]);
                    const md = new KJUR.crypto.MessageDigest({alg:hashAlg});
                    md.updateHex(buffer2Hex(contxBuf));
                    const digest = md.digest();
                    const params:SignPrams = {
                        version: 1,
                        hashalgs: [hashAlg],
                        econtent: {
                            type: "data",
                            content: {hex:signContent},
                        },
                        certs: [serverStatus.getCert()],
                        sinfos: [{
                            version: 1,
                            id: {type:'isssn', issuer: {str: issuer.str}, serial: {hex: issuer.serial}},
                            hashalg: hashAlg,
                            sattrs: {array: [{
                                attr: "contentType",
                                type: '1.2.840.113549.1.7.1',
                            },{
                                attr: "signingTime",
                                hex:new  KJUR.asn1.cms.SigningTime({type:"gen",str:getTimeStr()}).tohex(),
                            },{
                                attr: "messageDigest",
                                hex: digest,
                            }]},
                            sigalg: signAlg,
                            signkey:serverStatus.getKey(),
                        }],
                        fixed: true
                    }
                    const sd = new KJUR.asn1.cms.SignedData(params);
                    return hextob64(sd.getContentInfoEncodedHex());
                }
            }
        }
    }catch(e){
        console.error(e);
        return;
    }
}