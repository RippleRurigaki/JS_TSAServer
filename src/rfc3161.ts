
import {KJUR,X509,KEYUTIL} from "jsrsasign";
import {SrvStatus} from "./serverStatus";
import {buffer2Hex,getTimeStr, hex2buffer} from "./utils";

const paseErrMes = "Unsupport Fromat";
export const sign_RFC3161 = (request:Uint8Array,serverStatus:SrvStatus) => {
    try{
        const x509 = new X509(serverStatus.getCert());
        const issuer = {str: x509.getIssuer().str, serial: x509.getSerialNumberHex()};
        const keyObj = KEYUTIL.getKey(serverStatus.getKey());
        const keyType = keyObj.type==='EC'?'ECDSA':keyObj.type;
        const parser = new KJUR.asn1.tsp.TSPParser();
        const tspReq = parser.getTimeStampReq (buffer2Hex(request));
        const hashAlg = tspReq.messageImprint.alg;
        if(hashAlg !== 'sha1' && hashAlg !== "sha256" && hashAlg !== "sha384" && hashAlg !== "sha512"){
            const tsr = new KJUR.asn1.tsp.TimeStampResp({
                statusinfo: {
                    status:2,
                    failinfo:0,
                }
            });
            const hex = tsr.getEncodedHex();
            return hex2buffer(hex);
        }
        const signAlg = `${hashAlg.toUpperCase()}with${keyType}`;
        const tstInfoPram:TSTInfoPram = {
            policy: serverStatus.getTsaPolicyOID(),
            messageImprint: tspReq.messageImprint,
            serial: {"hex": serverStatus.getSerialNoHEX(true)},
            genTime: {str:getTimeStr(true), millis: true},
            accuracy: { millis: 500 },
            ordering: true,
        }
        if(tspReq.nonce){
            tstInfoPram["nonce"] = {hex:tspReq.nonce};
        }
        const tstInfo = new KJUR.asn1.tsp.TSTInfo(tstInfoPram);
        const tstInfoHex = tstInfo.getEncodedHex();
        const md = new KJUR.crypto.MessageDigest({alg:hashAlg});
        md.updateHex(tstInfoHex);
        const digest = md.digest();
        const params:TimeStampResPram = {
            version: 1,
            hashalgs: [hashAlg],
            econtent: {
                type: "tstinfo",
                content:tstInfoPram,
            },
            certs: [serverStatus.getCert()],
            sinfos: [{
                version: 1,
                id: {type:'isssn', issuer: {str: issuer.str}, serial: {hex: issuer.serial}},
                hashalg: hashAlg,
                sattrs: {array:[{
                    attr: "contentType",
                    type: '1.2.840.113549.1.9.16.1.4',
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
        const tsr = new KJUR.asn1.tsp.TimeStampResp(params);
        return  hex2buffer(tsr.getEncodedHex());
    }catch(e){
        console.error(e);
        return;
    }
}