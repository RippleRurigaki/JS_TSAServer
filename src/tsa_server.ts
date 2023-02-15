import {writeFileSync,readFileSync,existsSync} from "fs";
import express from 'express';
import BodyParser from 'body-parser';
import {X509,KEYUTIL,b64utohex} from "jsrsasign";
import { Command } from 'commander';
const commander = new Command();

import {SrvStatus} from "./serverStatus";
import {hex2buffer,contentType} from "./utils";
import {sign_MSTSAS} from "./ms-TSAS";
import {sign_RFC3161} from "./rfc3161";


const srvStatus = new SrvStatus();
const server = express();
server.set('x-powered-by',false);
server.use(express.raw());

server.post(`/`,BodyParser.raw({"type":"*/*"}),async (req,res,nex)=>{
    const requestContenteType = req.headers['content-type'];
    if(requestContenteType === contentType.octStream){
        //Maybe Microsoft Authenticode TimeStamp
        const msTsasResponse = sign_MSTSAS(new Uint8Array(hex2buffer(b64utohex(req.body))),srvStatus);
        if(msTsasResponse){
            exresponse.ok_octetstream(res,msTsasResponse);
        }else{
            exresponse.badRequest(res);
        }
        return;
    }else if(requestContenteType === contentType.timestampQuery){
        //RFC 3161
        const rfc3161Response = sign_RFC3161(new Uint8Array(req.body),srvStatus);
        if(rfc3161Response){
            exresponse.ok_octetstream(res,rfc3161Response);
        }else{
            exresponse.badRequest(res);
        }
        return;
    }
    exresponse.badRequest(res);
    return;
});
server.use((req,res,next)=>{
    res.status(404);
    res.end('404 Not Found');
});

const exresponse = {
    ok_octetstream:(res:express.Response,body:Uint8Array|string)=>{
        res.status(200);
        res.contentType("application/octet-stream");
        res.end(body);
    },
    badRequest:(res:express.Response)=>{
        res.status(400);
        res.end("Bad Request");        
    }
}

const initilize = (sv:express.Express) => {
    commander
        .requiredOption("-C, --cert <path>","TSA Certificate PEM file path.")
        .option("--forcekeyusage","Not keyusage timestamping, force load.")
        .requiredOption("-K, --key <path>","TSA PrivateKey PEM file path.")
        .option("-P, --pass <passphare>","PrivateKey passsphare.")
        .requiredOption("-S, --serialno <path>","Serialno record file path.")
        .option("-I, --oid <oid>","TSA Policy OID.","2.5.29.32.0")
        .option("-L, --listen <number>","TSA Server listen port","80")
        .parse(process.argv);
    const options:{
        cert:string,
        forcekeyusage?:boolean,
        key:string,
        pass?:string,
        oid:string,
        serialno:string,
        listen:string,
    } = commander.opts();

    const txtDec = new TextDecoder();
    const cert = txtDec.decode(Uint8Array.from(readFileSync(options.cert)));
    const usages = (()=>{
        if(options.forcekeyusage){
            return true;
        }
        try{
            const x509 = new X509(cert);
            const usage = x509.getExtKeyUsage();
            const usageEx = x509.getExtExtKeyUsage();
            if(!usage && !usageEx){
                return true;
            }
            return [...usage?usage.names:[],...usageEx?usageEx.array:[]].includes("timeStamping");
        }catch(e){
            throw new Error("Unsupport cert file.");
        }
    })();
    if(!usages){
        throw new Error("Certificate is not usage 'TimeStamping'.");
    }
    srvStatus.setCert(cert);

    const key = txtDec.decode(Uint8Array.from(readFileSync(options.key)));
    if(options.pass){
        try{
            const decryptKey = KEYUTIL.getPEM(KEYUTIL.getKey(key,options.pass),"PKCS1PRV");
            srvStatus.setKey(decryptKey);
        }catch(e){
            throw new Error("Key decrypt failed.");
        }
    }else{
        srvStatus.setKey(key);
    }
    try{
        KEYUTIL.getKey(srvStatus.getKey());
    }catch(e){
        throw new Error('Unsupport KEY file.');
    }
    if(!existsSync(options.serialno)){
        writeFileSync(options.serialno,new Uint8Array([0x31]));
    }
    srvStatus.setSerialnoRecord(options.serialno);

    srvStatus.setTsaPolicyOID(options.oid);

    const listenPort = parseInt(options.listen);
    if(typeof listenPort === "number"){
        if(isNaN(listenPort) || listenPort < 1 || listenPort > 65535){
            throw new Error ("Listen port invalid number");
        }
    }
    sv.listen(listenPort);
}
process.on("exit",()=>{
    if(srvStatus){
        if(!srvStatus.getLastSaveStatus()){
            console.error(`SerialNo record save failed.\r\nLast number is "${srvStatus.getCurrentSN()}"`);
        }
    }
})
process.on("SIGINT",()=>process.exit())

initilize(server);