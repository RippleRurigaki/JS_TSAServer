import {readFileSync,writeFileSync} from "fs";

export class SrvStatus{
    private tsaCert:string;
    private tsaKey:string;
    private snRecordPath:string;
    private serialNo:bigint;
    private tsaPolicyOID:string;
    private lastSaveStatus:boolean;

    constructor(){
        this.tsaCert = "";
        this.tsaKey = "";
        this.tsaPolicyOID = "2.5.29.32.0";
        this.serialNo = 1n;
        this.snRecordPath = "";
        this.lastSaveStatus = true;
    }

    public getCert = () => this.tsaCert;
    public setCert = (pem:string) => {this.tsaCert=pem};

    public getKey = () => this.tsaKey;
    public setKey = (pem:string) => {this.tsaKey=pem};

    public haveCertKey = () => (this.tsaCert&&this.tsaKey)?true:false;
    
    public getTsaPolicyOID = () => this.tsaPolicyOID;
    public setTsaPolicyOID = (oid:string) => {this.tsaPolicyOID = oid};

    public setSerialnoRecord = (path:string) => {
        this.snRecordPath = path;
        try{
            const _recordData = readFileSync(this.snRecordPath);
            const _intStr = _recordData.toString();
            this.serialNo = BigInt(_intStr);
        }catch(e){
            throw new Error("SN Recordfile load failed.");
        }

    }
    public getSerialNoHEX = (ignoreErr?:boolean) => {
        const hex = this.serialNo.toString(16);
        this.serialNo++;
        this.saveSnRecord(ignoreErr);
        return hex.length%2===0?hex:'0'+hex;
    }
    public getLastSaveStatus = () => this.lastSaveStatus;
    public getCurrentSN = () => this.serialNo;
    public saveSnRecord = (ignoreErr?:boolean) => {
        try{
            writeFileSync(this.snRecordPath,this.serialNo.toString());
            this.lastSaveStatus = true;
        }catch(e){
            this.lastSaveStatus = false;
            if(!ignoreErr){
                throw new Error(`SN Recordfile save failed.(CurrentNumber="${this.serialNo}")`);
            }
        }
    }
}