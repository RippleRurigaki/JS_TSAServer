# JS_TSAServer

FC3161 and MS-Authenticode timestamp server in JavaScript.

## Experimental
***It is for experimental use and may not meet all specifications.***


## Usage

1. Install modules.  
2. Compile typescript.  

3. and

```
Usage: node tsa_server.js [options]

Options:
  -C, --cert <path>       TSA Certificate PEM file path.
  --forcekeyusage         Not keyusage timestamping, force load.
  -K, --key <path>        TSA PrivateKey PEM file path.
  -P, --pass <passphare>  PrivateKey passsphare.
  -S, --serialno <path>   Serialno record file path.
  -I, --oid <oid>         TSA Policy OID. (default: "2.5.29.32.0")
  -L, --listen <number>   TSA Server listen port (default: "80")
  -h, --help              display help for command
```

Timestamp Certificate require timestamping in keyusage.  
If use --forcekeyusage option,not require timestamping in keyusage,but mabey invalid sign.  
