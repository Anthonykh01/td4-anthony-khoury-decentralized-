import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { REGISTRY_PORT } from "../config";
import {generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt} from "../crypto";
import http from "http";


let LastReceivedEncryptedMessage: string | null = null;
let LastReceivedDecryptedMessage: string | null = null;
let LastMessageDestination: number | null = null;

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.get("/status", (req, res) => {
    res.status(200).send("live")
  });

  const { publicKey, privateKey } = await generateRsaKeyPair();

  let pubKeyBase64 = await exportPubKey(publicKey);
  let privateKeyBase64 = await exportPrvKey(privateKey);

  const data = JSON.stringify({
    nodeId,
    pubKey: pubKeyBase64,
  });

  const options = {
    hostname: 'localhost',
    port: REGISTRY_PORT,
    path: '/registerNode',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': data.length,
    },
  };

  const req = http.request(options, (res) => {
    res.on('data', (chunk) => {
      console.log(`Response: ${chunk}`);
    });
  });

  req.on('error', (error) => {
    console.error(`Problem : ${error.message}`);
  });
  req.write(data);
  req.end();


  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: LastReceivedEncryptedMessage });
   });
 
   onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
     res.json({ result: LastReceivedDecryptedMessage });
    });
    
   onionRouter.get("/getLastMessageDestination", (req, res) => {
     res.json({ result: LastMessageDestination });
   });

   onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyBase64 });
  });

  onionRouter.post("/message",async (req, res) => {
    const { message } = req.body;
    LastReceivedEncryptedMessage = message;
    const decryptkey= await rsaDecrypt(message.slice(0, 344), privateKey);
    const decryptmessage=await symDecrypt(decryptkey, message.slice(344));
    LastReceivedDecryptedMessage=decryptmessage.slice(10);
    LastMessageDestination=parseInt(decryptmessage.slice(0,10),10);
    
    await fetch(`http://localhost:${LastMessageDestination}/message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: LastReceivedDecryptedMessage }),
    });
    res.status(200).send("success");
});
  
 

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}