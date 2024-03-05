import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // TODO implement the status route
  // _registry.get("/status", (req, res) => {});
  _registry.get("/status", (req: Request, res: Response) => {
    res.send("live");
  });

  
  let nodeRegistry: Node[] = [];

  _registry.post('/registerNode', (req: Request, res: Response) => {
    const { nodeId, pubKey } = req.body;

    const newNode: Node = {
      nodeId: nodeId,
      pubKey: pubKey,
    };

    nodeRegistry.push(newNode);

    return res.status(200).send({ message: "Node registered successfully." });
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes: nodeRegistry });
  });

  
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}