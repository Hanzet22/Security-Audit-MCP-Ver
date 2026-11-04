#!/usr/bin/env node
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createServer } from "./index.js";

const nodeMajor = Number(process.versions.node.split(".")[0]);

if (!Number.isInteger(nodeMajor) || nodeMajor < 22) {
  console.error(
    `Security-Audit-MCP-Ver requires Node.js 22 or newer. Detected Node.js ${process.versions.node}.`,
  );
  process.exit(1);
}

await serveStdio(createServer);
