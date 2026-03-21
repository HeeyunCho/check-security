import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "check-security", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const SECRET_PATTERNS = [
    { name: "Generic API Key", regex: /[a-zA-Z0-9]{32,}/g },
    { name: "Slack Token", regex: /xox[baprs]-[0-9]{12}-[a-zA-Z0-9]{24}/g },
    { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g },
    { name: "AWS Secret Key", regex: /[0-9a-zA-Z\/+]{40}/g },
    { name: "GitHub Personal Access Token", regex: /gh[pous]_[a-zA-Z0-9]{36}/g },
    { name: "Google Client ID", regex: /[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/g },
    { name: "Private Key", regex: /-----BEGIN (RSA|OPENSSH|PGP) PRIVATE KEY-----/g },
    { name: "Password/Secret Label", regex: /(password|passwd|secret|secrete|credential|token|key|client_id|client_secret)\s*[:=]\s*["'][^"']+["']/gi }
];

const SCAN_EXCLUSIONS = [
    "node_modules",
    ".git",
    "dist",
    "package-lock.json"
];

function scanFile(filePath: string): string[] {
    const findings: string[] = [];
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        for (const pattern of SECRET_PATTERNS) {
            const matches = content.match(pattern.regex);
            if (matches) {
                findings.push(`Found ${pattern.name} in ${filePath}`);
            }
        }
    } catch (e) {
        // Skip binary files or unreadable files
    }
    return findings;
}

function scanDirectory(dirPath: string): string[] {
    let findings: string[] = [];
    const files = fs.readdirSync(dirPath);

    for (const file of files) {
        if (SCAN_EXCLUSIONS.includes(file)) continue;
        const fullPath = path.join(dirPath, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            findings = findings.concat(scanDirectory(fullPath));
        } else {
            findings = findings.concat(scanFile(fullPath));
        }
    }
    return findings;
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "scan_for_secrets",
        description: "Scans a directory or file for potential secrets like API keys, tokens, and credentials.",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "The path to the directory or file to scan." }
          },
          required: ["path"],
        },
      },
      {
        name: "check_gitignore",
        description: "Checks if common sensitive files are ignored in .gitignore.",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "The path to the .gitignore file or the directory containing it." }
          },
          required: ["path"],
        },
      }
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "scan_for_secrets") {
    const targetPath = (args as { path: string }).path;
    if (!fs.existsSync(targetPath)) {
        return { content: [{ type: "text", text: `Error: Path ${targetPath} does not exist.` }], isError: true };
    }

    const stat = fs.statSync(targetPath);
    const findings = stat.isDirectory() ? scanDirectory(targetPath) : scanFile(targetPath);

    if (findings.length === 0) {
        return { content: [{ type: "text", text: "✅ No sensitive secrets detected." }] };
    } else {
        return {
            content: [{ type: "text", text: `⚠️ WARNING: Potential secrets found!\n\n${findings.join("\n")}\n\nDo NOT commit these files to a public repository.` }]
        };
    }
  }

  if (name === "check_gitignore") {
    let gitignorePath = (args as { path: string }).path;
    if (fs.statSync(gitignorePath).isDirectory()) {
        gitignorePath = path.join(gitignorePath, ".gitignore");
    }

    if (!fs.existsSync(gitignorePath)) {
        return { content: [{ type: "text", text: "❌ No .gitignore file found. It is highly recommended to create one." }], isError: true };
    }

    const content = fs.readFileSync(gitignorePath, 'utf8');
    const sensitiveFiles = [".env", "token.json", "credentials.json", "client_secret*.json", "GPG_KEY"];
    const missing = sensitiveFiles.filter(file => !content.includes(file));

    if (missing.length === 0) {
        return { content: [{ type: "text", text: "✅ .gitignore seems to cover common sensitive files." }] };
    } else {
        return {
            content: [{ type: "text", text: `⚠️ WARNING: .gitignore is missing patterns for: ${missing.join(", ")}.\nPlease add them to prevent accidental commits.` }]
        };
    }
  }

  throw new Error(`Tool not found: ${name}`);
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
