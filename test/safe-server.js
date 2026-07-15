const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
const tools = [
  {
    name: 'read_file',
    description: 'Read the contents of a file from the local filesystem.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] }
  },
  {
    name: 'safe_tool',
    description: 'A simple calculator that adds two numbers.',
    inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'] }
  }
];
const prompts = [];
const resources = [
  { uri: 'file:///home/user/docs/readme.txt', name: 'readme', description: 'Readme file', mimeType: 'text/plain' }
];
rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch (e) { return; }
  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, prompts: {}, resources: {} }, serverInfo: { name: 'test-safe-server', version: '2.0.0' } } }) + '\n');
  } else if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools } }) + '\n');
  } else if (msg.method === 'prompts/list') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { prompts } }) + '\n');
  } else if (msg.method === 'resources/list') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { resources } }) + '\n');
  }
});
