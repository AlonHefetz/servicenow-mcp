/**
 * Happy MCP Server - Express HTTP Server
 *
 * Copyright (c) 2025 Happy Technologies LLC
 * Licensed under the MIT License - see LICENSE file for details
 */

import express from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { ServiceNowClient } from './servicenow-client.js';
import { createMcpServer } from './mcp-server-consolidated.js';
import { configManager } from './config-manager.js';

// Load environment variables
dotenv.config();

// SSE configuration
const SSE_KEEPALIVE_INTERVAL = parseInt(process.env.SSE_KEEPALIVE_INTERVAL || '15000', 10); // Default: 15 seconds

const app = express();

// ============================================
// SECURITY: HTTP Headers & Rate Limiting
// ============================================
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for SSE compatibility
}));

// Rate limiting: 100 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

app.use(express.json());

// ============================================
// SECURITY: API Key Authentication (required by default)
// ============================================
const API_KEY = process.env.MCP_API_KEY;

// Fail-fast: require API key in production unless an explicit dev override is set
if (!API_KEY && process.env.MCP_ALLOW_NO_API_KEY !== 'true' && process.env.NODE_ENV !== 'development') {
  console.error('❌ FATAL: MCP_API_KEY is not set. For security the server requires MCP_API_KEY.');
  console.error('   To run locally for development only, set MCP_ALLOW_NO_API_KEY=true.');
  process.exit(1);
}

if (!API_KEY) {
  console.warn('⚠️  NOTICE: MCP running without API key (dev override enabled).');
}

// Authentication middleware
const authenticateRequest = (req, res, next) => {
  // Health check returns minimal info without auth
  if (req.path === '/health') {
    return next();
  }

  // If no API key configured, allow only when explicitly overridden for dev
  if (!API_KEY) {
    if (process.env.MCP_ALLOW_NO_API_KEY === 'true' || process.env.NODE_ENV === 'development') {
      console.warn(`⚠️ Allowing unauthenticated request to ${req.path} (dev override).`);
      return next();
    }
    return res.status(401).json({ error: 'Server misconfigured: MCP_API_KEY missing' });
  }

  // Check for API key in header or Bearer token
  const providedKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');

  if (!providedKey) {
    console.warn(`🚫 Unauthorized request to ${req.path} - missing API key`);
    return res.status(401).json({ error: 'Missing API key. Provide X-API-Key header.' });
  }

  // SECURITY: Hash both sides to fixed-length digests and use timingSafeEqual
  try {
    const providedHash = crypto.createHash('sha256').update(String(providedKey)).digest();
    const apiHash = crypto.createHash('sha256').update(String(API_KEY)).digest();

    if (!crypto.timingSafeEqual(providedHash, apiHash)) {
      console.warn(`🚫 Unauthorized request to ${req.path} - invalid API key`);
      return res.status(403).json({ error: 'Invalid API key' });
    }
  } catch (err) {
    console.error('❌ Error comparing API keys:', err);
    return res.status(500).json({ error: 'Internal authentication error' });
  }

  next();
};

// Apply authentication to all routes
app.use(authenticateRequest);

// In-memory session store (sessionId -> {server, transport})
const sessions = {};

// Get default instance configuration
const defaultInstance = configManager.getDefaultInstance();
console.log(`🔗 Default ServiceNow instance: ${defaultInstance.name} (${defaultInstance.url})`);
console.log(`💡 Use SN-Set-Instance tool to switch instances during session`);

// Create ServiceNow client with default instance
const serviceNowClient = new ServiceNowClient(
  defaultInstance.url,
  defaultInstance.username,
  defaultInstance.password
);
serviceNowClient.currentInstanceName = defaultInstance.name;

/**
 * GET /mcp - Establish SSE connection
 */
app.get('/mcp', async (req, res) => {
  try {
    // SSE-specific headers to prevent buffering and timeouts
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering
    res.setHeader('Connection', 'keep-alive');

    // Disable timeout for SSE endpoint (0 = infinite)
    req.setTimeout(0);
    res.setTimeout(0);

    // Create transport and start SSE connection
    const transport = new SSEServerTransport('/mcp', res);

    // Create and configure new MCP server instance
    const server = await createMcpServer(serviceNowClient);

    // Set up keepalive heartbeat to prevent connection timeout
    // Send a comment every N seconds to keep connection alive
    const keepaliveInterval = setInterval(() => {
      try {
        // Send SSE comment (starts with :) to keep connection alive
        res.write(': keepalive\n\n');
      } catch (error) {
        console.error('❌ Keepalive failed, clearing interval:', error.message);
        clearInterval(keepaliveInterval);
      }
    }, SSE_KEEPALIVE_INTERVAL);

    // Set up transport cleanup
    transport.onclose = () => {
      if (sessions[transport.sessionId]) {
        clearInterval(keepaliveInterval);
        delete sessions[transport.sessionId];
        console.log(`🧹 Cleaned up session ${transport.sessionId}`);
      }
    };

    // Clean up on request close/error
    req.on('close', () => {
      clearInterval(keepaliveInterval);
      if (sessions[transport.sessionId]) {
        delete sessions[transport.sessionId];
        console.log(`🔌 Client disconnected: ${transport.sessionId}`);
      }
    });

    req.on('error', (error) => {
      console.error('❌ Request error:', error);
      clearInterval(keepaliveInterval);
    });

    // Store the session
    sessions[transport.sessionId] = { server, transport, keepaliveInterval };
    console.log(`🔗 New session established: ${transport.sessionId}`);

    // connect() starts the transport automatically in current MCP SDK
    await server.connect(transport);

  } catch (error) {
    console.error('❌ Error establishing SSE connection:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to establish SSE connection' });
    }
  }
});

/**
 * POST /mcp - Handle JSON-RPC messages
 */
app.post('/mcp', async (req, res) => {
  try {
    const sessionId = req.query.sessionId;

    if (!sessionId || !sessions[sessionId]) {
      return res.status(400).json({
        error: 'Invalid or missing session ID'
      });
    }

    const { transport } = sessions[sessionId];
    // express.json() already consumed the stream, so pass parsed body
    await transport.handlePostMessage(req, res, req.body);

  } catch (error) {
    console.error('❌ Error handling POST message:', error);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

// Health check endpoint - SECURITY: Don't expose internal URLs
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '3.0.1'
    // Note: Instance details removed for security - use /instances with auth
  });
});

// List available instances endpoint
app.get('/instances', (req, res) => {
  try {
    const instances = configManager.listInstances();
    res.json({ instances });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
// SECURITY FIX: Default to localhost, not 0.0.0.0
const HOST = process.env.MCP_BIND_HOST || '127.0.0.1';

if (HOST === '0.0.0.0') {
  console.warn('⚠️  WARNING: Binding to 0.0.0.0 exposes server to all network interfaces!');
  console.warn('   Ensure firewall rules are in place or use a reverse proxy.');
}

app.listen(PORT, HOST, () => {
  console.log(`🚀 Happy MCP Server listening on ${HOST}:${PORT}`);
  console.log(`📊 Health check: http://${HOST}:${PORT}/health`);
  console.log(`🔌 MCP SSE endpoint: http://${HOST}:${PORT}/mcp`);
  console.log(`📋 Available instances: http://${HOST}:${PORT}/instances`);
  console.log(`💓 SSE keepalive interval: ${SSE_KEEPALIVE_INTERVAL}ms`);

  if (process.env.DEBUG === 'true') {
    console.log('🐛 Debug mode enabled');
    console.log(`🔗 Active ServiceNow instance: ${defaultInstance.name} - ${defaultInstance.url}`);
  }
});
