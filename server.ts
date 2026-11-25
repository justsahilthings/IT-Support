import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { initializeDatabase, syncDepartmentDropdownOptions } from './server/db.ts';
import { seedDatabaseIfEmpty } from './server/seed.ts';
import { attachRealtimeWebSocket } from './server/realtime.ts';
import authRoutes from './server/routes/authRoutes.ts';
import ticketRoutes from './server/routes/ticketRoutes.ts';
import adminOpsRoutes from './server/routes/adminOpsRoutes.ts';
import analyticsIntegrationRoutes from './server/routes/analyticsIntegrationRoutes.ts';
import chatDropdownRoutes from './server/routes/chatDropdownRoutes.ts';
import publicRoutes from './server/routes/publicRoutes.ts';
import broadcastRoutes, { startBroadcastScheduler } from './server/routes/broadcastRoutes.ts';
import trafficRoutes from './server/routes/trafficRoutes.ts';
import { getEffectiveOutlookConfig, saveIntegrationSetting } from './server/integrations.ts';
import { writeAuditLog } from './server/auth.ts';
import { startBackupScheduler } from './server/backupService.ts';
import { appendSystemLog, initConsoleLogCapture } from './server/logCapture.ts';
import driveSyncRoutes from './server/routes/driveSyncRoutes.ts';

initConsoleLogCapture();

const SENSITIVE_HTTP_PATH_RE =
  /^\/(\.env.*|\.git.*|server\/.*|data\/.*|uploads\/.*|backups\/.*|package(?:-lock)?\.json|tsconfig\.json|vite\.config.*|bun\.lockb?)$/i;

async function startServer() {
  initializeDatabase();
  seedDatabaseIfEmpty();
  syncDepartmentDropdownOptions();
  startBroadcastScheduler();
  startBackupScheduler();

  const app = express();
  app.set('trust proxy', true);
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    const decodedPath = (() => {
      try {
        return decodeURIComponent(req.path || '/');
      } catch {
        return req.path || '/';
      }
    })();

    if (decodedPath.includes('..') || SENSITIVE_HTTP_PATH_RE.test(decodedPath)) {
      writeAuditLog({
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        entityType: 'protected_file',
        entityId: decodedPath.slice(0, 180),
        details: { method: req.method, reason: 'Blocked public access to source/config/storage path' },
        ipAddress: req.ip,
      });
      return res.status(403).json({ error: 'Forbidden: access to protected server resources is disabled' });
    }

    if (decodedPath.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      if (
        req.method !== 'GET' &&
        !decodedPath.startsWith('/api/auth/drive-sync/sync-now') &&
        !decodedPath.startsWith('/api/public/visit')
      ) {
        appendSystemLog('INFO', 'api', `${req.method} ${decodedPath}`);
      }
    }
    next();
  });
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Healthcheck
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Mount API routes
  app.use('/api/public', publicRoutes);
  app.use('/api/auth', authRoutes);
  app.use('/api/auth', driveSyncRoutes);
  app.use('/api/tickets', ticketRoutes);
  app.use('/api', adminOpsRoutes);
  app.use('/api', analyticsIntegrationRoutes);
  app.use('/api', chatDropdownRoutes);
  app.use('/api', broadcastRoutes);
  app.use('/api', trafficRoutes);
  app.all('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
  });

  // Microsoft Outlook OAuth 2.0 Callback Handler (Handles trailing slash variants)
  const outlookCallbackHandler = async (req: express.Request, res: express.Response) => {
    const code = req.query.code as string | undefined;
    const errorDesc = req.query.error_description as string | undefined;

    if (errorDesc || !code) {
      return res.send(`
        <html><body style="font-family:sans-serif;padding:24px;">
          <h3>Outlook OAuth Connection Failed</h3>
          <p>${errorDesc || 'No authorization code received.'}</p>
          <script>if(window.opener){window.opener.postMessage({type:'OUTLOOK_OAUTH_ERROR', error:${JSON.stringify(errorDesc || 'No code')}}, '*');}</script>
        </body></html>
      `);
    }

    try {
      const cfg = getEffectiveOutlookConfig();
      const baseUrl = (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
      const redirectUri = `${baseUrl}/auth/outlook/callback`;

      const tokenRes = await fetch(
        `https://login.microsoftonline.com/${encodeURIComponent(cfg.tenantId || 'common')}/oauth2/v2.0/token`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: cfg.clientId,
            client_secret: cfg.clientSecret,
            code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            scope: 'openid profile email offline_access User.Read Mail.Read Mail.Send',
          }),
        }
      );

      const tokenData = (await tokenRes.json()) as any;
      if (!tokenRes.ok || !tokenData.access_token) {
        throw new Error(tokenData.error_description || 'Token exchange failed');
      }

      // Fetch connected user profile email
      let connectedEmail = cfg.connectedEmail || '';
      const meRes = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      if (meRes.ok) {
        const meData = (await meRes.json()) as any;
        connectedEmail = meData.mail || meData.userPrincipalName || connectedEmail;
      }

      saveIntegrationSetting('outlook', {
        ...cfg,
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token || cfg.refreshToken,
        expiresAt: new Date(Date.now() + (tokenData.expires_in || 3600) * 1000).toISOString(),
        connectedEmail,
      });

      return res.send(`
        <html>
          <body style="font-family:sans-serif;padding:24px;">
            <p>Microsoft Outlook connected (${connectedEmail}). Closing window...</p>
            <script>
              if (window.opener) {
                window.opener.postMessage({ type: 'OUTLOOK_OAUTH_SUCCESS', email: ${JSON.stringify(connectedEmail)} }, '*');
                window.close();
              } else {
                window.location.href = '/';
              }
            </script>
          </body>
        </html>
      `);
    } catch (err: any) {
      return res.send(`
        <html><body style="font-family:sans-serif;padding:24px;">
          <h3>Outlook Token Exchange Error</h3>
          <p>${err?.message || 'Unknown error'}</p>
        </body></html>
      `);
    }
  };

  app.get(['/auth/outlook/callback', '/auth/outlook/callback/'], outlookCallbackHandler);

  // Global error handler for multer / json errors
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Request failed' });
    }
  });

  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve(process.cwd(), 'dist'));
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const server = http.createServer(app);
  attachRealtimeWebSocket(server);

  const PORT = 3000;
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`SD Global IT CRM Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
