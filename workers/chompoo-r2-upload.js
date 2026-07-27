export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsOrigin = getAllowedOrigin(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: buildCorsHeaders(corsOrigin)
      });
    }

    if (request.method === 'GET' && url.pathname.startsWith('/files/')) {
      const key = decodeURIComponent(url.pathname.replace('/files/', ''));
      if (!key) return json({ error: 'Missing file key' }, 400, corsOrigin);

      const object = await env.R2_BUCKET.get(key);
      if (!object) return json({ error: 'File not found' }, 404, corsOrigin);

      const headers = new Headers(buildCorsHeaders(corsOrigin));
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
      if (object.httpEtag) headers.set('ETag', object.httpEtag);

      return new Response(object.body, { status: 200, headers });
    }

    if (request.method !== 'POST' || (url.pathname !== '/upload' && url.pathname !== '/')) {
      return json({ error: 'Not found' }, 404, corsOrigin);
    }

    try {
      const authError = validateAuth(request, env);
      if (authError) return json({ error: authError }, 401, corsOrigin);

      const maxBytes = Number(env.MAX_UPLOAD_MB || 10) * 1024 * 1024;
      const contentType = request.headers.get('content-type') || '';
      let fileBuffer;
      let fileName = 'upload.bin';
      let fileType = 'application/octet-stream';
      let key = '';
      let folder = 'products';

      if (contentType.includes('multipart/form-data')) {
        const formData = await request.formData();
        const file = formData.get('file');
        if (!(file instanceof File)) {
          return json({ error: 'Missing file field in multipart/form-data' }, 400, corsOrigin);
        }

        fileName = file.name || fileName;
        fileType = file.type || fileType;
        folder = (formData.get('folder') || folder).toString();
        key = (formData.get('key') || '').toString();
        fileBuffer = await file.arrayBuffer();
      } else {
        const raw = await request.arrayBuffer();
        fileBuffer = raw;
        fileType = request.headers.get('content-type') || fileType;
        fileName = request.headers.get('x-filename') || fileName;
        folder = url.searchParams.get('folder') || folder;
        key = url.searchParams.get('key') || '';
      }

      if (!fileBuffer || fileBuffer.byteLength === 0) {
        return json({ error: 'Empty file payload' }, 400, corsOrigin);
      }

      if (fileBuffer.byteLength > maxBytes) {
        return json({ error: `File is too large. Max ${env.MAX_UPLOAD_MB || 10} MB` }, 413, corsOrigin);
      }

      const normalizedFolder = sanitizeFolder(folder);
      const finalKey = key
        ? sanitizeKey(key)
        : `${normalizedFolder}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}-${sanitizeFileName(fileName)}`;

      await env.R2_BUCKET.put(finalKey, fileBuffer, {
        httpMetadata: { contentType: fileType }
      });

      const publicBase = (env.R2_PUBLIC_BASE_URL || '').trim();
      const fileUrl = publicBase
        ? `${publicBase.replace(/\/$/, '')}/${finalKey}`
        : `${url.origin}/files/${encodeURIComponent(finalKey).replace(/%2F/g, '/')}`;

      return json({ ok: true, key: finalKey, url: fileUrl }, 200, corsOrigin);
    } catch (error) {
      return json({ error: error?.message || 'Upload failed' }, 500, corsOrigin);
    }
  }
};

function json(payload, status = 200, origin = '*') {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...buildCorsHeaders(origin)
    }
  });
}

function buildCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Filename',
    'Access-Control-Max-Age': '86400'
  };
}

function getAllowedOrigin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowList = String(env.ALLOWED_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean);

  if (!origin || allowList.length === 0) return '*';
  if (allowList.some(pattern => matchOrigin(pattern, origin))) return origin;
  return 'null';
}

function matchOrigin(pattern, origin) {
  if (pattern === '*') return true;
  if (pattern.startsWith('*.')) {
    const host = pattern.slice(2).toLowerCase();
    try {
      const originHost = new URL(origin).hostname.toLowerCase();
      return originHost === host || originHost.endsWith(`.${host}`);
    } catch {
      return false;
    }
  }
  return pattern.toLowerCase() === origin.toLowerCase();
}

function sanitizeFileName(name) {
  const base = (name || 'upload.bin').toLowerCase();
  return base
    .replace(/[^a-z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'upload.bin';
}

function sanitizeFolder(folder) {
  const clean = String(folder || 'products')
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+$/, '')
    .replace(/^\/+/, '')
    .replace(/[^a-zA-Z0-9/_-]/g, '');
  return clean || 'products';
}

function sanitizeKey(key) {
  return String(key || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/\.\./g, '')
    .replace(/[^a-zA-Z0-9._/-]/g, '-');
}

function validateAuth(request, env) {
  const requiredToken = (env.UPLOAD_TOKEN || '').trim();
  if (!requiredToken) return '';

  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token !== requiredToken) return 'Unauthorized';
  return '';
}
