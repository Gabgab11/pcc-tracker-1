// /api/upload-agent-photo.js
//
// Handles agent profile photo uploads via Vercel Blob (public access),
// replacing the old Firebase Storage upload. Mirrors the auth pattern in
// /api/reset-password.js: verify the caller's Firebase ID token with the
// Admin SDK, then allow the upload if the caller IS the target agent, or
// if the caller is admin uploading on someone else's behalf.
//
// Env vars needed (Vercel Project Settings -> Environment Variables):
//   FIREBASE_PROJECT_ID     (same as reset-password.js uses)
//   FIREBASE_CLIENT_EMAIL   (same as reset-password.js uses)
//   FIREBASE_PRIVATE_KEY    (same as reset-password.js uses)
//   BLOB_READ_WRITE_TOKEN   (auto-added by Vercel when you connected the
//                            Blob store to this project — nothing to do)

import { put } from '@vercel/blob';
import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';

if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    }),
  });
}

const ADMIN_EMAIL = 'info@unitedfund.net';

export const config = {
  api: { bodyParser: false }, // we read the raw file stream ourselves
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // ── 1. Verify the caller ──
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Missing auth token' });

    const decoded = await getAuth().verifyIdToken(idToken);
    const callerEmail = (decoded.email || '').toLowerCase();

    // ── 2. Read query params (agentId, filename passed as query string) ──
    const { targetAgentId, ext } = req.query;
    if (!targetAgentId) return res.status(400).json({ error: 'Missing targetAgentId' });

    // ── 3. Authorize: caller must own this agent doc, or be admin ──
    const db = getFirestore();
    const agentSnap = await db.collection('agents').doc(targetAgentId).get();
    if (!agentSnap.exists) return res.status(404).json({ error: 'Agent not found' });

    const agentEmail = (agentSnap.data().email || '').toLowerCase();
    const isAdmin = callerEmail === ADMIN_EMAIL;
    const isSelf = callerEmail === agentEmail;
    if (!isAdmin && !isSelf) {
      return res.status(403).json({ error: 'Not authorized to upload this photo' });
    }

    // ── 4. Upload to Vercel Blob (public) ──
    const safeExt = (ext || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
    const filename = `agent-photos/${targetAgentId}/${Date.now()}.${safeExt}`;

    const blob = await put(filename, req, {
      access: 'public',
      addRandomSuffix: false,
    });

    // ── 5. Save URL onto the agent doc ──
    await db.collection('agents').doc(targetAgentId).update({ photoURL: blob.url });

    return res.status(200).json({ url: blob.url });
  } catch (e) {
    console.error('upload-agent-photo error', e);
    return res.status(500).json({ error: e.message || 'Upload failed' });
  }
}
