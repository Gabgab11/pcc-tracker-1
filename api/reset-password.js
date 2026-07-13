// api/reset-password.js
// Runs on Vercel's free Hobby tier — no billing plan required.
// Uses a Firebase service account (also free, no Blaze needed) to
// call the Admin SDK directly, which is the only thing that can
// actually change another user's password.

const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Env vars store newlines as literal "\n" — convert back to real ones.
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    }),
  });
}

const db = admin.firestore();

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 1. Verify the caller is a logged-in Firebase user at all.
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Missing auth token' });

    const decoded = await admin.auth().verifyIdToken(idToken);
    const callerUid = decoded.uid;

    // 2. Verify the caller is specifically an admin (checked server-side,
    //    against Firestore — never trust a role sent from the client).
    const callerSnap = await db.collection('agents').where('uid', '==', callerUid).limit(1).get();
    if (callerSnap.empty || callerSnap.docs[0].data().role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // 3. Validate input.
    const { targetAgentId, newPassword } = req.body || {};
    if (!targetAgentId || !newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'Missing agent id or password too short' });
    }

    const targetRef = db.collection('agents').doc(targetAgentId);
    const targetDoc = await targetRef.get();
    if (!targetDoc.exists) return res.status(404).json({ error: 'Agent not found' });
    const targetData = targetDoc.data();

    let targetUid = targetData.uid;

    // 4. Change the password. If the agent has never logged in yet (no uid
    //    on file), create their Auth account instead — this replaces the
    //    old "Add user" manual step in the Console.
    if (targetUid) {
      await admin.auth().updateUser(targetUid, { password: newPassword });
    } else {
      if (!targetData.email) return res.status(400).json({ error: 'Agent has no email on file' });
      const newUser = await admin.auth().createUser({
        email: targetData.email,
        password: newPassword,
      });
      targetUid = newUser.uid;
      await targetRef.update({ uid: targetUid });
    }

    // 5. Force them to pick their own password on next login, same as
    //    the existing client-side flow already expects.
    await db.collection('users').doc(targetUid).set(
      { mustChangePassword: true, updatedAt: new Date().toISOString() },
      { merge: true }
    );

    await targetRef.update({ lastPasswordResetAt: new Date().toISOString() });

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('reset-password error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
