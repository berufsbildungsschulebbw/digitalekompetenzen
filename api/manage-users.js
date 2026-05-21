const admin = require('firebase-admin');

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const auth = admin.auth();

async function verifyAdmin(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const idToken = authHeader.split('Bearer ')[1];
  const decoded = await auth.verifyIdToken(idToken);
  if (decoded.role !== 'admin') {
    return null;
  }
  return decoded;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const caller = await verifyAdmin(req);
    if (!caller) {
      return res.status(403).json({ error: 'Nur Hauptadmins dürfen Benutzer verwalten.' });
    }

    if (req.method === 'GET') {
      const listResult = await auth.listUsers(100);
      const users = listResult.users
        .filter(u => u.customClaims && u.customClaims.role)
        .map(u => ({
          uid: u.uid,
          email: u.email,
          username: u.email.split('.')[0],
          department: u.customClaims.department || 'admin',
          role: u.customClaims.role,
        }));
      return res.status(200).json({ users });
    }

    if (req.method === 'POST') {
      const { username, password, department, role } = req.body;

      if (!username || !password || !department) {
        return res.status(400).json({ error: 'Username, Passwort und Abteilung sind erforderlich.' });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: 'Passwort muss mindestens 6 Zeichen haben.' });
      }

      const email = `${username}.${department}@ikt-komp-bbw.local`;
      const userRole = role || (department === 'admin' ? 'admin' : 'department');

      const userRecord = await auth.createUser({
        email,
        password,
        displayName: `${username} (${department})`,
      });

      await auth.setCustomUserClaims(userRecord.uid, {
        role: userRole,
        department,
      });

      return res.status(201).json({
        uid: userRecord.uid,
        email,
        username,
        department,
        role: userRole,
      });
    }

    if (req.method === 'PUT') {
      const { uid, password, department, role } = req.body;

      if (!uid) {
        return res.status(400).json({ error: 'UID ist erforderlich.' });
      }

      const updates = {};
      if (password && password.length >= 6) {
        updates.password = password;
      }

      if (Object.keys(updates).length > 0) {
        await auth.updateUser(uid, updates);
      }

      if (department || role) {
        const user = await auth.getUser(uid);
        const currentClaims = user.customClaims || {};
        await auth.setCustomUserClaims(uid, {
          ...currentClaims,
          ...(department && { department }),
          ...(role && { role }),
        });
      }

      return res.status(200).json({ success: true });
    }

    if (req.method === 'DELETE') {
      const { uid } = req.body;
      if (!uid) {
        return res.status(400).json({ error: 'UID ist erforderlich.' });
      }

      const user = await auth.getUser(uid);
      if (user.customClaims && user.customClaims.role === 'admin') {
        const listResult = await auth.listUsers(100);
        const adminCount = listResult.users.filter(
          u => u.customClaims && u.customClaims.role === 'admin'
        ).length;
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'Der letzte Admin kann nicht gelöscht werden.' });
        }
      }

      await auth.deleteUser(uid);
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (error) {
    console.error('manage-users error:', error);
    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({ error: 'Dieser Benutzername existiert bereits für diese Abteilung.' });
    }
    return res.status(500).json({ error: error.message });
  }
};
