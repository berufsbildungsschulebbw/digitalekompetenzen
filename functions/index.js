const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const cors = require("cors")({ origin: true });

admin.initializeApp();
const auth = admin.auth();

async function verifyAdmin(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const idToken = authHeader.split("Bearer ")[1];
  const decoded = await auth.verifyIdToken(idToken);
  if (decoded.role !== "admin") return null;
  return decoded;
}

exports.manageUsers = onRequest({ region: "europe-west1" }, (req, res) => {
  cors(req, res, async () => {
    try {
      const caller = await verifyAdmin(req);
      if (!caller) {
        return res.status(403).json({ error: "Nur Hauptadmins dürfen Benutzer verwalten." });
      }

      if (req.method === "GET") {
        const listResult = await auth.listUsers(100);
        const users = listResult.users
          .filter((u) => u.customClaims && u.customClaims.role)
          .map((u) => ({
            uid: u.uid,
            email: u.email,
            username: u.email.split(".")[0],
            department: u.customClaims.department || "admin",
            role: u.customClaims.role,
          }));
        return res.status(200).json({ users });
      }

      if (req.method === "POST") {
        const { username, password, department, role } = req.body;
        if (!username || !password || !department) {
          return res.status(400).json({ error: "Username, Passwort und Abteilung sind erforderlich." });
        }
        if (password.length < 6) {
          return res.status(400).json({ error: "Passwort muss mindestens 6 Zeichen haben." });
        }

        const email = `${username}.${department}@ikt-komp-bbw.local`;
        const userRole = role || (department === "admin" ? "admin" : "department");

        const userRecord = await auth.createUser({
          email,
          password,
          displayName: `${username} (${department})`,
        });

        await auth.setCustomUserClaims(userRecord.uid, { role: userRole, department });

        return res.status(201).json({
          uid: userRecord.uid,
          email,
          username,
          department,
          role: userRole,
        });
      }

      if (req.method === "PUT") {
        const { uid, password, department, role } = req.body;
        if (!uid) {
          return res.status(400).json({ error: "UID ist erforderlich." });
        }

        if (password && password.length >= 6) {
          await auth.updateUser(uid, { password });
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

      if (req.method === "DELETE") {
        const { uid } = req.body;
        if (!uid) {
          return res.status(400).json({ error: "UID ist erforderlich." });
        }

        const user = await auth.getUser(uid);
        if (user.customClaims && user.customClaims.role === "admin") {
          const listResult = await auth.listUsers(100);
          const adminCount = listResult.users.filter(
            (u) => u.customClaims && u.customClaims.role === "admin"
          ).length;
          if (adminCount <= 1) {
            return res.status(400).json({ error: "Der letzte Admin kann nicht gelöscht werden." });
          }
        }

        await auth.deleteUser(uid);
        return res.status(200).json({ success: true });
      }

      return res.status(405).json({ error: "Method not allowed" });
    } catch (error) {
      console.error("manageUsers error:", error);
      if (error.code === "auth/email-already-exists") {
        return res.status(400).json({ error: "Dieser Benutzername existiert bereits für diese Abteilung." });
      }
      return res.status(500).json({ error: error.message });
    }
  });
});

exports.migrateUsers = onRequest({ region: "europe-west1" }, (req, res) => {
  cors(req, res, async () => {
    try {
      const caller = await verifyAdmin(req);
      if (!caller) {
        return res.status(403).json({ error: "Nur Hauptadmins dürfen migrieren." });
      }

      const db = admin.firestore();
      const docSnap = await db.doc("config/userAccounts").get();
      if (!docSnap.exists) {
        return res.status(404).json({ error: "config/userAccounts nicht gefunden." });
      }

      const accounts = docSnap.data();
      const created = [];
      const errors = [];

      for (const [department, users] of Object.entries(accounts)) {
        const userList = Array.isArray(users) ? users : (users && users.user ? [users] : []);
        for (const user of userList) {
          if (!user.user || !user.pass) continue;
          const email = `${user.user}.${department}@ikt-komp-bbw.local`;
          const role = department === "admin" ? "admin" : "department";

          try {
            try {
              await auth.getUserByEmail(email);
              continue;
            } catch (e) {
              if (e.code !== "auth/user-not-found") throw e;
            }

            const newUser = await auth.createUser({
              email,
              password: user.pass,
              displayName: `${user.user} (${department})`,
            });
            await auth.setCustomUserClaims(newUser.uid, { role, department });
            created.push({ email, username: user.user, department, role });
          } catch (err) {
            errors.push({ email, error: err.message });
          }
        }
      }

      return res.status(200).json({ created, errors });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  });
});
