const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const cors = require("cors")({ origin: true });
const crypto = require("crypto");

// Salt fuer das Hashen von IP-Adressen (Rate-Limit). Ueber Umgebungsvariable
// ANON_IP_SALT setzbar; der Fallback ist projektspezifisch und ausreichend.
const ANON_IP_SALT = process.env.ANON_IP_SALT || "ikt-komp-bbw-anon";

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

exports.manageUsers = onRequest({ region: "europe-west1", invoker: "public" }, (req, res) => {
  cors(req, res, async () => {
    try {
      const caller = await verifyAdmin(req);
      if (!caller) {
        return res.status(403).json({ error: "Nur Hauptadmins dürfen Benutzer verwalten." });
      }

      if (req.method === "GET") {
        const listResult = await auth.listUsers(1000);
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
          const listResult = await auth.listUsers(1000);
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

exports.migrateUsers = onRequest({ region: "europe-west1", invoker: "public" }, (req, res) => {
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

// ── Selbstbedienungs-Zugang «Anonym» ─────────────────────────────────────────
// Erzeugt auf Anfrage einen Zufallscode der Abteilung "anonym". Damit können
// Lehrpersonen ohne Code ihrer Abteilungsleitung teilnehmen; die Ergebnisse
// werden im Adminbereich als eigene Abteilung geführt.

const ANON_DEPARTMENT = "anonym";
// Drei gestaffelte Kontingente im rollierenden Stundenfenster:
// - pro Browser-Identität (anonyme Firebase-UID): bremst Klick-Spam aus einem Browser
// - pro Anschluss (IP-Hash): bewusst grosszügig, weil im Schulhaus alle Lehrpersonen
//   hinter derselben öffentlichen IP sitzen (NAT)
// - global: Notbremse gegen verteilte Anfragen
const ANON_MAX_PER_USER_PER_HOUR = 2;
const ANON_MAX_PER_IP_PER_HOUR = 100;
const ANON_MAX_GLOBAL_PER_HOUR = 200;
const ANON_WINDOW_MS = 60 * 60 * 1000;

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length) return fwd.split(",")[0].trim();
  return req.ip || "unknown";
}

// IP nie im Klartext ablegen – nur ein gesalzener Hash zur Missbrauchserkennung.
function hashIp(ip) {
  return crypto
    .createHash("sha256")
    .update(`${ANON_IP_SALT}:${ip}`)
    .digest("hex")
    .slice(0, 32);
}

function randomAnonCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // ohne I/O/0/1
  let suffix = "";
  const bytes = crypto.randomBytes(5);
  for (let i = 0; i < 5; i++) suffix += chars[bytes[i] % chars.length];
  return `ANON-${suffix}`;
}

// Prüft alle Kontingente atomar in einer Transaktion. Die Zähler werden nur
// erhöht, wenn jedes Kontingent Platz hat – eine abgewiesene Anfrage verbraucht
// also nichts (sonst würde z. B. die globale Bremse das Browser-Kontingent leeren).
async function consumeQuotas(db, quotas) {
  const refs = quotas.map((q) => db.collection("anonRateLimits").doc(q.key));
  return db.runTransaction(async (tx) => {
    const now = Date.now();
    const snaps = await tx.getAll(...refs);
    const states = snaps.map((snap) => {
      const data = snap.exists ? snap.data() : null;
      const expired = !data || now - data.windowStart >= ANON_WINDOW_MS;
      return {
        windowStart: expired ? now : data.windowStart,
        count: expired ? 0 : data.count,
      };
    });

    for (let i = 0; i < quotas.length; i++) {
      if (states[i].count >= quotas[i].limit) {
        return {
          allowed: false,
          scope: quotas[i].scope,
          retryAfterMs: states[i].windowStart + ANON_WINDOW_MS - now,
        };
      }
    }
    for (let i = 0; i < quotas.length; i++) {
      tx.set(
        refs[i],
        { windowStart: states[i].windowStart, count: states[i].count + 1, lastRequest: now },
        { merge: true }
      );
    }
    return { allowed: true };
  });
}

exports.createAnonCode = onRequest({ region: "europe-west1", invoker: "public" }, (req, res) => {
  cors(req, res, async () => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
      }

      // Gültiger Firebase-Token nötig (anonyme Anmeldung genügt).
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Nicht angemeldet." });
      }
      let caller;
      try {
        caller = await auth.verifyIdToken(authHeader.split("Bearer ")[1]);
      } catch (e) {
        return res.status(401).json({ error: "Anmeldung ungültig." });
      }

      const db = admin.firestore();
      const ipHash = hashIp(clientIp(req));

      const quota = await consumeQuotas(db, [
        { scope: "user", key: `uid_${caller.uid}`, limit: ANON_MAX_PER_USER_PER_HOUR },
        { scope: "ip", key: `ip_${ipHash}`, limit: ANON_MAX_PER_IP_PER_HOUR },
        { scope: "global", key: "global", limit: ANON_MAX_GLOBAL_PER_HOUR },
      ]);
      if (!quota.allowed) {
        const minutes = Math.max(1, Math.ceil(quota.retryAfterMs / 60000));
        const messages = {
          user: `In diesem Browser wurden bereits ${ANON_MAX_PER_USER_PER_HOUR} anonyme Zugänge erstellt. Bitte den vorhandenen Code weiterverwenden oder in ${minutes} Minuten erneut versuchen.`,
          ip: `Aus diesem Netzwerk wurden in der letzten Stunde sehr viele anonyme Zugänge erstellt. Bitte in ${minutes} Minuten erneut versuchen.`,
          global: "Aktuell werden sehr viele anonyme Zugänge erstellt. Bitte später erneut versuchen.",
        };
        return res.status(429).json({ error: messages[quota.scope] });
      }

      // Code erzeugen und Eindeutigkeit sicherstellen.
      let code = null;
      for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = randomAnonCode();
        const existing = await db.collection("codes").where("code", "==", candidate).limit(1).get();
        if (existing.empty) {
          code = candidate;
          break;
        }
      }
      if (!code) {
        return res.status(500).json({ error: "Code konnte nicht erzeugt werden. Bitte erneut versuchen." });
      }

      await db.collection("codes").add({
        code,
        description: "Selbstzugang (anonym)",
        department: ANON_DEPARTMENT,
        source: "self-service",
        ipHash,
        authUid: caller.uid,
        created: new Date().toLocaleDateString("de-DE"),
        timestamp: Date.now(),
        createdTimestamp: admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(201).json({ code, department: ANON_DEPARTMENT });
    } catch (error) {
      console.error("createAnonCode error:", error);
      return res.status(500).json({ error: error.message });
    }
  });
});
