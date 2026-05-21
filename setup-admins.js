/**
 * Einmaliges Migrations-Skript: Erstellt Firebase Auth Accounts
 * aus den bestehenden Klartext-Zugängen in Firestore.
 *
 * Voraussetzung: Firebase Service Account Key als JSON-Datei.
 *
 * Verwendung:
 *   node setup-admins.js path/to/serviceAccountKey.json
 */

const admin = require('firebase-admin');

const keyPath = process.argv[2];
if (!keyPath) {
  console.error('Verwendung: node setup-admins.js <pfad-zum-serviceAccountKey.json>');
  process.exit(1);
}

const serviceAccount = require(keyPath.startsWith('/') || keyPath.startsWith('C:') ? keyPath : './' + keyPath);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const auth = admin.auth();
const db = admin.firestore();

async function migrate() {
  console.log('Lese bestehende Accounts aus Firestore...\n');

  const docSnap = await db.doc('config/userAccounts').get();
  if (!docSnap.exists) {
    console.error('Dokument config/userAccounts nicht gefunden.');
    process.exit(1);
  }

  const accounts = docSnap.data();
  const created = [];
  const errors = [];

  for (const [department, users] of Object.entries(accounts)) {
    const userList = Array.isArray(users) ? users : (users && users.user ? [users] : []);

    for (const user of userList) {
      if (!user.user || !user.pass) continue;

      const email = `${user.user}.${department}@ikt-komp-bbw.local`;
      const role = department === 'admin' ? 'admin' : 'department';

      try {
        // Prüfen ob Account bereits existiert
        try {
          const existing = await auth.getUserByEmail(email);
          console.log(`  SKIP: ${email} existiert bereits (uid: ${existing.uid})`);
          continue;
        } catch (e) {
          if (e.code !== 'auth/user-not-found') throw e;
        }

        const newUser = await auth.createUser({
          email,
          password: user.pass,
          displayName: `${user.user} (${department})`,
        });

        await auth.setCustomUserClaims(newUser.uid, { role, department });

        created.push({
          email,
          username: user.user,
          department,
          role,
          uid: newUser.uid,
        });

        console.log(`  OK: ${email} → role=${role}, department=${department}`);
      } catch (err) {
        errors.push({ email, error: err.message });
        console.error(`  FEHLER: ${email} → ${err.message}`);
      }
    }
  }

  console.log('\n========================================');
  console.log(`Erstellt: ${created.length} Accounts`);
  if (errors.length > 0) {
    console.log(`Fehler: ${errors.length}`);
  }

  if (created.length > 0) {
    console.log('\nErstellte Accounts:');
    console.log('──────────────────────────────────────');
    for (const c of created) {
      console.log(`  Abteilung: ${c.department}`);
      console.log(`  Username:  ${c.username}`);
      console.log(`  E-Mail:    ${c.email}`);
      console.log(`  Rolle:     ${c.role}`);
      console.log('──────────────────────────────────────');
    }
  }

  console.log('\nWICHTIG: Die Admins müssen nach der Migration NEUE Passwörter setzen!');
  console.log('Die alten Passwörter wurden übernommen, sind aber kompromittiert.\n');

  process.exit(0);
}

migrate().catch(err => {
  console.error('Migration fehlgeschlagen:', err);
  process.exit(1);
});
