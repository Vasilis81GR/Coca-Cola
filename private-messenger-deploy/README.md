# Private Messenger

Ιδιωτική εφαρμογή συνομιλίας — σαν Viber, αλλά **δική σου**. Προσθέτεις επαφές
μόνο με σάρωση QR, και τα μηνύματα είναι **end-to-end κρυπτογραφημένα** (ούτε ο
server σου τα διαβάζει). Δεν ανεβαίνει σε κανένα app store· το hostάρεις εσύ.

## Τι είναι

- **PWA** (installable web app): τρέχει σε Android + iPhone από τον browser, μπαίνει στο home screen σαν κανονικό app. Χωρίς Play Store / App Store.
- **Self-hosted Node server**: ένας relay που περνάει τα (ήδη κρυπτογραφημένα) μηνύματα και τα κρατάει σε ουρά όταν ο παραλήπτης είναι offline.
- **E2E encryption**: κάθε συσκευή φτιάχνει τα δικά της κλειδιά (P-256). Κρυπτογράφηση AES-256-GCM με κλειδί που προκύπτει από ECDH ανά επαφή. Ο server βλέπει μόνο ciphertext.
- **QR pairing**: προσθέτεις κάποιον μόνο σκανάροντας το QR του. Μόνο όποιον έχεις προσθέσει μπορεί να σου γράψει.

## Δομή

```
server/   Node relay (WebSocket + static + QR endpoint)
public/   Η PWA (HTML/CSS/JS, όλη η κρυπτογράφηση τρέχει εδώ, στον browser)
Dockerfile, docker-compose.yml, Caddyfile   deploy με auto-HTTPS
```

## Γρήγορη δοκιμή (τοπικά)

```bash
cd server
npm install
npm start
```

Άνοιξε `http://localhost:8080` σε δύο καρτέλες/browsers. Στη μία δείξε το QR σου
(κουμπί ▣), στην άλλη σκάναρε (κουμπί ＋). Γράψε — τα μηνύματα περνάνε real-time.

> Σημείωση: σε `localhost` η κάμερα δουλεύει. Σε άλλη διεύθυνση **χρειάζεται HTTPS**
> (δες παρακάτω) — αλλιώς ο browser μπλοκάρει την κάμερα για το QR scan.

## Deploy για χρήση από παντού (internet)

Χρειάζεσαι έναν server (VPS ~4-5€/μήνα, ή δικό σου μηχάνημα) και ένα **domain**.

1. Στρέψε ένα A record του domain (π.χ. `chat.to-domain-sou.gr`) στην IP του server.
2. Άλλαξε το `chat.example.com` στο `Caddyfile` με το domain σου.
3. Σήκωσέ το:

```bash
docker compose up -d
```

Ο Caddy βγάζει **αυτόματα HTTPS** (Let's Encrypt) και κάνει proxy web + WebSocket.
Ανοίγεις `https://chat.to-domain-sou.gr` στο κινητό → "Add to Home Screen".

Χωρίς Docker: τρέξε `node server/server.js` και βάλε μπροστά Caddy/nginx με HTTPS
(στο Caddyfile βάλε `reverse_proxy localhost:8080`).

## Πώς μπαίνει σαν app

- **Android (Chrome)**: μενού ⋮ → "Install app" / "Add to Home screen".
- **iPhone (Safari)**: κουμπί Share → "Add to Home Screen".

## Ασφάλεια — τι ισχύει ειλικρινά

**Ναι:**
- Τα μηνύματα είναι E2E κρυπτογραφημένα· ο server δεν τα διαβάζει.
- Auth με signature challenge: κανείς δεν μπορεί να παριστάνει το ID σου χωρίς το ιδιωτικό σου κλειδί.
- Η ανταλλαγή κλειδιών γίνεται από κοντά (σκανάρεις το QR), άρα δεν υπάρχει man-in-the-middle στο pairing.

**Όρια (MVP — να τα ξέρεις):**
- Τα κλειδιά ζουν στον browser (IndexedDB). Καθάρισμα δεδομένων browser = χάνεις ταυτότητα/ιστορικό. (Δεν υπάρχει ακόμα backup/export.)
- Χωρίς forward secrecy (το κλειδί ανά επαφή είναι σταθερό). Για προσωπική χρήση σε έμπιστη ομάδα είναι μια χαρά· για threat model υψηλού κινδύνου θέλει Signal-protocol (double ratchet).
- Μόνο text μηνύματα προς το παρόν. Όχι φωτό/αρχεία/κλήσεις/group chats (ακόμα).
- Ο server κρατάει σε ουρά τα offline μηνύματα (κρυπτογραφημένα) μέχρι να παραδοθούν.

## Επόμενα βήματα (αν θες)
Εικόνες/αρχεία, group chats, φωνητικά, export/backup ταυτότητας, push notifications
μέσω Web Push. Πες μου ποιο θες πρώτο.
