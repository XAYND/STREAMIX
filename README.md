# STREAM-IX — Secure HLS Video Streaming

## Objectif

Cette brique permet de protéger la lecture des vidéos dans le projet STREAM-IX.

Au lieu de lire directement un fichier `.mp4`, la vidéo est transformée en flux HLS chiffré en AES-128.  
La clé AES n’est pas publique : elle est délivrée uniquement par un key-server si le front présente un token temporaire valide.

En résumé :

```text
vidéo chiffrée
→ login utilisateur (email + mot de passe)
→ session token (JWT)
→ token temporaire HLS (si l'utilisateur a le droit de voir la vidéo)
→ demande de clé AES
→ vérification du token
→ lecture autorisée ou refusée
→ logs d’accès
```

## Authentification (backend/key-server)

La session de démo (header `X-Streamix-Session`) a été remplacée par une
vraie authentification utilisateur, adossée à une base SQLite locale
(`backend/key-server/data/streamix.db`, générée automatiquement, gitignored) :

- `POST /auth/login` — `{ email, password }` → vérifie le mot de passe
  (haché avec bcrypt) et renvoie un `session_token` (JWT signé, TTL
  configurable via `SESSION_TTL_SECONDS`).
- `POST /auth/register` — crée un compte (mot de passe 8+ caractères). Pour
  la démo, un nouveau compte reçoit automatiquement l'accès à `VIDEO_ID` ;
  en production il faudrait retirer cet octroi automatique.
- `GET /token` — désormais protégé par `Authorization: Bearer <session_token>`
  (au lieu du header de démo). Vérifie la session, puis que l'utilisateur a
  bien accès à `VIDEO_ID` (table `video_access`) avant d'émettre le token
  HLS temporaire.

Un compte de démo est semé automatiquement au démarrage à partir de
`DEMO_USER_EMAIL` / `DEMO_USER_PASSWORD` (voir `.env.example`), avec accès à
`VIDEO_ID`.
