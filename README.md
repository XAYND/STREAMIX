# STREAM-IX — Secure HLS Video Streaming

## Objectif

Cette brique permet de protéger la lecture des vidéos dans le projet STREAM-IX.

Au lieu de lire directement un fichier `.mp4`, la vidéo est transformée en flux HLS chiffré en AES-128.  
La clé AES n’est pas publique : elle est délivrée uniquement par un key-server si le front présente un token temporaire valide.

En résumé :

```text
vidéo chiffrée
→ token temporaire
→ demande de clé AES
→ vérification du token
→ lecture autorisée ou refusée
→ logs d’accès
