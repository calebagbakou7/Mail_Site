# Tâches Bénin

Application Flask mobile-first de micro-tâches avec SQLite, portefeuille FCFA,
attribution de plusieurs tickets, validation textuelle et traitement des retraits.
Les réponses de tâche sont du texte ordinaire : l’application n’intègre aucun
collecteur de mots de passe, code 2FA, code à usage unique ou autre identifiant secret.

## Fonctionnalités

- Inscription avec téléphone béninois, réseau MTN/MOOV et mot de passe haché.
- Attribution atomique de tickets indépendants, avec un maximum de cinq tickets
  actifs ou en revue par utilisateur.
- Validation de réponse exacte (comparaison Unicode insensible à la casse) ou
  validation manuelle par l’administrateur.
- Crédit du portefeuille et journal comptable, une seule fois par ticket accepté.
- Retrait Mobile Money à partir du seuil configuré : le portefeuille est débité
  dans la même transaction SQLite que la création de la demande.
- Paiement administratif ou rejet avec remboursement atomique et idempotent.
- Protection CSRF des formulaires, cookies de session HttpOnly/SameSite et en-têtes
  de sécurité.

L’interface utilise une feuille CSS locale légère plutôt qu’une dépendance CDN :
elle reste utilisable sans charger une bibliothèque de styles externe.

## Installation (Windows PowerShell)

Depuis le dossier du projet :

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "remplacer-par-un-mot-de-passe-long-et-unique"
python app.py
```

Ouvrir `http://127.0.0.1:5000`. La base est créée automatiquement dans
`instance\crowdtasks.sqlite3`. Le chemin peut être changé avec `DATABASE_PATH`.

Pour un serveur accessible sur le réseau, configurez HTTPS devant l’application,
choisissez une clé `SECRET_KEY` persistante et unique, puis définissez
`COOKIE_SECURE=1`. Pour servir l’application avec Waitress :

```powershell
waitress-serve --listen=127.0.0.1:5000 app:app
```

Ne publiez pas `SECRET_KEY` ou `ADMIN_PASSWORD` dans le dépôt. En production,
fournissez-les au processus via un gestionnaire de secrets ou des variables
d’environnement protégées. Si aucun `ADMIN_PASSWORD` ou `ADMIN_PASSWORD_HASH`
n’est défini, la connexion administrateur est désactivée.

## Utilisation

1. Connectez-vous à `/admin/login` avec les variables d’environnement configurées.
2. Dans **Tickets**, créez une consigne textuelle, puis choisissez une validation
   exacte ou manuelle. Une réponse exacte ne doit jamais être un secret.
3. Les utilisateurs s’inscrivent, piochent des tickets et soumettent leurs réponses.
4. Les réponses manuelles sont vérifiées dans le tableau de bord administrateur.
5. Les demandes de retrait sont traitées dans **Retraits**. Le rejet recrédite le
   portefeuille dans la même transaction que le changement d’état.
6. La récompense des nouveaux tickets et le seuil minimal sont réglables dans
   **Configuration**. La récompense est figée lors de l’attribution du ticket.

## Tests

Avec Flask installé dans l’environnement :

```powershell
python -m unittest discover -s tests -v
```

La plateforme ne réalise pas elle-même les virements Mobile Money ; le statut
« payé » correspond à une confirmation manuelle de l’opérateur.
