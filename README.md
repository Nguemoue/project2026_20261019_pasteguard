# PasteGuard

Un log Laravel, un `.env`, un header `Authorization` : trois secondes plus tard c'est dans Slack, une issue GitHub, ou un prompt. PasteGuard masque le secret **avant** le collage.

Zero dependance. PHP 8.1+. Un fichier a lire, une commande a lancer.

```bash
php examples/make-leaky.php | php bin/pasteguard
```

Le texte propre sort sur **stdout** (a copier). Le bilan sort sur **stderr** :

```text
pasteguard: masque 6 (aws_access_key 1, email 1, github_token 1, jwt 1, payment_card 1, url_password 1)
```

`password=changeme` est laisse tel quel : c'est un placeholder, pas un secret. `docs@example.com` aussi.

## Install

```bash
git clone https://github.com/Nguemoue/project2026_20261019_pasteguard.git
cd project2026_20261019_pasteguard
php bin/pasteguard --demo
```

Composer est optionnel (`composer install` ajoute seulement l'autoload). Sans Composer, le binaire charge `src/` tout seul.

## Usage

```bash
php bin/pasteguard storage/logs/laravel.log > /tmp/clean.log
cat .env | php bin/pasteguard --no-email
php bin/pasteguard --check --quiet incident.log ; echo $?
```

| Option | Effet |
| --- | --- |
| `--demo` | Avant/apres integre, rien a fournir |
| `--check` | Exit `1` si quelque chose a ete masque (gate CI), le texte masque est quand meme affiche |
| `--json` | `{"text","counts","total"}` sur stdout |
| `--no-email` | Garde les adresses e-mail |
| `--ips` | Masque aussi les IPv4 (desactive par defaut : un log sans IP ne se relit plus) |
| `--quiet` | Pas de resume stderr |
| `-h`, `-v` | Aide, version |

Plusieurs fichiers : chacun est precede de `===== chemin =====`.

## Ce qui est masque

| Type | Exemple de forme | Remplacement |
| --- | --- | --- |
| Cle privee PEM | bloc `BEGIN PRIVATE KEY` | `[REDACTED:pem_private_key]` |
| GitHub / GitLab / npm | prefixe connu + entropie | `[REDACTED:github_token]` … |
| Slack (token + webhook) | `xoxb-` / `hooks.slack.com` | idem |
| Stripe, AWS access key, Google, OpenAI, SendGrid | prefixe connu | idem |
| JWT | `eyJ…`.`eyJ…`.signature | `[REDACTED:jwt]` |
| URL avec mot de passe | `postgres://user:secret@host` | le user reste, le secret non |
| `Authorization: Bearer` / `Basic` | header | le scheme reste |
| Affectation | `DB_PASSWORD`, `API_KEY`, `AWS_SECRET_ACCESS_KEY`, `token=` … | valeur seulement |
| E-mail | sauf `example.com` / `example.org` / `example.net` / `test.com` / `localhost` | `[REDACTED:email]` |
| Carte (Luhn) | chiffres separes, ou mot `card`/`visa`/`pan` a cote | `[REDACTED:payment_card]` |

Les valeurs bidon ne bougent pas : `changeme`, `password`, `secret`, `xxx`, `${VAR}`, `{{ template }}`, `<secret>`.

## Limites

C'est un filtre, pas un audit. Un secret sans forme reconnaissable (`hunter2` colle au milieu d'une phrase) passe. Un faux positif reste possible sur une longue chaine mixte assignee a `token`. Relis le stdout avant de l'envoyer.

Les numeros de carte isoles, sans separateurs ni mot-cle, sont gardes : trop de faux positifs sur les identifiants.

## Tester

```bash
php tests/run.php
```

Le workflow GitHub Actions rejoue la suite sur PHP 8.1, 8.3 et 8.4.

## Licence

MIT.
