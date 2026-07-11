# attest-bot

Bot Telegram di attestazione e verifica per [Spazio Genesi ETS](https://spaziogenesi.org) —
[attestazione.spaziogenesi.org](https://attestazione.spaziogenesi.org).

**In produzione**: [@SGAttestBot](https://t.me/SGAttestBot) su
`https://attest-bot.it-e3f.workers.dev`.

**Canale comodità, non il canale a privacy totale.** Dal sito, il file che attesti
non lascia mai il tuo dispositivo (l'impronta si calcola nel browser). Qui su
Telegram, il file che invii al bot **transita** per i server di Telegram e per
questo Worker: l'impronta si calcola in streaming e i byte si scartano subito
— **nulla viene salvato** — ma il transito avviene, e il bot lo dichiara prima
di scaricare qualunque file. Per la privacy assoluta, usa il sito.

## Cosa fa

- **Attesta** un file inviato in chat (impronta SHA-256, timestamp server,
  firma HMAC — stesso motore del sito) e genera il certificato PDF firmato.
- **Verifica** un'impronta, un certificato PDF, o un file rispetto a
  un'attestazione esistente.
- **Recupera** un certificato smarrito dall'impronta (`/certificato <hash>`).
- Mostra lo **stato dei servizi** (`/stato`).

## Architettura

Client puro dell'[API pubblica di imgauth](https://imgauth.spaziogenesi.org/docs)
— nessuna modifica al motore di attestazione, nessuna nuova route Cloudflare.
Cloudflare Worker in modalità webhook (Telegram Bot API), D1 dedicata per lo
stato minimo del bot (accettazione dell'avvertenza, quote giornaliere — mai i
byte di un file). Dettagli e razionale completo delle decisioni in
[`../img-auth-hub/P23-DESIGN-telegram-bot.md`](../img-auth-hub/P23-DESIGN-telegram-bot.md).

## Sviluppo locale

```
npm install
wrangler d1 create attest-bot   # copia il database_id in wrangler.toml
wrangler d1 execute attest-bot --local --file=schema/bot.sql
cp .dev.vars.example .dev.vars  # compila con un bot di TEST (mai quello di produzione)
wrangler dev
```

Vedi `test/run-local.md` per iniettare update di Telegram finti via curl senza
un vero webhook in ingresso (l'uscita usa comunque il bot Telegram reale
indicato in `.dev.vars`: i messaggi arrivano davvero in chat).

## Licenza

MIT — vedi [LICENSE](LICENSE).
