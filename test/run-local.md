# Test locale senza webhook reale

`wrangler dev` non riceve update da Telegram (nessun webhook pubblico in
locale): si inietta un update finto via `curl` su `POST /webhook`, con
l'header `X-Telegram-Bot-Api-Secret-Token` uguale a `TELEGRAM_WEBHOOK_SECRET`
di `.dev.vars`. **L'uscita è reale**: il bot risponde davvero, in chat, sul
bot di TEST configurato in `.dev.vars` — apri quella chat su Telegram per
vedere gli esiti.

Sostituisci `<CHAT_ID>` con l'id numerico del tuo utente Telegram (scrivi
`/start` una volta al bot di test e leggi `message.from.id` da un log, oppure
usa `@userinfobot`) e `<SECRET>` con `TELEGRAM_WEBHOOK_SECRET`.

## /start

```bash
curl -s http://localhost:8787/webhook \
  -H "X-Telegram-Bot-Api-Secret-Token: <SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "update_id": 1,
    "message": {
      "message_id": 1, "date": 0,
      "from": { "id": <CHAT_ID>, "is_bot": false, "first_name": "Test" },
      "chat": { "id": <CHAT_ID>, "type": "private" },
      "text": "/start"
    }
  }'
```

## Header secret errato (deve rispondere 403, nessuna elaborazione)

```bash
curl -si http://localhost:8787/webhook \
  -H "X-Telegram-Bot-Api-Secret-Token: sbagliato" \
  -H "Content-Type: application/json" \
  -d '{"update_id":2}'
```

## Impronta incollata (check archivio — usa un'impronta vera già attestata)

```bash
curl -s http://localhost:8787/webhook \
  -H "X-Telegram-Bot-Api-Secret-Token: <SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "update_id": 3,
    "message": {
      "message_id": 3, "date": 0,
      "from": { "id": <CHAT_ID>, "is_bot": false, "first_name": "Test" },
      "chat": { "id": <CHAT_ID>, "type": "private" },
      "text": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }'
```
(l'hash sopra è un placeholder di 65 caratteri: accorcialo a 64 con un'impronta reale.)

## /certificato con hash inesistente (404 pulito)

```bash
curl -s http://localhost:8787/webhook \
  -H "X-Telegram-Bot-Api-Secret-Token: <SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "update_id": 4,
    "message": {
      "message_id": 4, "date": 0,
      "from": { "id": <CHAT_ID>, "is_bot": false, "first_name": "Test" },
      "chat": { "id": <CHAT_ID>, "type": "private" },
      "text": "/certificato 0000000000000000000000000000000000000000000000000000000000000000"
    }
  }'
```

## Documento (attestazione) — richiede un file reale caricato sul bot di test

Il caso "invia un documento" NON è simulabile via curl puro: `document.file_id`
deve essere un id reale rilasciato da Telegram per un file davvero caricato sul
bot. Procedura più semplice per testare FASE 2/3 end-to-end:
1. Scrivi al bot di test da Telegram vero (non via curl) inviando un file.
2. Con `wrangler dev` in ascolto e un tunnel (es. `wrangler dev --remote` con
   route pubblica, o un tunnel `cloudflared`/`ngrok` verso `localhost:8787`)
   **oppure**, più semplice, punta temporaneamente `setWebhook` del bot di
   test alla URL `workers.dev` di un deploy di prova (`wrangler deploy --dry-run`
   non basta: serve un deploy reale, anche su un bot/ambiente usa-e-getta).

In alternativa, per isolare la sola logica di parsing/hash senza il webhook,
scrivere unit test Node (`node --test`) che chiamano direttamente le funzioni
esportate (da valutare in FASE 2/3 se il flusso curl risulta scomodo).

## Verifica webhook impostato correttamente (dopo `setWebhook` in produzione)

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"
```
