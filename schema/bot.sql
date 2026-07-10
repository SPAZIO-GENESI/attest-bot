-- attest-bot: stato minimo del canale Telegram (P23-DESIGN §4.6).
-- Nessun byte di file viene mai salvato: hash calcolato in streaming e
-- scartato subito dopo la chiamata a imgauth. Qui restano solo id utente
-- Telegram, accettazione dell'avvertenza, modo corrente e contatori d'uso
-- (retention 90 giorni, ripulita dal cron).

CREATE TABLE IF NOT EXISTS bot_users (
  tg_user_id    INTEGER PRIMARY KEY,
  accepted_at   INTEGER,           -- epoch ms accettazione avvertenza; NULL = mai
  mode          TEXT,              -- 'attest' | 'verify' | NULL (= attest, default)
  mode_expires  INTEGER,           -- epoch ms; scaduto = torna a attest
  verify_expect TEXT,              -- ultimo hash atteso in modo verify (64 hex)
  pending_cert  TEXT,              -- JSON di /api/hash per il callback cert-pdf
  last_seen     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bot_usage (
  tg_user_id INTEGER NOT NULL,
  day        TEXT    NOT NULL,     -- YYYY-MM-DD Europe/Rome
  attests    INTEGER NOT NULL DEFAULT 0,
  verifies   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tg_user_id, day)
);
