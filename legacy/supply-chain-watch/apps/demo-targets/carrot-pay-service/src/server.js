// 모사 결제 서비스 — 런타임 축(docs/13 §8) 공격 시연용 백엔드.
// 중고거래 앱의 "안전결제" 요청을 받아 주문을 저장한다. 실제 결제·외부 전송은 없다.
import express from "express";
import pg from "pg";
import Redis from "ioredis";
import payAnalytics from "pay-analytics-demo"; // 오염된 데모 의존성 (docs/13 §8)

const PORT = Number(process.env.PORT ?? 3000);
const db = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
const redis = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1 });

const log = (level, msg, extra = {}) =>
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, svc: "carrot-pay", msg, ...extra }));

async function initSchema() {
  for (let attempt = 1; ; attempt++) {
    try {
      await db.query(`CREATE TABLE IF NOT EXISTS orders (
        id         BIGSERIAL PRIMARY KEY,
        item_id    TEXT        NOT NULL,
        amount     INTEGER     NOT NULL CHECK (amount > 0),
        status     TEXT        NOT NULL DEFAULT 'PAID',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      return;
    } catch (err) {
      if (attempt >= 10) throw err;
      log("warn", "db not ready, retrying", { attempt });
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));

app.get("/health", async (_req, res) => {
  const checks = { db: false, redis: false };
  try { await db.query("SELECT 1"); checks.db = true; } catch { /* reported below */ }
  try { checks.redis = (await redis.ping()) === "PONG"; } catch { /* reported below */ }
  const ok = checks.db && checks.redis;
  res.status(ok ? 200 : 503).json({ ok, svc: "carrot-pay", ...checks });
});

app.post("/pay", async (req, res) => {
  const { itemId, amount } = req.body ?? {};
  if (typeof itemId !== "string" || !/^[\w-]{1,64}$/.test(itemId)) {
    return res.status(400).json({ error: "itemId must be 1-64 chars of [A-Za-z0-9_-]" });
  }
  if (!Number.isInteger(amount) || amount < 1 || amount > 10_000_000) {
    return res.status(400).json({ error: "amount must be an integer between 1 and 10,000,000" });
  }
  try {
    const { rows } = await db.query(
      "INSERT INTO orders (item_id, amount) VALUES ($1, $2) RETURNING id, status, created_at",
      [itemId, amount],
    );
    await redis.incr("pay:orders:count");
    payAnalytics.track("pay"); // 결제 분석 — 오염 버전은 여기서 fake-c2로 비콘을 보낸다
    const order = rows[0];
    log("info", "order paid", { orderId: order.id, itemId, amount });
    res.status(201).json({ orderId: Number(order.id), status: order.status, createdAt: order.created_at });
  } catch (err) {
    log("error", "pay failed", { err: String(err) });
    res.status(500).json({ error: "payment failed" });
  }
});

app.get("/orders/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "invalid order id" });
  const { rows } = await db.query("SELECT id, item_id, amount, status, created_at FROM orders WHERE id = $1", [id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });
  const o = rows[0];
  res.json({ orderId: Number(o.id), itemId: o.item_id, amount: o.amount, status: o.status, createdAt: o.created_at });
});

await initSchema();
const server = app.listen(PORT, () => log("info", "listening", { port: PORT }));

function shutdown() {
  log("info", "shutting down");
  server.close(async () => {
    await Promise.allSettled([db.end(), redis.quit()]);
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
