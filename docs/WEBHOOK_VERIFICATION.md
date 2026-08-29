# Webhook Signature Verification

OphirPay signs every webhook delivery with HMAC-SHA256. Receiving endpoints must verify the signature before trusting the payload.

## Signature algorithm

The HMAC is computed over the JSON body **with the `signature` field set to an empty string**:

```json
{
  "event": "payment.created",
  "timestamp": "2026-08-06T12:00:00Z",
  "data": { "paymentId": "p_123" },
  "signature": ""
}
```

```
signature = HMAC-SHA256(webhook_secret, canonical_body).hex()
```

The same value is sent in both:

- The `X-OphirPay-Signature` HTTP header
- The `signature` field inside the JSON body

Always compare signatures with a constant-time comparison function to prevent timing attacks.

---

## Node.js / TypeScript example

```typescript
import { createHmac, timingSafeEqual } from "crypto";
import type { IncomingMessage } from "http";

interface WebhookPayload {
  event: string;
  timestamp: string;
  data: Record<string, unknown>;
  signature: string;
}

/**
 * Verify an OphirPay webhook signature.
 *
 * @param secret   The webhook signing secret shown when the webhook was created.
 * @param payload  The parsed JSON body received from OphirPay.
 * @returns        true if the signature is valid.
 */
export function verifyWebhookSignature(
  secret: string,
  payload: WebhookPayload
): boolean {
  const { signature: received, ...rest } = payload;
  const canonical = JSON.stringify({ ...rest, signature: "" });

  const expected = createHmac("sha256", secret).update(canonical).digest("hex");

  if (received.length !== expected.length) return false;

  return timingSafeEqual(
    Buffer.from(received, "hex"),
    Buffer.from(expected, "hex")
  );
}

// Express-style middleware example
export async function ophirpayWebhookMiddleware(
  req: IncomingMessage,
  secret: string
): Promise<WebhookPayload> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString("utf-8");
  const payload: WebhookPayload = JSON.parse(body);

  if (!verifyWebhookSignature(secret, payload)) {
    throw new Error("Invalid webhook signature");
  }

  return payload;
}
```

---

## Python example

```python
import hmac
import hashlib
import json
from typing import Any


def verify_ophirpay_signature(secret: str, payload: dict[str, Any]) -> bool:
    """
    Verify the HMAC-SHA256 signature of an OphirPay webhook payload.

    :param secret:  The webhook signing secret.
    :param payload: The parsed JSON body received from OphirPay.
    :return:        True if the signature is valid.
    """
    received = payload.get("signature", "")
    canonical_payload = {**payload, "signature": ""}
    canonical_body = json.dumps(canonical_payload, separators=(",", ":"))

    expected = hmac.new(
        secret.encode("utf-8"),
        canonical_body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(received, expected)


# Flask example
from flask import request, abort


@app.route("/webhooks/ophirpay", methods=["POST"])
def ophirpay_webhook():
    payload = request.get_json(force=True)
    secret = "your-webhook-secret"  # load from env

    if not verify_ophirpay_signature(secret, payload):
        abort(401, "Invalid signature")

    # Process the verified payload
    print(f"Received event: {payload['event']}")
    return "", 200
```

---

## Important security notes

1. **Use constant-time comparison.** Never use `===`, `==`, or string comparison to check signatures.
2. **Reject replayed timestamps.** Consider rejecting payloads with timestamps older than a few minutes.
3. **Only parse after verification.** Parse the JSON body only after the signature is verified, or parse without accessing nested fields first.
4. **Keep the secret secure.** Store webhook secrets in a secrets manager or environment variables, never in source control.
5. **Use the header when available.** If your framework provides raw body access, you can also verify against the `X-OphirPay-Signature` header using the same algorithm.

---

## Payload shape

```json
{
  "event": "payment.created",
  "timestamp": "2026-08-06T12:00:00Z",
  "data": {
    "paymentId": "p_123",
    "payer": "G...",
    "payee": "G...",
    "amount": "10000000",
    "asset": "XLM"
  },
  "signature": "a1b2c3..."
}
```

See [`SSE_EVENT_SCHEMA.md`](./SSE_EVENT_SCHEMA.md) for the list of event types and [`integration-guide.md`](./integration-guide.md) for the full integration flow.
