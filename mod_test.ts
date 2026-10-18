import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { Client, type Identifier } from "./mod.ts";
import { base64url } from "jose";
import * as x509 from "@peculiar/x509";
import { Buffer } from "node:buffer";

async function pebbleDo(path: string, body: unknown): Promise<void> {
  const resp = await fetch(`http://localhost:8055${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`unexpected response ${resp.status} ${await resp.text()}`);
  }
  await resp.body?.cancel();
}

const rsaPrivateKey =
  generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const ecPrivateKey =
  generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;

Deno.test("a failed directory fetch is retried by the next call", async () => {
  const failures = [
    () => Promise.reject(new TypeError("network down")),
    () => Promise.resolve(new Response("not json")),
  ];
  const realFetch = globalThis.fetch;
  for (const failure of failures) {
    let directoryFetches = 0;
    globalThis.fetch = ((input: string | URL | Request) => {
      if (String(input) !== "https://acme.test/dir") {
        return Promise.resolve(Response.json({
          suggestedWindow: {
            start: "2026-01-01T00:00:00Z",
            end: "2026-01-02T00:00:00Z",
          },
        }));
      }
      if (directoryFetches++ === 0) {
        return failure();
      }
      return Promise.resolve(Response.json({
        newNonce: "https://acme.test/nonce",
        newAccount: "https://acme.test/account",
        newOrder: "https://acme.test/order",
        revokeCert: "https://acme.test/revoke",
        keyChange: "https://acme.test/key",
        renewalInfo: "https://acme.test/renewal-info",
      }));
    }) as typeof fetch;
    try {
      const client = new Client({
        directoryUrl: "https://acme.test/dir",
        accountKey: rsaPrivateKey,
      });
      const first = await client.getRenewalInfo("id").then(
        () => null,
        (error) => error,
      );
      if (first === null) {
        throw new Error("the first call should fail");
      }
      const info = await client.getRenewalInfo("id");
      if (
        directoryFetches !== 2 ||
        info.suggestedWindow.start !== "2026-01-01T00:00:00Z"
      ) {
        throw new Error(`directory fetched ${directoryFetches} times`);
      }
    } finally {
      globalThis.fetch = realFetch;
    }
  }
});

async function issue(
  accountKey: KeyObject,
  identifiers: Identifier[],
  alg: RsaHashedKeyGenParams | EcKeyGenParams,
): Promise<string> {
  const client = new Client({
    directoryUrl: "https://localhost:14000/dir",
    accountKey,
  });

  await client.createAccount({
    contact: ["mailto:pebble@example.com"],
    termsOfServiceAgreed: true,
  });

  let order = await client.createOrder({ identifiers });
  if (order.status === "pending") {
    const authzUrls = order.authorizations;

    const identifiers = await Promise.all(
      authzUrls.map((authzUrl) => doAuthz(client, authzUrl)),
    );

    for (const identifier of identifiers) {
      if (!identifier) continue;
      await pebbleDo("/clear-txt", {
        host: `_acme-challenge.${identifier}.`,
      });
    }
  }

  order = await client.waitUntil(order, ["ready", "invalid"]);

  if (order.status === "invalid") {
    throw order;
  }

  // create a rsa private key
  const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    keys,
    signingAlgorithm: alg,
    name: `CN=${identifiers[0].value}`,
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        identifiers.map((id) => {
          return { type: "dns", value: id.value };
        }),
        true,
      ),
    ],
  });

  order = await client.finalizeOrder(order, new Uint8Array(csr.rawData));

  order = await client.waitUntil(order, ["valid", "invalid"]);

  if (order.status === "invalid") {
    throw order;
  }

  const cert = await client.getCertificate(order.certificate!);

  const certRaw = x509.PemConverter.decodeFirst(cert);
  const certObj = new x509.X509Certificate(certRaw);

  const certUID = getCertificateUniqueIdentifier(certObj);

  const renewalInfo = await client.getRenewalInfo(certUID);
  const end = new Date(renewalInfo.suggestedWindow.end);
  if (end.getTime() >= certObj.notAfter.getTime()) {
    throw new Error("end is not before notAfter");
  }
  return certUID;
}

async function test(
  ...args: Parameters<typeof issue>
): Promise<void> {
  await issue(...args);
}

function getCertificateUniqueIdentifier(cert: x509.X509Certificate): string {
  // The unique identifier is constructed by concatenating the
  //  base64url-encoding [RFC4648] of the keyIdentifier field of the
  //  certificate's Authority Key Identifier (AKI) [RFC5280] extension, a
  //  literal period, and the base64url-encoding of the DER-encoded Serial
  //  Number field (without the tag and length bytes).  All trailing "="
  //  characters MUST be stripped from both parts of the unique identifier.

  const akiExt = cert.getExtension(x509.AuthorityKeyIdentifierExtension);
  if (!akiExt || !akiExt.keyId) {
    throw new Error("No AKI extension found or no keyId in AKI extension");
  }
  const keyId = Buffer.from(akiExt.keyId, "hex");
  const serialNumber = Buffer.from(cert.serialNumber, "hex");
  return base64url.encode(keyId).replaceAll("=", "") + "." +
    base64url.encode(serialNumber).replaceAll("=", "");
}

async function doAuthz(
  client: Client,
  authzUrl: string,
): Promise<string | null> {
  const authz = await client.getAuthorization(authzUrl);
  if (authz.status !== "pending") return null;

  const challenge = authz.challenges.find((c) => c.type === "dns-01")!;

  const keyAuthorization = await client
    .getChallengeKeyAuthorization(challenge.token!);

  const digest = base64url.encode(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(keyAuthorization),
      ),
    ),
  );

  await pebbleDo("/set-txt", {
    host: `_acme-challenge.${authz.identifier.value}.`,
    value: digest,
  });

  await client.completeChallenge(challenge.url);

  await client.waitUntil(challenge, ["valid", "invalid"]);

  return authz.identifier.value;
}

Deno.test("supportsRenewalInfo follows the directory", async () => {
  const realFetch = globalThis.fetch;
  for (const renewalInfo of [undefined, "https://acme.test/renewal-info"]) {
    globalThis.fetch = (() =>
      Promise.resolve(Response.json({
        newNonce: "https://acme.test/nonce",
        newAccount: "https://acme.test/account",
        newOrder: "https://acme.test/order",
        revokeCert: "https://acme.test/revoke",
        keyChange: "https://acme.test/key",
        renewalInfo,
      }))) as typeof fetch;
    try {
      const client = new Client({
        directoryUrl: "https://acme.test/dir",
        accountKey: rsaPrivateKey,
      });
      if (await client.supportsRenewalInfo() !== (renewalInfo !== undefined)) {
        throw new Error(`wrong answer for renewalInfo ${renewalInfo}`);
      }
    } finally {
      globalThis.fetch = realFetch;
    }
  }
});

Deno.test("rsa + single + rsa", () =>
  test(rsaPrivateKey, [{ type: "dns", value: "example.com" }], {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  }));

Deno.test("rsa + single + ec", () =>
  test(rsaPrivateKey, [{ type: "dns", value: "example2.com" }], {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
  }));

Deno.test("rsa + multiple + rsa", () =>
  test(rsaPrivateKey, [{ type: "dns", value: "example3.com" }, {
    type: "dns",
    value: "example4.com",
  }], {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  }));

Deno.test("ec + single + rsa", () =>
  test(ecPrivateKey, [{ type: "dns", value: "example5.com" }], {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  }));

Deno.test("ec + wildcard + ec", () =>
  test(ecPrivateKey, [{ type: "dns", value: "example6.com" }, {
    type: "dns",
    value: "*.example6.com",
  }], {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
  }));

Deno.test("replaces a previous certificate", async () => {
  const replaced = await issue(
    rsaPrivateKey,
    [{ type: "dns", value: "example7.com" }],
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
  );
  const client = new Client({
    directoryUrl: "https://localhost:14000/dir",
    accountKey: rsaPrivateKey,
  });
  await client.createAccount({
    contact: ["mailto:pebble@example.com"],
    termsOfServiceAgreed: true,
  });

  const order = await client.createOrder({
    identifiers: [{ type: "dns", value: "example7.com" }],
    replaces: replaced,
  });

  if (order.replaces !== replaced) {
    throw new Error(`order does not replace ${replaced}: ${order.replaces}`);
  }
});

Deno.test("replaces is not sent without renewalInfo", async () => {
  const payloads: Record<string, unknown>[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === "https://acme.test/dir") {
      return Promise.resolve(Response.json({
        newNonce: "https://acme.test/nonce",
        newAccount: "https://acme.test/account",
        newOrder: "https://acme.test/order",
        revokeCert: "https://acme.test/revoke",
        keyChange: "https://acme.test/key",
      }));
    }
    if (url === "https://acme.test/nonce") {
      return Promise.resolve(
        new Response(null, { headers: { "Replay-Nonce": "nonce" } }),
      );
    }
    const jws = JSON.parse(String(init?.body));
    payloads.push(
      JSON.parse(new TextDecoder().decode(base64url.decode(jws.payload))),
    );
    return Promise.resolve(Response.json({
      status: "pending",
      identifiers: [],
      authorizations: [],
      finalize: "https://acme.test/finalize",
    }, { status: 201, headers: { Location: "https://acme.test/order/1" } }));
  }) as typeof fetch;
  try {
    const client = new Client({
      directoryUrl: "https://acme.test/dir",
      accountKey: rsaPrivateKey,
      accountUrl: "https://acme.test/account/1",
    });
    await client.createOrder({
      identifiers: [{ type: "dns", value: "example.com" }],
      replaces: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE",
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  if (payloads.length !== 1 || "replaces" in payloads[0]) {
    throw new Error(
      `unexpected newOrder payloads: ${JSON.stringify(payloads)}`,
    );
  }
});

Deno.test("waitUntil rejects with the signal's reason", async () => {
  const client = new Client({
    directoryUrl: "https://acme.test/dir",
    accountKey: rsaPrivateKey,
    accountUrl: "https://acme.test/account/1",
  });
  const controller = new AbortController();
  const reason = new Error("stop");
  const timer = setTimeout(() => controller.abort(reason), 10);
  const started = Date.now();
  let caught: unknown;
  try {
    await client.waitUntil(
      { url: "https://acme.test/order/1", status: "pending" },
      ["valid"],
      { signal: controller.signal },
    );
  } catch (e) {
    caught = e;
  } finally {
    clearTimeout(timer);
  }

  if (caught !== reason) throw new Error(`unexpected rejection: ${caught}`);
  if (Date.now() - started > 1000) throw new Error("did not stop promptly");
});

Deno.test("waitUntil with an aborted signal does not poll", async () => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => {
    calls++;
    return Promise.reject(new Error("no network in this test"));
  }) as typeof fetch;
  let caught: unknown;
  try {
    const client = new Client({
      directoryUrl: "https://acme.test/dir",
      accountKey: rsaPrivateKey,
      accountUrl: "https://acme.test/account/1",
    });
    await client.waitUntil(
      { url: "https://acme.test/order/1", status: "pending" },
      ["valid"],
      { signal: AbortSignal.abort("stopped") },
    );
  } catch (e) {
    caught = e;
  } finally {
    globalThis.fetch = realFetch;
  }

  if (caught !== "stopped" || calls !== 0) {
    throw new Error(`unexpected result: ${caught}, ${calls} requests`);
  }
});

const DIRECTORY_URL = "https://acme.test/dir";
const DIRECTORY = {
  newNonce: "https://acme.test/nonce",
  newAccount: "https://acme.test/account",
  newOrder: "https://acme.test/order",
  revokeCert: "https://acme.test/revoke",
  keyChange: "https://acme.test/key",
  renewalInfo: "https://acme.test/renewal-info",
};

interface HeldRequest {
  request: string;
  signal: AbortSignal | undefined;
  release(): void;
}

// Answers every request; a held one waits for release() or, like fetch, rejects with the signal's reason.
// Like fetch, it sends nothing for an aborted signal.
function fakeServer(hold: (request: string, index: number) => boolean) {
  const requests: string[] = [];
  const held: HeldRequest[] = [];
  const respond = (url: string, method: string) => {
    if (url === DIRECTORY_URL) return Response.json(DIRECTORY);
    const headers = { "Replay-Nonce": "nonce", "Location": url };
    if (method === "HEAD") return new Response(null, { headers });
    if (url.startsWith(DIRECTORY.renewalInfo)) {
      return Response.json({
        suggestedWindow: {
          start: "2026-01-01T00:00:00Z",
          end: "2026-01-02T00:00:00Z",
        },
      });
    }
    return Response.json({ status: "valid" }, { headers });
  };
  const fetch = (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const request = `${method} ${url}`;
    const signal = init?.signal ?? undefined;
    if (signal?.aborted) return Promise.reject(signal.reason);
    const index = requests.push(request) - 1;
    if (!hold(request, index)) return Promise.resolve(respond(url, method));
    return new Promise<Response>((resolve, reject) => {
      signal?.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      });
      held.push({
        request,
        signal,
        release: () => resolve(respond(url, method)),
      });
    });
  };
  return { fetch: fetch as typeof globalThis.fetch, requests, held };
}

async function withFetch<T>(
  fetch: typeof globalThis.fetch,
  run: () => Promise<T>,
): Promise<T> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = realFetch;
  }
}

async function until(condition: () => boolean): Promise<void> {
  const started = Date.now();
  while (!condition()) {
    if (Date.now() - started > 5000) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => new Error("resolved instead of rejecting"),
    (error) => error,
  );
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

const ORDER_URL = "https://acme.test/order/1";
const ABORTABLE_CALLS: [
  string,
  (client: Client, signal: AbortSignal) => Promise<unknown>,
][] = [
  [
    "createAccount",
    (client, signal) =>
      client.createAccount({ termsOfServiceAgreed: true }, { signal }),
  ],
  [
    "updateAccount",
    (client, signal) => client.updateAccount({ contact: [] }, { signal }),
  ],
  ["createOrder", (client, signal) =>
    client.createOrder(
      { identifiers: [{ type: "dns", value: "example.com" }] },
      { signal },
    )],
  ["getOrder", (client, signal) => client.getOrder(ORDER_URL, { signal })],
  ["finalizeOrder", (client, signal) =>
    client.finalizeOrder(
      { url: ORDER_URL, finalize: `${ORDER_URL}/finalize` },
      new Uint8Array(),
      { signal },
    )],
  [
    "getAuthorization",
    (client, signal) =>
      client.getAuthorization("https://acme.test/authz/1", { signal }),
  ],
  [
    "completeChallenge",
    (client, signal) =>
      client.completeChallenge("https://acme.test/chall/1", { signal }),
  ],
  [
    "getCertificate",
    (client, signal) =>
      client.getCertificate("https://acme.test/cert/1", { signal }),
  ],
  [
    "getRenewalInfo",
    (client, signal) => client.getRenewalInfo("id", { signal }),
  ],
  [
    "supportsRenewalInfo",
    (client, signal) => client.supportsRenewalInfo({ signal }),
  ],
  [
    "waitUntil",
    (client, signal) =>
      client.waitUntil({ url: ORDER_URL, status: "pending" }, ["valid"], {
        signal,
      }),
  ],
];

function newClient(): Client {
  return new Client({ directoryUrl: DIRECTORY_URL, accountKey: rsaPrivateKey });
}

Deno.test("an aborted signal stops every call before its first request", async () => {
  for (const [name, call] of ABORTABLE_CALLS) {
    const server = fakeServer(() => false);
    const caught = await withFetch(
      server.fetch,
      () => rejection(call(newClient(), AbortSignal.abort())),
    );
    if (!isAbortError(caught) || server.requests.length !== 0) {
      throw new Error(
        `${name}: ${caught}, requests ${server.requests.join(", ")}`,
      );
    }
  }
});

Deno.test("a signal aborts every request of every call", async () => {
  for (const [name, call] of ABORTABLE_CALLS) {
    const complete = fakeServer(() => false);
    await withFetch(
      complete.fetch,
      () => call(newClient(), new AbortController().signal),
    );
    for (const [index, request] of complete.requests.entries()) {
      const server = fakeServer((_, i) => i === index);
      const controller = new AbortController();
      const caught = await withFetch(server.fetch, async () => {
        const result = rejection(call(newClient(), controller.signal));
        await until(() => server.held.length === 1);
        controller.abort();
        return await result;
      });
      if (!isAbortError(caught) || server.held[0].signal?.aborted !== true) {
        throw new Error(`${name}, ${request}: ${caught}`);
      }
    }
  }
});

Deno.test("a shared directory fetch stops only when every caller aborts", async () => {
  const server = fakeServer((request) => request === `GET ${DIRECTORY_URL}`);
  await withFetch(server.fetch, async () => {
    const client = newClient();
    const first = new AbortController();
    const second = new AbortController();
    const calls = [first, second].map((controller) =>
      rejection(client.getRenewalInfo("id", { signal: controller.signal }))
    );
    await until(() => server.held.length === 1);
    first.abort("first");
    if (server.held[0].signal?.aborted) {
      throw new Error("the first abort must not stop the shared fetch");
    }
    second.abort("second");
    // Called before the aborted fetch settles, it must start a new one.
    const third = client.getRenewalInfo("id");
    if (!server.held[0].signal?.aborted) {
      throw new Error("the last abort must stop the shared fetch");
    }
    for (const caught of await Promise.all(calls)) {
      if (!isAbortError(caught)) throw new Error(`rejected with ${caught}`);
    }
    await until(() => server.held.length === 2);
    server.held[1].release();
    await third;
  });
});

Deno.test("a call without a signal keeps a shared directory fetch going", async () => {
  const server = fakeServer((request) => request === `GET ${DIRECTORY_URL}`);
  await withFetch(server.fetch, async () => {
    const client = newClient();
    const controller = new AbortController();
    const aborted = rejection(
      client.getRenewalInfo("id", { signal: controller.signal }),
    );
    const kept = client.getRenewalInfo("id");
    await until(() => server.held.length === 1);
    let settled = false;
    aborted.then(() => settled = true);
    controller.abort("stopped");
    await new Promise((resolve) => setTimeout(resolve, 10));
    if (settled || server.held[0].signal?.aborted) {
      throw new Error("the shared fetch and the aborted call must go on");
    }
    server.held[0].release();
    await kept;
    // The aborted call gets the directory too; its own fetch then stops it.
    const caught = await aborted;
    const renewalInfo = server.requests.filter((request) =>
      request.startsWith(`GET ${DIRECTORY.renewalInfo}`)
    );
    if (caught !== "stopped" || renewalInfo.length !== 1) {
      throw new Error(`${caught}, requests ${server.requests.join(", ")}`);
    }
  });
});
