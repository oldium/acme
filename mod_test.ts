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
