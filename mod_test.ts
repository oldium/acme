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

async function test(
  accountKey: KeyObject,
  identifiers: Identifier[],
  alg: RsaHashedKeyGenParams | EcKeyGenParams,
) {
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
