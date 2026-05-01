---
title: "OAuth 2.0 Client Instance Actor Assertion Profile"
abbrev: "oauth-client-instance-actor"
category: std

docname: draft-mcguinness-oauth-client-instance-actor-assertion-latest
submissiontype: IETF
number:
date: 2026-05-01
v: 3
ipr: trust200902
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - OAuth
 - CIMD
 - Actor
 - Workload Identity
 - Client Instance
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "mcguinness/draft-mcguinness-oauth-client-instance-actor-assertion"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-client-instance-actor-assertion/draft-mcguinness-oauth-client-instance-actor-assertion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC6755:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7523:
  RFC7591:
  RFC7800:
  RFC8414:
  RFC8693:
  RFC8725:

informative:
  RFC8705:
  RFC9449:
  CIMD: I-D.ietf-oauth-client-id-metadata-document
  ACTOR-PROFILE: I-D.mcguinness-oauth-actor-profile
  ENTITY-PROFILES: I-D.mora-oauth-entity-profiles
  SPIFFE-CLIENT-AUTH: I-D.ietf-oauth-spiffe-client-auth
  SPIFFE:
    title: "SPIFFE: Secure Production Identity Framework For Everyone"
    target: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
    author:
      org: SPIFFE
    date: 2024

--- abstract

This specification defines a profile for representing client instance
identity in OAuth 2.0. It does not introduce a new client_instance
identifier in protocol messages. Instead, it extends the Client ID
Metadata Document (CIMD) so that a client_id identifies a logical
client class whose concrete runtime instances are authenticated by one
or more trusted instance issuers (for example, workload identity
systems).

This document profiles the actor_token and actor_token_type parameters
defined by OAuth 2.0 Token Exchange (RFC 8693) and permits their use
with grant types other than token exchange. It registers a new
actor_token_type, urn:ietf:params:oauth:token-type:client-instance-jwt,
that carries the instance identity as a signed JWT. The Authorization
Server validates the actor token and represents the instance using the
act claim defined by the OAuth Actor Profile.


--- middle

# Introduction

OAuth 2.0 {{RFC6749}} defines client_id as the identifier of a client.
In modern deployments such as agentic workloads, autoscaled services,
and ephemeral function executions, a single logical client routinely
corresponds to many concrete runtime instances that come and go on a
short timescale. Resource servers and authorization servers
increasingly need to know not only *which* client made a request but
*which instance* of that client made it. Instances may be acting on a
user's behalf or as the principal themselves; this profile covers
both.

OAuth 2.0 Token Exchange {{RFC8693}} defines the actor_token and
actor_token_type token request parameters and the act claim for
representing an actor in an issued token. The OAuth Actor Profile
{{ACTOR-PROFILE}} further constrains the act claim and registers
actor-related claims, but explicitly leaves out a token request
parameter for proving an actor in flows other than token exchange.

This document fills that gap with a tightly scoped profile:

* It treats the CIMD client_id as identifying a client *class*, and
  defines metadata describing the *instance issuers* trusted to assert
  that a particular runtime is an instance of that class.
* It permits the actor_token and actor_token_type parameters from
  {{RFC8693}} to appear on token requests using grant types other than
  urn:ietf:params:oauth:grant-type:token-exchange (including the
  authorization code, client credentials, and JWT bearer
  ({{RFC7523}}) grants).
* It registers a new actor_token_type,
  urn:ietf:params:oauth:token-type:client-instance-jwt, that carries
  the instance identity as a JWT {{RFC7519}} signed by an instance
  issuer published in the client's CIMD metadata.
* It defines authorization server metadata so that clients can
  discover support.

What this document does *not* do:

* It does not introduce a client_instance request parameter.
* It does not change the syntax or processing of the act claim
  beyond what {{ACTOR-PROFILE}} already defines.
* It does not define authorization endpoint interactions for
  conveying actor identity; like {{ACTOR-PROFILE}}, this is left for
  future work.

## Relationship to RFC 8693

{{RFC8693}} defines actor_token and actor_token_type only in the
context of the token exchange grant type. This document permits these
parameters on additional grant types listed in
{{grant-type-applicability}}, while preserving their semantics: the
actor_token identifies the party acting on behalf of the subject and
is reflected in an act claim in the issued token. Use of these
parameters on a token exchange request remains fully governed by
{{RFC8693}}, with the additional client-instance-jwt token type
defined here.

## Relationship to OAuth Actor Profile

{{ACTOR-PROFILE}} defines the structure of the act claim, the
sub_profile claim, and nested actor representation. This document does
not redefine those constructs. It defines (a) how a client instance
proves itself at the token endpoint and (b) how the AS populates
act using the validated assertion. Implementations of this document
MUST also implement {{ACTOR-PROFILE}}.

## Relationship to SPIFFE Client Authentication {#relationship-spiffe-client-auth}

{{SPIFFE-CLIENT-AUTH}} (an OAuth Working Group document) defines how
a SPIFFE workload authenticates *as the OAuth client itself*, using a
JWT-SVID or X.509-SVID in place of a client secret. It registers the
client_assertion_type
urn:ietf:params:oauth:client-assertion-type:jwt-spiffe and adds CIMD
metadata (spiffe_id, spiffe_bundle_endpoint) for resolving the
client's SPIFFE trust bundle. Notably, its spiffe_id field permits a
trailing /* wildcard, enabling one OAuth client to be authenticated
by any SPIFFE workload whose ID matches the prefix.

This document operates at a different layer. Its scope is *actor /
instance identity*, not client authentication. The two specifications
operate on different OAuth parameters and trust sources:

| Layer | SPIFFE Client Auth | This document |
| --- | --- | --- |
| What is authenticated | The OAuth client | An actor (instance) acting under an OAuth client |
| Token request parameter | client_assertion / client_assertion_type | actor_token / actor_token_type |
| Trust source | SPIFFE bundle endpoint and spiffe_id (CIMD) | instance_issuers (CIMD) |
| Where the SPIFFE ID surfaces | Validated against spiffe_id; not propagated | Surfaced in act.sub of issued access tokens |

The two specifications are orthogonal and MAY be combined. A common
deployment pattern uses {{SPIFFE-CLIENT-AUTH}} with a wildcard
spiffe_id to authenticate a class of SPIFFE workloads as a single
OAuth client, and uses this profile to additionally surface the
specific instance's identity as an act claim and to bind the issued
access token to that instance ({{sender-constrained}}). In that
combined pattern:

* {{SPIFFE-CLIENT-AUTH}} answers "may this workload act as this
  client?": a yes/no based on prefix match.
* This document answers "which specific instance is acting?": a
  named, bindable, propagatable identity.

Where {{SPIFFE-CLIENT-AUTH}} alone is sufficient (no need to name
specific instances downstream, and the user-facing flows do not
require post-consent instance binding), this document is not
needed.

This document does not require SPIFFE. Instance issuers may issue
non-SPIFFE JWT actor tokens (subject_syntax other than "spiffe");
{{SPIFFE-CLIENT-AUTH}} is one example mechanism by which the client
*class itself* might authenticate, alongside others such as
private_key_jwt with keys published in CIMD jwks_uri. Integration
with {{SPIFFE-CLIENT-AUTH}}'s spiffe_bundle_endpoint as an
alternative trust source for the instance_issuers descriptor is
left to a future profile.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the following terms:

Client Class:
: The logical OAuth client identified by a CIMD client_id. The client
  class is the issuer (in the OAuth metadata sense) that publishes the
  set of instance issuers permitted to authenticate its runtime
  instances.

Client Instance:
: A concrete runtime of a client class, for example a particular
  process, container, function invocation, or session.

Instance Issuer:
: An authority trusted by the client class to authenticate client
  instances and issue actor tokens on their behalf. Examples include
  workload identity providers (e.g., a SPIFFE control plane
  {{SPIFFE}}) and platform-managed identity services.

Client Instance Actor Token:
: A JWT issued by an instance issuer asserting the identity of a
  client instance, presented as the actor_token in a token request.

# Architecture {#architecture}

Three roles cooperate to authenticate a client instance:

| Role | Responsibility |
| --- | --- |
| Client Class | Logical OAuth client identified by a CIMD client_id. Publishes the list of trusted instance issuers in its CIMD metadata document. |
| Instance Issuer | Authenticates concrete runtime instances and issues short-lived JWT actor tokens describing them. |
| Authorization Server (AS) | Authenticates the client per its registered client authentication method; resolves the CIMD metadata; verifies the actor token against a trusted instance issuer; mints an access token whose act claim represents the instance. |

A high-level flow:

~~~ ascii-art
+-----------+   actor token   +------------+
|  Client   |<----------------|  Instance  |
|  Instance |                 |   Issuer   |
+-----------+                 +------------+
      |
      | token request:
      |  - client authentication (e.g., private_key_jwt)
      |  - actor_token (instance JWT)
      |  - actor_token_type =
      |      urn:...:client-instance-jwt
      v
+--------------------+
| Authorization      |  -> resolves CIMD for client_id
| Server             |  -> validates actor token
|                    |  -> issues access token with act claim
+--------------------+
~~~

The client class identifier (the CIMD URL) is the OAuth client
identifier; the instance issuer identifier is the JWT iss of the
actor token. They are distinct trust anchors: the AS authenticates
the client class using its registered client authentication method
(typically private_key_jwt with keys from the CIMD jwks_uri) and
authenticates the instance through the actor token.

# Trust Delegation Model {#trust-model}

This profile defines a three-party trust delegation between the
client class, the instance issuer, and the AS. The client class
*delegates* attestation of its runtime instances to one or more
instance issuers; the AS *relies on* that delegation as expressed in
the CIMD document.

## Delegation by the Client Class {#trust-model-delegation}

By listing an instance issuer in its CIMD instance_issuers
({{instance-issuers}}), a client class delegates to that issuer the
authority to attest that a concrete runtime is an instance of the
client class. This delegation is bounded by the descriptor; the AS
MUST enforce, and the instance issuer MUST honor, the following
limits:

* The asserted sub MUST fall within trust_domain when present and
  MUST conform to subject_syntax when present.
* The asserted sub_profile values MUST be a subset of
  actor_profiles_supported when present.
* The signing alg MUST be among signing_alg_values_supported when
  present.

A client class MUST NOT list instance issuers it does not control or
trust to enforce these bounds. An instance issuer accepting delegation
MUST NOT mint actor tokens naming this client_id outside the
delegated scope.

This delegation has a corollary for client authentication. Because
the CIMD listing publicly endorses the issuer to mint tokens naming
this client_id, an actor token signed by such an issuer is itself
attributable to the client class. The AS MAY, when so configured by
the class, treat the presented actor token as both the actor
assertion and the client authentication credential
({{auth-via-actor-token}}). In this mode the class need not control
an online private key, which is necessary in deployments where
instances cannot reach class-controlled credentials.

## Authority of the Authorization Server {#trust-model-as}

The AS treats the CIMD instance_issuers list as authoritative: it
derives its trust in an actor token solely from the descriptor whose
issuer member matches the actor token's iss claim. This document
does not define out-of-band or AS-side configuration of additional
instance issuers for a client_id; deployments requiring such
configuration MUST do so via a separate specification.

## Trust Update Handling {#trust-lifecycle}

The trust relationship between client class and instance issuer is
mutable. When the CIMD document changes (for example, when an
instance issuer is removed, its jwks_uri changes, or its descriptor's
scope is narrowed via trust_domain, actor_profiles_supported, or
signing_alg_values_supported), the AS SHOULD apply the
diligence required by {{CIMD}} for changes to client jwks. In
particular, the AS SHOULD revoke previously issued access tokens
whose act claim either:

* names a removed instance issuer; or
* falls outside the descriptor's narrowed scope.

# CIMD Extensions {#cimd-extensions}

This document extends the Client ID Metadata Document {{CIMD}} with
parameters describing the trust relationship between a client class
and the instance issuers that authenticate its runtime instances.
These parameters are registered in the OAuth Dynamic Client
Registration Metadata registry (see {{iana-client-metadata}}).

## instance_issuers {#instance-issuers}

OPTIONAL. A non-empty JSON array of *instance issuer descriptor*
objects. Each descriptor declares an issuer that the client class
trusts to authenticate its instances. If this parameter is absent,
the AS MUST NOT accept actor tokens of type
urn:ietf:params:oauth:token-type:client-instance-jwt for this client.

An instance issuer descriptor has the following members:

issuer (REQUIRED):
: A StringOrURI {{RFC7519}} identifying the instance issuer. This
  value MUST exactly match the iss claim of accepted actor tokens.

jwks_uri (REQUIRED unless jwks is present):
: An HTTPS URL of a JWK Set {{RFC7517}} containing the public keys
  used to verify signatures of actor tokens issued by this issuer.

jwks (OPTIONAL):
: An inline JWK Set. If both jwks and jwks_uri are present, jwks_uri
  takes precedence and jwks SHOULD be ignored.

signing_alg_values_supported (OPTIONAL):
: A JSON array of JWS {{RFC7515}} alg values that this issuer uses to
  sign actor tokens. If present, the AS MUST reject actor tokens
  whose alg is not listed.

subject_syntax (OPTIONAL):
: A short identifier indicating the syntactic profile of the sub
  claim used by this issuer. Defined values are "uri" (default,
  arbitrary StringOrURI) and "spiffe" (a SPIFFE ID {{SPIFFE}}; see
  also {{SPIFFE-CLIENT-AUTH}} for the related SPIFFE-based client
  authentication profile). Other values MAY be used; unrecognized
  values MUST cause the AS to fall back to "uri" semantics.

trust_domain (OPTIONAL):
: When subject_syntax is "spiffe", a SPIFFE trust domain that the
  sub claim MUST belong to. The AS MUST reject any actor token
  whose sub does not lie within this trust domain. A descriptor's
  trust_domain is independent of any SPIFFE trust domain associated
  with the client class itself under {{SPIFFE-CLIENT-AUTH}}; the two
  MAY differ.

actor_profiles_supported (OPTIONAL):
: A JSON array of sub_profile values from the OAuth Entity Profiles
  registry {{ENTITY-PROFILES}} that this issuer is authorized to
  assert. If present, the AS MUST reject any actor token whose
  sub_profile contains values not listed.

Example client metadata document:

~~~ json
{
  "client_id": "https://openai.example.com/codex",
  "jwks_uri": "https://openai.example.com/codex/jwks.json",
  "token_endpoint_auth_method": "private_key_jwt",
  "instance_issuers": [
    {
      "issuer": "https://workload.openai.example.com",
      "jwks_uri": "https://workload.openai.example.com/jwks.json",
      "subject_syntax": "spiffe",
      "trust_domain": "openai.example.com",
      "signing_alg_values_supported": ["ES256"],
      "actor_profiles_supported": ["client_instance", "ai_agent"]
    }
  ],
  "max_actor_chain_depth": 4
}
~~~

## max_actor_chain_depth {#max-actor-chain-depth}

OPTIONAL. A positive integer specifying the maximum delegation depth
({{ACTOR-PROFILE}}) the client class permits in actor chains
originating from one of its instances. If absent, the AS applies its
own policy. The AS MUST reject requests whose resulting act chain
would exceed the lower of (a) this value, (b) the AS-imposed maximum,
and (c) 4 (the floor specified by {{ACTOR-PROFILE}}).

## actor_token_required {#actor-token-required}

OPTIONAL. A JSON boolean. When true, the AS MUST reject any token
request from this client_id that does not include an actor_token of
type urn:ietf:params:oauth:token-type:client-instance-jwt. The default
is false.

This parameter lets a client class enforce that every issued access
token is bound to an identifiable instance. It is redundant when
token_endpoint_auth_method is client_instance_actor_token
({{auth-via-actor-token}}); in that mode the actor token is
implicitly required by the auth method itself.

# Authorization Server Metadata {#as-metadata}

This document defines the following AS metadata parameter for
{{RFC8414}} (see {{iana-as-metadata}}):

actor_token_types_supported:
: OPTIONAL. A JSON array of actor_token_type values supported by the
  AS at the token endpoint. An AS implementing this profile SHOULD
  include urn:ietf:params:oauth:token-type:client-instance-jwt.

Clients use this metadata to determine whether the AS supports
client-instance actor tokens before assembling token requests.

# The Client Instance Actor Token {#client-instance-jwt}

A *Client Instance Actor Token* is a JWT {{RFC7519}} that asserts the
identity of a client instance. Its actor_token_type is
urn:ietf:params:oauth:token-type:client-instance-jwt (see
{{iana-token-type}}).

## Layering of Instance Identity and Actor Assertion {#layering}

A client instance actor token serves two conceptually distinct
purposes:

1. it authenticates the *runtime instance* (workload identity); and
2. it asserts that the instance is a member of the named *client
   class*.

This document defines a single combined artifact: a JWT signed by the
instance issuer that carries both. This matches the prevailing pattern
in workload identity systems, which already issue audience-scoped,
signed assertions of runtime identity (e.g., JWT-SVIDs in {{SPIFFE}}).

The instance issuer is the trust authority for the combined assertion
and MUST, before minting an actor token under this profile:

* Authenticate the runtime instance (e.g., via attestation,
  platform-level identity, or possession of an instance key); and
* Verify, under issuer-side policy, that the runtime is permitted to
  claim the client_id named in the token. This typically means that
  the runtime is operationally part of the client class's deployment.

Decoupled deployments, in which a workload identity provider issues
an *instance credential* and the runtime independently mints an
actor assertion bound to that credential, are out of scope for this
document. A future profile MAY define such a layered model and re-use
the actor_token_type registered here, or register an additional one.

## JWT Claims {#claims}

The following claims are defined for client instance actor tokens.

iss (REQUIRED):
: The instance issuer identifier. MUST exactly match an issuer
  member of an instance_issuers descriptor in the client class CIMD
  metadata.

sub (REQUIRED):
: The identifier of the client instance, in the syntax declared by
  the descriptor's subject_syntax (default: arbitrary StringOrURI).

aud (REQUIRED):
: The intended audience. MUST identify the AS. Per {{RFC7523}}
  Section 3, the AS MUST verify aud and SHOULD use its issuer
  identifier or token endpoint URL. If multiple values are present,
  the AS MUST find one that matches.

client_id (REQUIRED):
: The client_id of the client class to which this instance belongs.
  This claim binds the actor token to a specific client class; it is
  not part of the actor's identity (per {{ACTOR-PROFILE}}, client_id
  identifies an OAuth client, not an actor). The AS MUST reject the
  token if this value does not exactly equal the client_id of the
  authenticated client.

exp (REQUIRED):
: Expiration time. Issuers SHOULD set short lifetimes (e.g., five
  minutes or less); see {{security-replay}}.

iat (REQUIRED):
: Issued-at time.

jti (REQUIRED):
: A unique identifier used for replay prevention; see
  {{security-replay}}.

sub_profile (RECOMMENDED):
: A space-delimited list of OAuth Entity Profile names
  {{ENTITY-PROFILES}} classifying the actor. This document registers
  the value client_instance ({{iana-entity-profile}}). Issuers MAY
  include additional values such as service or ai_agent.

cnf (RECOMMENDED):
: A confirmation claim {{RFC7800}} carrying a key bound to this
  instance, enabling proof-of-possession at the AS and propagation to
  downstream resource servers. Issuers SHOULD include cnf so that
  access tokens whose act claim names the instance can be
  sender-constrained. See {{sender-constrained}} and
  {{security-binding}}.

nbf (OPTIONAL):
: Not-before time. If present, the AS MUST reject the token before
  this time.

Additional claims MAY be present and MUST be ignored if not
understood, except where this document or {{ACTOR-PROFILE}} specifies
processing rules.

## Signing {#signing}

The actor token MUST be signed using a JWS {{RFC7515}} algorithm. The
"none" algorithm MUST NOT be used. Implementations MUST follow the
guidance in {{RFC8725}}.

Verification keys are obtained from the descriptor's jwks_uri (or
jwks) for the issuer that matches the iss claim. The AS MUST verify
the alg against signing_alg_values_supported when present.

## Example {#example-token}

A decoded client instance actor token:

~~~ json
{
  "iss":          "https://workload.openai.example.com",
  "sub":          "spiffe://openai.example.com/codex/session-abc",
  "aud":          "https://as.example.com",
  "client_id":    "https://openai.example.com/codex",
  "sub_profile":  "client_instance ai_agent",
  "iat":          1770000000,
  "nbf":          1770000000,
  "exp":          1770000300,
  "jti":          "1a2b3c4d-5e6f",
  "cnf":          { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

# Token Endpoint Processing {#token-endpoint}

## Token Request {#token-request}

A client presents a client instance actor token at the token endpoint
by adding the actor_token and actor_token_type parameters defined by
{{RFC8693}} to a token request of any grant type listed in
{{grant-type-applicability}}.

The following example shows a client credentials grant carrying a
client instance actor token. The client class authenticates with
private_key_jwt; line breaks are for readability:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=repo.write
&client_id=https%3A%2F%2Fopenai.example.com%2Fcodex
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6...
&actor_token=eyJhbGciOiJFUzI1NiIsImtpZCI6...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

## Authorization Server Processing {#as-processing}

On receipt of a token request that includes actor_token and
actor_token_type, an AS implementing this document MUST perform the
following steps in addition to grant-type-specific processing:

1. **Authenticate the client.** Authenticate the client class using
   its registered token_endpoint_auth_method per {{RFC6749}} and, if
   applicable, {{RFC7523}}. The CIMD client_id is the client class.
   When the registered method is client_instance_actor_token, follow
   {{auth-via-actor-token}} instead of presenting a separate
   client-controlled credential.

2. **Match the token type.** If actor_token_type is not
   urn:ietf:params:oauth:token-type:client-instance-jwt, processing
   under this document does not apply. (Other actor token types MAY
   be processed under their own specifications.)

3. **Resolve client metadata.** Retrieve the CIMD document for the
   authenticated client_id, subject to caching rules in {{CIMD}}.

4. **Locate the instance issuer descriptor.** Parse the actor_token
   as a JWT and read its iss claim. Find the descriptor in
   instance_issuers whose issuer member exactly equals iss. If no
   descriptor is found, or instance_issuers is absent, reject the
   request with invalid_grant ({{errors}}).

5. **Verify the signature.** Using the descriptor's jwks_uri or
   jwks, verify the JWS signature per {{RFC7515}} and {{signing}}.

6. **Validate JWT claims.** Validate iss, sub, aud, exp, iat, nbf,
   and jti per {{claims}} and {{RFC7523}} Section 3. Enforce
   subject_syntax, trust_domain, signing_alg_values_supported, and
   actor_profiles_supported when present in the descriptor.

7. **Verify client_id binding.** The actor token's client_id claim
   MUST exactly equal the authenticated client_id. Reject with
   invalid_grant otherwise.

8. **Enforce delegation policy.** Apply max_actor_chain_depth, the
   AS's own policy, and the floor of 4 from {{ACTOR-PROFILE}}.

9. **Check authorization-time consistency.** For grants that
   originate from a prior authorization step (notably
   authorization_code), apply the rules of
   {{auth-time-consistency}}.

10. **Bind the actor.** If issuance succeeds, populate the access
    token's act claim per {{access-token}}, applying
    {{sender-constrained}} for token binding. Reflect any prior actor
    chain present in input tokens (e.g., the subject_token in a
    token-exchange request) by nesting per {{ACTOR-PROFILE}}.

If the client metadata sets actor_token_required to true and no
actor_token of this type is presented, the AS MUST reject the request
with invalid_request.

If validation succeeds, the AS issues an access token (and optionally
a refresh token) per the requested grant.

## Client Authentication via Actor Token {#auth-via-actor-token}

A client class MAY register the token_endpoint_auth_method value
client_instance_actor_token in its CIMD metadata to indicate that
the AS authenticates the client implicitly from a presented actor
token, without requiring a separate client_assertion or other
credential controlled by the class itself.

This mode is appropriate where the class has no online private key
that an instance can use, for example when the class identifier is
a logical CIMD URL with class-key custody centralized away from the
runtime, or when the workload identity provider trusted to attest
instances is also the only authority the class wishes to publish.
The trust chain to the class is preserved: the class's CIMD listing
of the instance issuer is itself the endorsement, and a token signed
by such an issuer naming this client_id is attributable to the
class.

### Token Request {#auth-via-actor-token-request}

A request using this auth method carries client_id, actor_token,
and actor_token_type. It MUST NOT carry client_assertion or any
other client authentication credential. Example, using the
client_credentials grant:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=repo.write
&client_id=https%3A%2F%2Fopenai.example.com%2Fcodex
&actor_token=eyJhbGciOiJFUzI1NiIsImtpZCI6...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

### Authorization Server Processing {#auth-via-actor-token-as}

When the registered token_endpoint_auth_method for the client_id is
client_instance_actor_token, the AS replaces step 1 of
{{as-processing}} with the following procedure:

1. Resolve CIMD metadata for client_id per {{as-processing}} step 3.
2. Validate the presented actor_token per {{as-processing}} steps 2,
   4, 5, and 6 (token type, instance issuer descriptor, signature,
   and JWT claims).
3. Verify that the actor_token's client_id claim exactly equals the
   request's client_id parameter.
4. Reject the request with invalid_client if any of the above fails.
5. Treat the client as authenticated. The validated actor_token also
   satisfies the actor_token requirement of this profile and is used
   for instance representation per {{access-token}}.

The actor_token's aud claim serves both purposes (the
{{RFC7523}} client-assertion audience and this profile's actor-token
audience). A single value identifying the AS satisfies both.

The remaining steps of {{as-processing}} apply unchanged.

## Authorization-Time Consistency {#auth-time-consistency}

When a token request is made under the authorization_code grant
({{RFC6749}} Section 4.1), the user has authorized the *client class*
identified by client_id, not any specific instance of that class. The
AS MUST ensure that the actor introduced at the token endpoint is
consistent with that authorization:

* The client_id authenticated at the token endpoint MUST match the
  client_id that received the authorization_code ({{RFC6749}} Section
  4.1.3). Combined with the client_id-binding requirement of
  {{as-processing}} step 7, this prevents an actor token from
  another client class being attached to a code.
* The AS MUST NOT permit the actor identity to bypass standard
  authorization-code controls (single-use redemption, redirect URI
  matching, and any code challenge bound to the original
  authorization request).
* If the AS has any authorization-time policy that depends on the
  actor (for example, a per-instance allow-list), the AS MUST
  evaluate that policy against the actor token presented at /token
  and reject inconsistent requests with invalid_grant.

User consent under this profile applies to the client class as a
whole; consent thereby covers all instances attested by listed
instance issuers. ASes MAY display the client class identifier and
the trust domain of the instance issuer at consent time. Per-instance
consent (asking the user to authorize a specific runtime) is out of
scope for this document; deployments requiring it MUST define it via
a separate extension.

## Sender-Constrained Access Tokens {#sender-constrained}

When the AS issues an access token under this profile, whether the
client instance is represented in act (delegation case;
{{access-token-delegation}}) or in sub (self-acting case;
{{access-token-self-acting}}), the AS MUST issue a
sender-constrained access token bound to a key the client instance
possesses. Established mechanisms include DPoP {{RFC9449}} and
Mutual-TLS-bound access tokens {{RFC8705}}.

The AS MUST NOT issue a bearer access token under this profile.
Deployments unable to sender-constrain access tokens for
operational reasons are outside the scope of this profile; they
should publish or reference a separate profile that addresses their
constraints.

If the actor token includes a cnf claim ({{claims}}), the AS SHOULD
bind the issued access token to the same key by setting the access
token's top-level cnf to that value, and SHOULD verify possession of
the key at the token endpoint (for example, by requiring a DPoP
proof in the same request) when the deployment supports it. If the
actor token does not include a cnf claim, the AS MUST establish a
sender-constrained binding through some other means (for example, by
using the client's mTLS certificate as the bound key per
{{RFC8705}}).

## Access Token Representation {#access-token}

A client instance may be acting on behalf of another principal
(*delegation case*; e.g., a user authorized the request through an
authorization_code grant) or acting as itself with no other principal
involved (*self-acting case*; e.g., a client_credentials grant). The
AS MUST classify each request as delegation or self-acting before
populating the issued access token's claims. Classification rules
are in {{access-token-classification}}; representation rules differ
between the two cases.

In both cases, the access token's client_id remains the client
class, the access token MUST be sender-constrained per
{{sender-constrained}}, and any upstream actor chain (e.g., from a
subject_token in a token-exchange request) MUST be preserved by
nesting per {{ACTOR-PROFILE}}.

### Classification {#access-token-classification}

The AS classifies the request based on whether the grant produces a
principal distinct from the instance presenting the actor_token:

| Grant | Principal | Classification |
| --- | --- | --- |
| authorization_code ({{RFC6749}}) | the user who authorized the code | delegation |
| client_credentials ({{RFC6749}}) | none | self-acting |
| refresh_token ({{RFC6749}}) | inherited from the original grant | inherited |
| jwt-bearer ({{RFC7523}}) | the assertion's sub | self-acting iff the assertion's sub is byte-equal to the actor token's sub; otherwise delegation |
| token-exchange ({{RFC8693}}) | the subject_token's subject | self-acting iff no subject_token is present (uncommon); otherwise delegation |

When neither delegation nor self-acting cleanly applies (for example,
custom or experimental grants), the AS MUST refuse to issue the
access token rather than guess; reject with invalid_grant
({{errors}}).

### Delegation Case {#access-token-delegation}

When the request is classified as delegation, the AS MUST populate
the issued access token's act claim per {{ACTOR-PROFILE}} from the
validated actor token:

* act.iss = actor token iss
* act.sub = actor token sub
* act.sub_profile = actor token sub_profile (if present); the value
  client_instance SHOULD be included.
* act.cnf = actor token cnf, if present.

The access token's sub MUST be the principal identified by the grant
(e.g., the authenticated user). When the AS issues a
sender-constrained access token, the AS SHOULD propagate the cnf to
the access token's top-level cnf so that resource servers can enforce
possession.

Example access token (delegation, sender-constrained):

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://openai.example.com/codex",
  "scope":     "repo.write",
  "iat":       1770000005,
  "exp":       1770003605,
  "cnf":       { "jkt": "0ZcOCORZNYy...iguA4I" },
  "act": {
    "iss":         "https://workload.openai.example.com",
    "sub":         "spiffe://openai.example.com/codex/session-abc",
    "sub_profile": "client_instance ai_agent",
    "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
  }
}
~~~

Example with a nested actor (the subject_token of a token-exchange
request was itself acting on behalf of the user through a prior
service):

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://openai.example.com/codex",
  "scope":     "repo.write",
  "act": {
    "iss":         "https://workload.openai.example.com",
    "sub":         "spiffe://openai.example.com/codex/session-abc",
    "sub_profile": "client_instance",
    "act": {
      "iss":         "https://upstream.example.com",
      "sub":         "service-router",
      "sub_profile": "service"
    }
  }
}
~~~

### Self-Acting Case {#access-token-self-acting}

When the request is classified as self-acting, the instance is the
principal and there is no other party on whose behalf it acts. The
AS MUST populate the issued access token from the validated actor
token as follows:

* sub = actor token sub
* sub_profile = actor token sub_profile (if present); the value
  client_instance SHOULD be included
* cnf = actor token cnf, if present (required for sender-constrained
  issuance per {{sender-constrained}})
* act MUST be omitted, except that an upstream actor chain
  (introduced by an inner act in a presented subject_token) MUST be
  preserved.

The instance issuer's identifier (the actor token's iss) is not
represented as a claim in the self-acting access token. Trust in the
instance issuer is structural: the AS validated the actor token
against the descriptor in {{instance-issuers}} before issuance, and
the resource server trusts the AS. Deployments that require
in-token instance-issuer attribution for self-acting tokens may
define a separate claim in a future profile.

Example access token (self-acting, sender-constrained,
client_credentials grant):

~~~ json
{
  "iss":         "https://as.example.com",
  "aud":         "https://api.example.com",
  "sub":         "spiffe://openai.example.com/codex/session-abc",
  "sub_profile": "client_instance ai_agent",
  "client_id":   "https://openai.example.com/codex",
  "scope":       "repo.write",
  "iat":         1770000005,
  "exp":         1770003605,
  "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

Note that client_id (the class) and sub (the instance) are distinct,
and that act is absent.

## Refresh Tokens {#refresh}

When an access token issued under this profile is refreshed
({{RFC6749}} Section 6), the AS MAY require a fresh actor token in
the refresh request, or it MAY copy the previously validated actor
identity into the refreshed access token's act claim. The choice is a
matter of AS policy and SHOULD be documented by the deployment.
Issuing access tokens with a stale act claim across long refresh
windows is discouraged; see {{security-replay}}.

## Error Responses {#errors}

Errors are returned per {{RFC6749}} Section 5.2 and {{RFC8693}}
Section 2.2.2. The following table maps the validation failures
defined in {{as-processing}} to error codes:

| Failure | error |
| --- | --- |
| actor_token absent but actor_token_required is true | invalid_request |
| actor_token present but actor_token_type absent | invalid_request |
| actor_token malformed (not a valid JWT) | invalid_request |
| actor_token_type not understood and required for the grant | unsupported_token_type ({{RFC8693}}) |
| iss not found in instance_issuers | invalid_grant |
| signature invalid; alg not permitted | invalid_grant |
| aud, exp, iat, nbf, or jti validation fails | invalid_grant |
| client_id binding mismatch | invalid_grant |
| sub_profile or trust_domain constraint fails | invalid_grant |
| max_actor_chain_depth exceeded | invalid_grant |

The AS MAY return additional information via the error_description
parameter; deployments MUST NOT include sensitive instance details
(e.g., raw SPIFFE IDs of unrelated workloads) in error responses.

# Grant Type Applicability {#grant-type-applicability}

Token endpoint grant types that MAY carry an actor_token of type
client-instance-jwt are:

* authorization_code ({{RFC6749}})
* client_credentials ({{RFC6749}})
* refresh_token ({{RFC6749}}; see {{refresh}})
* urn:ietf:params:oauth:grant-type:jwt-bearer ({{RFC7523}})
* urn:ietf:params:oauth:grant-type:token-exchange ({{RFC8693}})

For the token-exchange grant, processing under {{RFC8693}} continues
to apply; this document adds only the new actor_token_type and the
CIMD-based trust resolution.

This document does not define behavior for the implicit grant or for
the device authorization grant; specifying those is left to future
work.

# Security Considerations {#security}

This document inherits the security considerations of {{RFC6749}},
{{RFC7519}}, {{RFC7523}}, {{RFC8693}}, {{RFC8725}}, {{CIMD}}, and
{{ACTOR-PROFILE}}.

## Trust Model {#security-trust-model}

The normative trust model for this profile is in {{trust-model}}.
This subsection summarizes the security implications.

A client class delegates the authentication of its instances to one
or more instance issuers. A compromised or misconfigured instance
issuer can mint actor tokens that the AS will accept as legitimate
instances of the named client class. Client classes SHOULD list only
instance issuers under their own administrative control (or
contractually equivalent), and SHOULD set trust_domain,
actor_profiles_supported, and signing_alg_values_supported to bound
what each issuer is allowed to assert.

The CIMD document is itself trust-affecting: an attacker who can
modify it can add a new instance issuer under their control. Client
classes publishing CIMD metadata MUST protect the publication channel
(per {{CIMD}}'s requirement of HTTPS) and the storage backing it.

## Instance Lifecycle {#security-lifecycle}

Client instances are short-lived in many deployments (containers,
function invocations, agent sessions). This profile relies on three
mechanisms to keep actor identity current:

Rotation:
: Instance issuers MUST mint short-lived actor tokens
  ({{security-replay}}). New tokens are issued continuously as
  instances start, restart, or rotate keys.

Revocation within the validity window:
: Within an actor token's exp window, the AS prevents reuse via the
  jti replay rule ({{security-replay}}). A specific issued access
  token can be revoked only via the AS's own revocation mechanisms;
  this profile does not define an instance revocation list.

Trust withdrawal:
: To stop accepting actor tokens from an issuer (e.g., after a
  workload identity compromise), the client class removes the issuer
  from instance_issuers, narrows trust_domain, or rotates jwks at
  the issuer level. The AS's response is governed by
  {{trust-lifecycle}}: previously issued access tokens whose act
  references the affected scope SHOULD be revoked.

Refresh windows are a particular concern: an access token refreshed
without a new actor token may carry a stale act claim long after the
original instance has terminated. ASes SHOULD prefer requiring a
fresh actor token on refresh ({{refresh}}), or set short refresh
intervals when act is present.

## Replay {#security-replay}

Actor tokens MUST include jti, exp, and iat ({{claims}}). The AS
MUST reject tokens whose jti has been seen within their validity
window. Issuers SHOULD use short lifetimes (five minutes or less)
both to limit replay exposure and because client instances often
have lifetimes of seconds to minutes.

When refreshing access tokens ({{refresh}}), AS implementations
SHOULD prefer requiring a fresh actor token rather than perpetuating
a stale act claim, especially across long refresh windows.

## Audience and Confused Deputy

The aud claim binds the actor token to a specific AS, preventing one
AS from replaying it against another ({{RFC7523}} Section 3). The
client_id claim, which this document treats as a binding (not as
actor identity), prevents an actor token issued for one client class
from being presented under a different client class's authentication.

## Defense in Depth in Implicit Client Authentication {#security-auth-via-actor-token}

The client_instance_actor_token authentication method
({{auth-via-actor-token}}) eliminates the requirement for the client
class to control a private key used at the token endpoint. The
trust chain to the class is preserved (the CIMD listing endorses the
instance issuer), but the AS no longer requires possession of two
independent keys to issue a token: compromise of any CIMD-listed
instance issuer is sufficient to mint tokens that authenticate as
the class.

In contrast, modes such as private_key_jwt require an attacker to
possess both an instance issuer's signing key (to mint the actor
token) and the class's private key (to assert the client) before any
token can be issued. Where the operational model permits, deployments
SHOULD prefer two-key authentication.

When client_instance_actor_token is used, classes SHOULD constrain
each instance issuer's authority through trust_domain,
actor_profiles_supported, and signing_alg_values_supported, and
SHOULD list only the minimum set of instance_issuers necessary.

## Mode-Switch Between Delegation and Self-Acting

Whether an issued access token represents delegation or self-acting
({{access-token-classification}}) determines whether the instance is
exposed to resource servers as act or as sub. An adversary that can
influence classification could escalate privileges, for example by
inducing the AS to drop a sub belonging to a user and re-anchor the
token on the instance's sub. The classification rule in
{{access-token-classification}} is byte-equality of subject
identifiers; ASes MUST NOT employ heuristic or fuzzy matching that
could be manipulated by attacker-controlled assertion contents. When
classification is ambiguous (for example, custom grants not listed in
the table), the AS MUST refuse rather than guess.

## Binding {#security-binding}

Without sender-constraint, an act claim is an *assertion* about who
acted, not a *binding* enforced at the resource server: any party in
possession of the access token can present it as the named actor.
For this reason {{sender-constrained}} requires sender-constrained
access tokens whenever act is populated under this profile and
forbids bearer issuance.

This document does not specify a single proof-of-possession
mechanism. DPoP {{RFC9449}} and Mutual TLS {{RFC8705}} are the
primary examples in current OAuth practice; other mechanisms may be
defined elsewhere. Where the actor token itself carries cnf, the AS
SHOULD propagate cnf to both the access token's top-level cnf and
the act object so that downstream resource servers can verify
possession against the same key the AS authenticated.

## Delegation Control

Unbounded delegation chains permit privilege amplification across
boundaries. Client classes SHOULD set max_actor_chain_depth, AS
implementations SHOULD enforce their own ceiling, and both MUST
honor the floor of 4 from {{ACTOR-PROFILE}}.

## Privacy

A client instance actor token reveals fine-grained workload identity
to the AS and, after issuance, to resource servers via the act claim.
Issuers and client classes SHOULD avoid encoding sensitive
information (e.g., human user identifiers, internal infrastructure
details) in sub. The error response guidance in {{errors}} extends
to logs and audit trails: actor token contents SHOULD be logged at a
level commensurate with the sensitivity of the workload identity
they convey.

# IANA Considerations {#iana}

## OAuth Token Type {#iana-token-type}

IANA is requested to register the following value in the "OAuth URI"
registry established by {{RFC6755}} (and used by {{RFC8693}} for
actor_token_type values):

URN:
: urn:ietf:params:oauth:token-type:client-instance-jwt

Common Name:
: OAuth 2.0 Client Instance Actor Token

Change Controller:
: IETF

Specification Document(s):
: This document

## OAuth Dynamic Client Registration Metadata {#iana-client-metadata}

IANA is requested to register the following parameters in the "OAuth
Dynamic Client Registration Metadata" registry established by
{{RFC7591}}. The Change Controller for each entry is IETF.

### instance_issuers

Client Metadata Name:
: instance_issuers

Client Metadata Description:
: Trusted issuers of client instance actor tokens for this client.

Specification Document(s):
: {{instance-issuers}} of this document

### max_actor_chain_depth

Client Metadata Name:
: max_actor_chain_depth

Client Metadata Description:
: Maximum permitted delegation depth for act chains rooted at an
  instance of this client.

Specification Document(s):
: {{max-actor-chain-depth}} of this document

### actor_token_required

Client Metadata Name:
: actor_token_required

Client Metadata Description:
: When true, the AS rejects token requests for this client that lack
  a client instance actor token.

Specification Document(s):
: {{actor-token-required}} of this document

## OAuth Token Endpoint Authentication Method {#iana-auth-method}

IANA is requested to register the following value in the "OAuth Token
Endpoint Authentication Methods" registry established by {{RFC8414}}:

Token Endpoint Authentication Method Name:
: client_instance_actor_token

Change Controller:
: IETF

Specification Document(s):
: {{auth-via-actor-token}} of this document

## OAuth Authorization Server Metadata {#iana-as-metadata}

IANA is requested to register the following parameter in the "OAuth
Authorization Server Metadata" registry established by {{RFC8414}}:

Metadata Name:
: actor_token_types_supported

Metadata Description:
: JSON array of actor_token_type values supported at the token
  endpoint.

Change Controller:
: IETF

Specification Document(s):
: {{as-metadata}} of this document

## OAuth Entity Profile {#iana-entity-profile}

IANA is requested to register the following value in the "OAuth
Entity Profiles" registry established by {{ENTITY-PROFILES}}. This
registration is contingent on the establishment of that registry.

Profile Name:
: client_instance

Profile Description:
: A concrete runtime instance of an OAuth client class identified by
  a Client ID Metadata Document.

Profile Usage Location:
: Actor Profile

Change Controller:
: IETF

Specification Document(s):
: This document


--- back

# Design Rationale {#design-rationale}
{:numbered="false"}

This appendix records design choices that motivated the normative
text.

## Why not a client_instance request parameter?
{:numbered="false"}

A new top-level client_instance parameter would have to flow through
the authorization request, the token request, introspection, the
access token, and several existing extensions. Each is a separate
specification touch-point and a deployment cliff. Reusing actor_token
keeps the protocol surface unchanged.

## Why extend actor_token to non-token-exchange grants?
{:numbered="false"}

The actor concept in {{RFC8693}} fits client instance identity
exactly: the instance acts on behalf of the subject (the human user
or service principal) under the authority of the client class. The
parameter machinery is already specified, deployed, and understood.
The only normative move is permitting it on additional grants: a
small, contained extension whose security analysis is the union of
{{RFC8693}}'s and the underlying grant's.

## Why CIMD as the trust anchor for instance issuers?
{:numbered="false"}

CIMD already establishes a publication mechanism for client metadata
keyed to a stable, dereferenceable client identifier. Listing
instance issuers in the same document keeps the trust relationship
between client class and instance issuer auditable in one place and
reuses CIMD's caching and key-rotation rules.

## Why a dedicated actor_token_type URN?
{:numbered="false"}

The generic JWT token type does not signal that the AS should look
up trust via CIMD's instance_issuers, nor that client_id binding
applies. A dedicated URN lets ASes route processing unambiguously
and lets clients advertise support via actor_token_types_supported.

# Acknowledgments
{:numbered="false"}

The author thanks participants in the OAuth Working Group for
discussions on client instance identity, workload identity, and
actor-based delegation that informed this document.
