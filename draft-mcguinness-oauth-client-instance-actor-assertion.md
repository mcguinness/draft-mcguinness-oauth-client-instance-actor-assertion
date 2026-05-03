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
  RFC9068:
  CIMD: I-D.ietf-oauth-client-id-metadata-document
  ACTOR-PROFILE: I-D.mcguinness-oauth-actor-profile
  ENTITY-PROFILES: I-D.mora-oauth-entity-profiles

informative:
  RFC7662:
  RFC8705:
  RFC9449:
  RFC9101:
  RFC9126:
  RFC8707:
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
{{grant-type-applicability}}, while preserving their semantics in the
*delegation* case ({{access-token-delegation}}): the actor_token
identifies the party acting on behalf of the subject and is reflected
in an act claim in the issued token. Use of these parameters on a
token exchange request remains fully governed by {{RFC8693}}, with
the additional client-instance-jwt token type defined here.

This document additionally defines a *self-acting* case
({{access-token-self-acting}}) for grants that produce no principal
distinct from the instance (notably client_credentials). In that
case the validated instance identity is the principal: the issued
access token's sub names the instance and act is not populated.
{{RFC8693}}'s "actor" framing presumes a separate subject and so
does not strictly apply to self-acting requests, but this profile
reuses the actor_token wire artifact and validation rules unchanged
because the same JWT correctly produces either shape; classification
is determined by the grant, not by the actor token. See
{{rationale-self-acting}}.

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
non-SPIFFE JWT actor tokens (any subject_syntax other than
"spiffe"), and the client class itself may authenticate via
private_key_jwt, {{SPIFFE-CLIENT-AUTH}}, or any other registered
method.

For SPIFFE deployments specifically, this profile defines first-
class support to enable presenting JWT-SVIDs from the SPIFFE
Workload API directly as actor_token without re-minting:

* the instance_issuers descriptor accepts spiffe_bundle_endpoint
  as a trust source ({{instance-issuers}}), aligned with
  {{SPIFFE-CLIENT-AUTH}};
* the descriptor accepts a spiffe_id member with optional "/*"
  wildcard ({{instance-issuers}}), structurally bounding which
  workloads may be attested as instances of the class (analogous to
  {{SPIFFE-CLIENT-AUTH}}'s spiffe_id matching for client auth); and
* the actor_token's client_id claim is OPTIONAL when the matched
  descriptor uses these SPIFFE features ({{spiffe-client-id-omission}}).

A SPIFFE deployment combining {{SPIFFE-CLIENT-AUTH}} with this
profile MAY present the same SVID as both client_assertion and
actor_token in a single token request ({{spiffe-combined}}). An
end-to-end deployment recipe is in {{appendix-spiffe-recipe}}.

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

When the client class registers token_endpoint_auth_method
client_instance_actor_token ({{auth-via-actor-token}}), these two
trust anchors collapse onto a single artifact: the actor token both
authenticates the client class (via the CIMD endorsement of its
issuer) and identifies the instance. In that mode the request
carries no separate client_assertion; the client authentication and
the actor assertion are the same JWT.

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
delegated scope, and MUST NOT mint actor tokens whose client_id names
a class for which the runtime has not been authorized as a member
({{layering}}). This per-class minting requirement is what prevents
cross-class instance impersonation when the same instance issuer is
listed by multiple client classes (for example, in multi-tenant
SaaS).

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
mutable. When the CIMD document changes (for example, an instance
issuer is removed, its jwks_uri or jwks rotates, its trust_domain is
replaced, or its actor_profiles_supported or
signing_alg_values_supported narrows), the AS applies the same
freshness and re-fetch rules it applies to other CIMD-published
trust material such as jwks_uri (see {{CIMD}}).

For the cache window during which the AS may continue to honor a
stale descriptor, this profile imposes no additional revocation
requirement on previously issued access tokens. After the AS has
adopted the updated CIMD document, the AS SHOULD treat further use
of access tokens whose act claim either (a) names a removed instance
issuer, or (b) falls outside the descriptor's updated scope, as no
longer endorsed by the client class. Where the deployment supports
it, this is naturally enforced by access-token introspection and
short access-token lifetimes; AS implementations MAY additionally
revoke such tokens via {{RFC6749}} Section 7 mechanisms.

To bound the compromise recovery window, ASes issuing access tokens
under this profile SHOULD set the access token TTL no longer than
the AS's CIMD cache TTL plus the actor token's exp window. A
deployment that cannot satisfy this bound (for example, because it
issues long-lived access tokens for offline-capable resources) MUST
support active access-token revocation per {{RFC6749}} Section 7,
and SHOULD support introspection-based status checks at the
resource server.

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
or is present as an empty array, the AS MUST NOT accept actor tokens
of type urn:ietf:params:oauth:token-type:client-instance-jwt for this
client; the AS SHOULD treat an empty array as a metadata error and
log it for the client class operator.

An instance issuer descriptor has the following members:

issuer (REQUIRED):
: A StringOrURI {{RFC7519}} identifying the instance issuer. This
  value MUST exactly match the iss claim of accepted actor tokens.

A descriptor MUST contain exactly one of jwks_uri, jwks, and
spiffe_bundle_endpoint. If two or more are present, or all are
absent, the AS MUST reject the descriptor as invalid client metadata.

jwks_uri:
: An HTTPS URL of a JWK Set {{RFC7517}} containing the public keys
  used to verify signatures of actor tokens issued by this issuer.

jwks:
: An inline JWK Set serving the same purpose as jwks_uri.

spiffe_bundle_endpoint:
: An HTTPS URL of a SPIFFE trust bundle endpoint {{SPIFFE}} from
  which the AS resolves verification keys for actor tokens issued by
  this issuer. When present, subject_syntax MUST be "spiffe". The
  bundle endpoint format and resolution rules are governed by SPIFFE;
  see {{SPIFFE-CLIENT-AUTH}} for the analogous use in client
  authentication.

signing_alg_values_supported (OPTIONAL):
: A JSON array of JWS {{RFC7515}} alg values that this issuer uses to
  sign actor tokens. If present, the AS MUST reject actor tokens
  whose alg is not listed.

subject_syntax (OPTIONAL):
: A short identifier indicating the syntactic profile of the sub
  claim used by this issuer. Defined values are "uri" (default,
  arbitrary StringOrURI) and "spiffe" (a SPIFFE ID {{SPIFFE}}; see
  also {{SPIFFE-CLIENT-AUTH}} for the related SPIFFE-based client
  authentication profile). Other values MAY be defined by future
  specifications. An AS that does not understand the value MUST reject
  actor tokens for that descriptor with invalid_grant.

trust_domain (OPTIONAL):
: When subject_syntax is "spiffe", a SPIFFE trust domain that the
  sub claim MUST belong to. The AS MUST reject any actor token
  whose sub does not lie within this trust domain. A descriptor's
  trust_domain is independent of any SPIFFE trust domain associated
  with the client class itself under {{SPIFFE-CLIENT-AUTH}}; the two
  MAY differ.

spiffe_id (OPTIONAL):
: When subject_syntax is "spiffe", a SPIFFE ID that further bounds
  which workloads this issuer may attest as instances of this class.
  The value is a SPIFFE ID, optionally with a trailing "/*" wildcard,
  using the same syntax and matching rules as {{SPIFFE-CLIENT-AUTH}}.
  Without "/*", the actor token's sub MUST equal this value exactly;
  with "/*", the actor token's sub MUST be a SPIFFE ID whose prefix
  before the wildcard matches this value's prefix and whose path
  begins with the prefix's path. If both spiffe_id and trust_domain
  are present, the trust domain in spiffe_id MUST equal trust_domain.
  This member, when present, structurally binds a workload subtree
  to this client class — see {{spiffe-client-id-omission}}.

actor_profiles_supported (OPTIONAL):
: A JSON array of sub_profile values from the OAuth Entity Profiles
  registry {{ENTITY-PROFILES}} that this issuer is authorized to
  assert. If present, the AS MUST reject any actor token whose
  sub_profile contains values not listed.

Example client metadata document with a SPIFFE instance issuer:

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

Example client metadata document using a non-SPIFFE instance issuer
(a platform-managed identity service):

~~~ json
{
  "client_id": "https://app.example.com/billing-agent",
  "jwks_uri": "https://app.example.com/billing-agent/jwks.json",
  "token_endpoint_auth_method": "private_key_jwt",
  "instance_issuers": [
    {
      "issuer": "https://identity.platform.example.net",
      "jwks_uri": "https://identity.platform.example.net/jwks.json",
      "subject_syntax": "uri",
      "signing_alg_values_supported": ["ES256", "RS256"],
      "actor_profiles_supported": ["client_instance"]
    }
  ]
}
~~~

## max_actor_chain_depth {#max-actor-chain-depth}

OPTIONAL. A positive integer specifying the maximum delegation depth
({{ACTOR-PROFILE}}) the client class permits in actor chains
originating from one of its instances. If absent, the AS applies its
own policy. The AS MUST reject requests whose resulting act chain
would exceed the lower of (a) this value, when present, and (b) the
AS-imposed maximum, with invalid_request per {{ACTOR-PROFILE}}.

ASes implementing this profile SHOULD support a local maximum of at
least depth 4, consistent with the cross-domain interoperability
recommendation in {{ACTOR-PROFILE}}.

## actor_token_required {#actor-token-required}

OPTIONAL. A JSON boolean. When true, the AS MUST reject any token
request from this client_id that does not include an actor_token of
type urn:ietf:params:oauth:token-type:client-instance-jwt. The default
is false.

This requirement applies uniformly across grant types, including
refresh_token and token-exchange. In particular, a token-exchange
request whose actor_token is of a different type (for example, the
generic urn:ietf:params:oauth:token-type:jwt) does not satisfy this
requirement, and the AS MUST reject it with invalid_request even if
that other actor_token would otherwise be processable under
{{RFC8693}}.

This parameter lets a client class enforce that every issued access
token is bound to an identifiable instance. It is redundant when
token_endpoint_auth_method is client_instance_actor_token
({{auth-via-actor-token}}); in that mode the actor token is
implicitly required by the auth method itself.

# Authorization Server Metadata {#as-metadata}

This document defines the following AS metadata parameters for
{{RFC8414}} (see {{iana-as-metadata}}):

actor_token_types_supported:
: A JSON array of actor_token_type values supported by the AS at the
  token endpoint. An AS implementing this profile SHOULD publish this
  parameter and MUST include
  urn:ietf:params:oauth:token-type:client-instance-jwt in it. This is
  the only AS-side discovery signal for support of this profile;
  clients use it to decide whether to assemble token requests
  carrying an actor token.

Values other than urn:ietf:params:oauth:token-type:client-instance-jwt
MAY appear in actor_token_types_supported and are processed under
their own specifications. For non-normative reference, the values
defined in {{RFC8693}} Section 3 (including
urn:ietf:params:oauth:token-type:jwt,
urn:ietf:params:oauth:token-type:access_token, and
urn:ietf:params:oauth:token-type:id_token) describe generic actor
tokens whose trust is resolved by means outside this document (e.g.,
configured issuers or token introspection). The
urn:ietf:params:oauth:token-type:client-instance-jwt value is
distinguished by its CIMD-based instance_issuers trust resolution
({{instance-issuers}}) and its required client_id binding
({{claims}}).

subject_syntaxes_supported:
: OPTIONAL. A JSON array of subject_syntax values
  ({{instance-issuers}}) that the AS understands when validating
  client instance actor tokens. If the AS publishes this array, a
  client class SHOULD only register instance_issuers descriptors
  whose subject_syntax appears in it. If absent, clients MUST assume
  the AS supports at least the default value "uri".

In addition, an AS that supports {{auth-via-actor-token}} MUST
advertise client_instance_actor_token in
token_endpoint_auth_methods_supported ({{RFC8414}}).

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
  An instance issuer MUST refuse to mint an actor token whose
  client_id claim names a class for which the runtime has not been
  authorized, by issuer-side policy, as a member.

How the issuer internally authenticates the runtime is out of scope
for this document, but a common deployment pattern uses an
underlying workload identity system (Kubernetes projected service-
account tokens, AWS IMDS, GCP metadata server, Azure managed
identity, a SPIFFE control plane, etc.) and a thin "OAuth-aware
adapter" that re-mints a client instance actor token from the
underlying credential by adding this profile's required claims
(client_id, aud, jti) and signing with a key registered in the
client class's CIMD instance_issuers descriptor. From the AS's
perspective, the adapter is the instance issuer; the underlying
identity material is internal to the issuer's authentication
procedure. Deployments choosing this pattern SHOULD ensure the
adapter enforces the per-class authorization above (the underlying
workload-identity system typically does not know about OAuth client
classes).

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
: The intended audience, identifying the AS. The AS validates aud per
  {{RFC7523}} Section 3, accepting its own issuer identifier or
  token endpoint URL; if multiple values are present, at least one
  MUST match. Each AS SHOULD specify a single canonical aud format
  (typically its issuer identifier) and document it; instance issuers
  SHOULD use that canonical form. Where actor tokens are scoped per
  AS, instance issuers SHOULD mint an AS-specific actor token rather
  than a multi-aud JWT, to limit the replay surface.

client_id (REQUIRED unless the SPIFFE compatibility conditions of {{spiffe-client-id-omission}} are met):
: The client_id of the client class to which this instance belongs.
  This claim uses the JSON Web Token client_id claim registered by
  {{RFC9068}} Section 2.2 (which itself defers to {{RFC8693}}
  Section 4.3 for the underlying definition). Note that RFC 9068
  defines client_id as the OAuth client to which a JWT access token
  was issued; in this profile, the claim instead names the client
  class to which the asserted instance belongs. It binds the actor
  token to a specific client class and is not part of the actor's
  identity (per {{ACTOR-PROFILE}}, client_id identifies an OAuth
  client, not an actor). When present, the AS MUST reject the token
  if this value does not exactly equal the client_id of the
  authenticated client. When omitted under
  {{spiffe-client-id-omission}}, the binding is established
  structurally by the matched descriptor's spiffe_id rather than by
  a JWT claim, and a SPIFFE JWT-SVID may be presented as the
  actor_token directly without re-minting.

exp (REQUIRED):
: Expiration time. Issuers SHOULD set short lifetimes (e.g., five
  minutes or less); see {{security-replay}}.

iat (REQUIRED):
: Issued-at time.

jti (REQUIRED):
: A unique identifier used for replay prevention; see
  {{security-replay}}.

sub_profile (RECOMMENDED):
: One or more OAuth Entity Profile names {{ENTITY-PROFILES}}
  classifying the actor. Its syntax (a space-delimited string of
  profile names) is the one defined by {{ACTOR-PROFILE}}, which
  matches the format of the actor_profiles_supported descriptor
  member ({{instance-issuers}}) when each member of that array is
  treated as a single profile name. This document registers the
  value client_instance ({{iana-entity-profile}}). Issuers MAY
  include additional values registered with the "Actor Profile"
  usage location in the OAuth Entity Profiles registry, or
  privately defined collision-resistant values, per
  {{ACTOR-PROFILE}}.

cnf (RECOMMENDED):
: A confirmation claim {{RFC7800}} carrying a key bound to this
  instance, enabling proof-of-possession at the AS and propagation to
  downstream resource servers. When cnf is present, the instance
  issuer MUST mint it from a key whose corresponding private key the
  named runtime instance demonstrably possesses (for example, an
  instance-attested key, a per-instance workload key, or a DPoP
  public key presented by the runtime to the issuer at attestation
  time). Issuers SHOULD include cnf so that access tokens whose act
  claim names the instance can be sender-constrained. See
  {{sender-constrained}} and {{security-binding}}.

nbf (OPTIONAL):
: Not-before time. If present, the AS MUST reject the token before
  this time.

A client instance actor token MUST NOT contain an act claim. The
actor token is a direct identity assertion of a single party (the
instance); per {{ACTOR-PROFILE}}, an actor_token that carries an
act claim represents a delegation chain rather than a direct
identity, and the AS MUST reject such a token with invalid_grant
({{chain-merging}}, {{errors}}).

Additional claims MAY be present and MUST be ignored if not
understood, except where this document or {{ACTOR-PROFILE}} specifies
processing rules. Future profiles requiring AS understanding of a
new claim SHOULD use the JWS crit header parameter ({{RFC7515}}
Section 4.1.11) to mark it must-understand; ASes MUST reject actor
tokens whose crit header includes claims they do not implement.

## Signing {#signing}

The actor token MUST be signed using a JWS {{RFC7515}} algorithm. The
"none" algorithm MUST NOT be used. Implementations MUST follow the
guidance in {{RFC8725}}.

For interoperability, ASes implementing this profile SHOULD support
both RS256 and ES256 for actor token signature verification. Other
asymmetric algorithms permitted by the descriptor's
signing_alg_values_supported MAY be supported.

Issuers SHOULD include a kid in the JWS protected header to identify
the signing key, and ASes SHOULD use kid for key selection from the
descriptor's jwks_uri or jwks.

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

The sub_profile value "ai_agent" is illustrative; only
"client_instance" is registered by this document
({{iana-entity-profile}}). Other values require their own
registration in the OAuth Entity Profiles registry
{{ENTITY-PROFILES}}.

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

When evaluating a token request for this profile, an AS implementing
this document MUST perform the following checks and steps in addition
to grant-type-specific processing.

Before the steps below, the AS MUST reject the request with
invalid_request if any of the following pre-conditions hold:

* exactly one of actor_token and actor_token_type is present;
* actor_token_type is
  urn:ietf:params:oauth:token-type:client-instance-jwt but
  actor_token is absent;
* actor_token is present but is not a syntactically valid JWT.

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

7. **Verify client_id binding.** If the actor token contains a
   client_id claim, it MUST exactly equal the authenticated
   client_id; reject with invalid_grant otherwise. If the
   actor token has no client_id claim, the AS MUST verify that the
   matched descriptor satisfies the SPIFFE compatibility conditions
   ({{spiffe-client-id-omission}}); if not, reject with
   invalid_grant. When the descriptor satisfies those conditions,
   the AS MUST verify that the actor_token's sub falls under the
   descriptor's spiffe_id (with wildcard expansion if any); if not,
   reject with invalid_grant.

8. **Enforce delegation policy.** Apply max_actor_chain_depth and the
   AS's own maximum, subject to the minimum supported depth required by
   {{ACTOR-PROFILE}}.

9. **Check authorization-time consistency.** For grants that
   originate from a prior authorization step (notably
   authorization_code), apply the rules of
   {{auth-time-consistency}}.

10. **Bind the instance.** If issuance succeeds, represent the
    instance in the access token per {{access-token}}, applying
    {{sender-constrained}} for token binding. Reflect any prior actor
    chain present in input tokens by nesting per {{ACTOR-PROFILE}};
    chain merging rules are given in {{chain-merging}}.

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
4. Verify proof-of-possession of the actor_token at presentation per
   {{sender-constrained}}. In this mode the actor_token serves as the
   sole client authentication credential, so the bearer-replay
   considerations in {{security-replay}} apply with no fallback
   credential; ASes SHOULD reject requests in this mode whose
   actor_token lacks a cnf claim, and MUST verify possession of the
   cnf key when present.
5. Reject the request with invalid_client if any of the above fails.
6. Treat the client as authenticated. The validated actor_token also
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
the trust domain of the instance issuer at consent time.

ASes that record consent SHOULD record the descriptor scope under
which consent was granted (in particular, the descriptor's issuer
and trust_domain), and MAY refuse access tokens for the same client
class issued under a different descriptor scope than the one
consented. This matters for client classes deployed across multiple
trust domains (for example, "production" vs. "staging" SPIFFE trust
domains, or distinct PaaS environments) where the user's consent to
one is not necessarily consent to another.

Per-instance consent (asking the user to authorize a specific
runtime) is out of scope for this document; deployments requiring it
MUST define it via a separate extension.

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

If the actor token includes a cnf claim ({{claims}}), the AS MUST:

* bind the issued access token to the same key by setting the access
  token's top-level cnf to the actor token's cnf value;
* verify possession of the cnf key at the token endpoint, matching
  the confirmation method used in cnf per {{RFC7800}}. For cnf.jkt,
  the JWK thumbprint of the DPoP proof's public key {{RFC9449}} MUST
  equal cnf.jkt. For cnf.x5t#S256, the certificate authenticated at
  the TLS layer {{RFC8705}} MUST match cnf.x5t#S256. Other
  confirmation methods MUST be verified per their defining
  specifications;
* reject the request with invalid_request if verification fails.

This protects the actor token from bearer-style replay within its
validity window ({{security-replay}}); without it, the actor token
would be a bearer credential whose replay is bounded only by exp
and the jti cache.

The binding key MUST be specific to the validated client instance.
A credential shared by the client class as a whole, such as the
class-level mTLS certificate authenticated under {{RFC8705}}, the
class's private_key_jwt key, or any other class-controlled key not
provisioned per-instance, is not sufficient.

If the actor token does not include a cnf claim, the AS MUST
establish an instance-specific binding through some other means
whose key is attributable to the validated instance, for example:

* a per-instance mTLS client certificate provisioned by the instance
  issuer (or otherwise tied to instance attestation) and presented
  under {{RFC8705}}; or
* a DPoP key {{RFC9449}} that the AS confirms, through deployment-
  specific attestation or out-of-band binding to the instance issuer,
  represents the same runtime named by the actor token's sub.

If the AS cannot establish such an instance-specific binding, it
MUST reject the request with invalid_request ({{errors}}). For this
reason, instance issuers SHOULD include cnf in actor tokens so that
the binding key is supplied by the same authority that named the
instance.

Deployments combining class-level Mutual-TLS-bound client
authentication ({{RFC8705}}) with this profile MUST establish
instance binding through a separate, instance-specific key. The
typical configuration uses the class's mTLS certificate at the TLS
layer for client authentication and a cnf.jkt in the actor token
paired with DPoP {{RFC9449}} at the token endpoint for instance
binding. Per-instance mTLS certificates issued by the instance
issuer (or otherwise bound to instance attestation) are an
alternative; in that case the same TLS certificate satisfies both
class authentication and instance binding only if the AS treats it
as belonging to the instance for binding purposes.

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
{{sender-constrained}}, and any upstream actor chain MUST be
preserved by nesting per {{ACTOR-PROFILE}}; merge rules are in
{{chain-merging}}.

### Classification {#access-token-classification}

The AS classifies the request based on whether the grant produces a
principal distinct from the instance presenting the actor_token:

| Grant | Principal | Classification |
| --- | --- | --- |
| authorization_code ({{RFC6749}}) | the user who authorized the code | delegation |
| client_credentials ({{RFC6749}}) | none | self-acting |
| refresh_token ({{RFC6749}}) | inherited from the original grant | inherited |
| jwt-bearer ({{RFC7523}}) | the assertion's sub | delegation |
| token-exchange ({{RFC8693}}) | the subject_token's subject | delegation |

The jwt-bearer and token-exchange rows always classify as delegation
under this profile. {{RFC7523}} requires a JWT-bearer assertion that
identifies a principal, and {{RFC8693}} Section 2.1 requires a
subject_token; in both cases another party is present and named, so
the issued access token's sub is that party and the instance appears
in act. ASes MUST NOT classify these grants as self-acting based on
heuristic matching of subject identifiers; see
{{security-mode-switch}}.

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

The access token's sub MUST be the principal identified by the
grant (e.g., the authenticated user). The AS MUST also propagate the
actor token's cnf (if present) to the access token's top-level cnf
per {{sender-constrained}}, so that resource servers can enforce
possession against the same key the AS verified at issuance.

Example (delegation, sender-constrained). The validated source
client instance actor token, with all claims required by {{claims}}:

~~~ json
{
  "iss":         "https://workload.openai.example.com",
  "sub":         "spiffe://openai.example.com/codex/session-abc",
  "aud":         "https://as.example.com",
  "client_id":   "https://openai.example.com/codex",
  "sub_profile": "client_instance ai_agent",
  "iat":         1770000000,
  "nbf":         1770000000,
  "exp":         1770000300,
  "jti":         "1a2b3c4d-5e6f",
  "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

Issued access token. Note that the actor token's iss, sub,
sub_profile, and cnf propagate to act; aud, client_id, exp, iat, and
jti are validated and consumed by the AS but do not appear in the
access token (client_id appears at the top level as a property of
the issued token, not the actor):

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
service). Source client instance actor token, with all claims
required by {{claims}}:

~~~ json
{
  "iss":         "https://workload.openai.example.com",
  "sub":         "spiffe://openai.example.com/codex/session-abc",
  "aud":         "https://as.example.com",
  "client_id":   "https://openai.example.com/codex",
  "sub_profile": "client_instance",
  "iat":         1770000000,
  "nbf":         1770000000,
  "exp":         1770000300,
  "jti":         "9f8e7d6c-5b4a",
  "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

Issued access token. The outermost act represents the requesting
instance and inherits the access token's top-level cnf for
sender-constraint; nested actors further down the chain are
historical and need not carry cnf at this layer:

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://openai.example.com/codex",
  "scope":     "repo.write",
  "cnf":       { "jkt": "0ZcOCORZNYy...iguA4I" },
  "act": {
    "iss":         "https://workload.openai.example.com",
    "sub":         "spiffe://openai.example.com/codex/session-abc",
    "sub_profile": "client_instance",
    "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" },
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

Example (self-acting, sender-constrained, client_credentials grant).
Source client instance actor token, with all claims required by
{{claims}}:

~~~ json
{
  "iss":         "https://workload.openai.example.com",
  "sub":         "spiffe://openai.example.com/codex/session-abc",
  "aud":         "https://as.example.com",
  "client_id":   "https://openai.example.com/codex",
  "sub_profile": "client_instance ai_agent",
  "iat":         1770000000,
  "nbf":         1770000000,
  "exp":         1770000300,
  "jti":         "1a2b3c4d-5e6f",
  "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

Issued access token:

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
and that act is absent. The actor token's iss is not represented in
the access token (see preceding paragraph).

### Actor Chain Merging {#chain-merging}

Per {{ACTOR-PROFILE}}, a client instance actor token presented as
actor_token MUST NOT itself carry an act claim; if it does, the AS
MUST reject the request with invalid_grant. A client instance actor
token is a direct identity assertion of the instance, not a
delegation-chain credential.

Consequently, only two inputs can contribute actor information to
the issued token under this profile:

* the validated actor_token (this request's instance, the new
  outermost actor); and
* the subject_token's act chain, if any (only applicable to a
  token-exchange ({{RFC8693}}) request, since other grants do not
  introduce a subject_token).

The AS MUST construct the issued access token's act chain by
applying the algorithm in {{ACTOR-PROFILE}} (its "Delegation Chain
Validation and Construction" section) with the validated actor_token
as the new outermost actor and the subject_token's preserved
delegation chain (when present) nested inside. The resulting depth
MUST NOT exceed max_actor_chain_depth ({{max-actor-chain-depth}});
otherwise the AS MUST reject the request with invalid_request
({{errors}}), per {{ACTOR-PROFILE}}.

In the self-acting case ({{access-token-self-acting}}) the act claim
is omitted at top level. When a subject_token is present (uncommon
outside token-exchange, which this profile classifies as delegation
in any case), any act chain it carries is preserved verbatim per
{{ACTOR-PROFILE}}.

## Interactions with Other OAuth Extensions {#interactions}

This profile conveys actor identity at the token endpoint only. Its
interactions with other OAuth extensions are as follows.

### Pushed Authorization Requests (PAR) and JAR {#interactions-par-jar}

This profile does not define any extensions to the authorization
request, so it does not interact directly with Pushed Authorization
Requests {{RFC9126}} or JWT-Secured Authorization Requests
{{RFC9101}}. A request that uses PAR or JAR for the authorization
step proceeds to the token endpoint as usual; the actor_token and
actor_token_type parameters are presented at /token in the same way
as for a non-PAR/JAR flow. ASes implementing per-actor
authorization-time policy ({{auth-time-consistency}}) evaluate that
policy at the token endpoint, after the actor token has been
validated; PAR and JAR do not change this.

### Resource Indicators {#interactions-resource}

The resource parameter {{RFC8707}} constrains the audience of the
issued access token. It is orthogonal to actor identity: the same
client instance MAY request access tokens for multiple resources
under a single user consent, and the AS populates act (delegation
case) or sub (self-acting case) the same way regardless of resource.
Per-resource policies that depend on the actor (for example,
restricting an instance to a subset of resources the class is
otherwise permitted) are an AS-side decision; this profile does not
require or define them. When such a policy applies, the AS MUST
evaluate it against the validated actor token before issuing the
access token, and reject inconsistent requests with invalid_grant
({{errors}}).

### Token Introspection {#interactions-introspection}

When an AS supports token introspection {{RFC7662}} for access
tokens issued under this profile, introspection responses for
delegated tokens follow the introspection semantics defined by
{{ACTOR-PROFILE}}. The top-level cnf, when present in the access
token, SHOULD be returned in the introspection response so that
protected resources performing introspection-based proof-of-
possession have the binding key. In the self-acting case, the
access token's sub_profile and cnf SHOULD be returned alongside the
standard {{RFC7662}} response fields.

## SPIFFE Compatibility {#spiffe-compatibility}

A SPIFFE workload typically obtains a JWT-SVID from the SPIFFE
Workload API. JWT-SVIDs carry iss (the trust domain), sub (the
SPIFFE ID), aud, exp, iat, and a signature, but do not carry an
OAuth client_id claim. To allow such SVIDs to be presented as
actor_token without re-minting, this profile defines a SPIFFE
compatibility mode driven entirely by descriptor configuration.

### client_id Claim Omission {#spiffe-client-id-omission}

When all of the following hold for the descriptor that matches the
actor_token's iss:

* subject_syntax is "spiffe";
* a spiffe_id member is present ({{instance-issuers}}); and
* the actor_token's sub satisfies the spiffe_id matching rule
  (exact match or prefix match including the "/*" wildcard);

the AS MUST treat the descriptor as the per-class binding even if
the actor_token has no client_id claim. In this mode:

* The AS MUST verify that the actor_token's sub falls under the
  descriptor's spiffe_id (after applying the wildcard, if any).
* If the actor_token has a client_id claim, it MUST still equal the
  request's client_id parameter ({{as-processing}} step 7); the
  exception narrows the *requirement* that the claim be present,
  not the *consistency* of the claim when present.
* All other JWT claims and validation rules of {{claims}} continue
  to apply unchanged.

The security rationale is that the descriptor's spiffe_id, signed
into the client class's CIMD document and dereferenced by the AS,
is itself the per-class binding: a workload's SPIFFE ID is bound to
a class by the class explicitly listing the prefix that contains it.
This is the same model SPIFFE-CLIENT-AUTH uses for client
authentication, applied here to actor identity.

### SPIFFE Trust Bundle Resolution {#spiffe-bundle-resolution}

When a descriptor specifies spiffe_bundle_endpoint instead of
jwks_uri or jwks, the AS resolves verification keys via the SPIFFE
trust bundle endpoint. The AS MUST validate the bundle's freshness
and applicability to the trust domain in the descriptor's
trust_domain (or the trust domain implied by spiffe_id), and MUST
reject actor tokens whose iss does not correspond to a key in the
bundle for the relevant trust domain. The bundle endpoint format,
freshness, and rotation rules follow SPIFFE; see
{{SPIFFE-CLIENT-AUTH}} for the analogous handling in client
authentication.

### Combined SPIFFE Client Authentication and Actor Identity {#spiffe-combined}

A SPIFFE deployment that uses {{SPIFFE-CLIENT-AUTH}} for client
authentication MAY use the same JWT-SVID as the actor_token under
this profile, in the same token request:

* The SVID is presented as client_assertion with
  client_assertion_type =
  urn:ietf:params:oauth:client-assertion-type:jwt-spiffe per
  {{SPIFFE-CLIENT-AUTH}} (validated against the client's spiffe_id
  CIMD member).
* The same SVID is presented as actor_token with actor_token_type =
  urn:ietf:params:oauth:token-type:client-instance-jwt (validated
  against an instance_issuers descriptor under this profile).

The SVID's aud MUST identify the AS in a form acceptable to both
specifications (typically a single value identifying the AS
satisfies both). The two parameters carry the same JWT bytes; the
AS performs both validations against the same artifact.

This is a non-normative coordination pattern; neither
{{SPIFFE-CLIENT-AUTH}} nor this document requires it. A future
profile MAY define a single auth method that subsumes both roles.

## Refresh Tokens {#refresh}

When an access token issued under this profile is refreshed
({{RFC6749}} Section 6), the AS reuses the classification
({{access-token-classification}}) of the original grant to shape the
refreshed access token; the original classification is *inherited*
and is not re-derived from the refresh request itself.

A client MAY include the actor_token and actor_token_type
({{token-request}}) parameters on a refresh token request to supply
a fresh client instance actor token. When present:

* actor_token_type MUST be
  urn:ietf:params:oauth:token-type:client-instance-jwt;
* the actor_token MUST validate per {{as-processing}} steps 2, 4, 5,
  6, and 7, with the same client_id binding and aud rules that apply
  on initial issuance;
* the actor token's sub MAY differ from the previous instance (for
  example, when the original instance has terminated and a successor
  instance is now operating under the same client class), provided
  the new sub satisfies the descriptor's subject_syntax,
  trust_domain, and actor_profiles_supported constraints;
* the AS MUST update the refreshed access token's act (delegation)
  or sub (self-acting) and cnf to reflect the new actor token,
  preserving any nested upstream actor chain per {{ACTOR-PROFILE}};
* the AS MUST re-establish sender-constraint per
  {{sender-constrained}} against the new key.

If actor_token is absent on a refresh request, the AS MAY either
copy the previously validated actor identity into the refreshed
access token or reject the request with invalid_request and require
a fresh actor token. The choice is a matter of AS policy and SHOULD
be documented by the deployment. A client class MAY signal that a
fresh actor token is required at refresh time by registering
actor_token_required = true ({{actor-token-required}}); when so
registered, refresh requests without actor_token MUST be rejected
with invalid_request.

Refresh tokens issued under this profile SHOULD be sender-constrained
to the originating instance's cnf key, by the same mechanism used to
sender-constrain the access token ({{sender-constrained}}). A
refresh token shared across successor instances of a class is a
credential-theft amplifier: any present-or-future instance of the
class can use it to obtain access tokens by presenting its own actor
token. Where a deployment intentionally permits successor-instance
refresh (for example, agentic workloads whose runtime is recycled
but whose long-running session must continue), the deployment MUST
document the audit consequence — the resulting access token's
act.sub (delegation case) or sub (self-acting case) names the
*current* instance, not the instance that originally received the
refresh token, and audit pipelines reading these claims will see the
instance change mid-stream.

Issuing access tokens with stale instance identity across long
refresh windows is discouraged; see {{security-replay}}.

## Error Responses {#errors}

Errors are returned per {{RFC6749}} Section 5.2 and {{RFC8693}}
Section 2.2.2. The following table maps the validation failures
defined in {{as-processing}} to error codes:

| Failure | Error code |
| --- | --- |
| actor_token absent but actor_token_required is true | invalid_request |
| actor_token absent on refresh when actor_token_required is true | invalid_request |
| actor_token present but actor_token_type absent | invalid_request |
| actor_token_type present but actor_token absent | invalid_request |
| actor_token not a syntactically valid JWT | invalid_request |
| cnf possession verification fails ({{sender-constrained}}) | invalid_request |
| instance-specific binding key cannot be established ({{sender-constrained}}) | invalid_request |
| actor_token_type not understood and required for the grant | unsupported_token_type ({{RFC8693}}) |
| iss not found in instance_issuers | invalid_grant |
| signature invalid | invalid_grant |
| alg not in signing_alg_values_supported, or alg is "none" | invalid_grant |
| crit header includes unrecognized parameter | invalid_grant |
| aud, exp, iat, nbf, or jti validation fails | invalid_grant |
| client_id binding mismatch | invalid_grant |
| client_id claim absent and SPIFFE compatibility conditions not met ({{spiffe-client-id-omission}}) | invalid_grant |
| spiffe_id prefix match fails ({{instance-issuers}}) | invalid_grant |
| subject_syntax, sub_profile, or trust_domain constraint fails | invalid_grant |
| subject_syntax is "spiffe" but sub is not a valid SPIFFE ID | invalid_grant |
| max_actor_chain_depth exceeded ({{ACTOR-PROFILE}}) | invalid_request |
| actor_token carries an act claim ({{ACTOR-PROFILE}}) | invalid_grant |
| classification ambiguous ({{access-token-classification}}) | invalid_grant |

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
  from instance_issuers, replaces or removes trust_domain, reduces
  actor_profiles_supported, or rotates jwks at the issuer level. The
  AS's response is governed by {{trust-lifecycle}}: subsequent uses
  of access tokens whose act references the withdrawn scope are
  treated as no longer endorsed.

Refresh windows are a particular concern: an access token refreshed
without a new actor token may carry stale instance identity long after
the original instance has terminated. ASes SHOULD prefer requiring a
fresh actor token on refresh ({{refresh}}), or set short refresh
intervals when instance identity is present.

## Replay {#security-replay}

Actor tokens MUST include jti, exp, and iat ({{claims}}). After the
AS has identified the issuer and validated the actor token signature,
it MUST reject a token whose (iss, jti) pair has already been seen
within the token's validity window. The AS MUST retain replay-cache
entries at least until the token's exp time, plus any allowed clock
skew. Issuers SHOULD use short lifetimes (five minutes or less) both
to limit replay exposure and because client instances often have
lifetimes of seconds to minutes.

When refreshing access tokens ({{refresh}}), AS implementations
SHOULD prefer requiring a fresh actor token rather than perpetuating
stale instance identity, especially across long refresh windows.

The replay surface depends on whether the actor token carries cnf
({{claims}}) and whether the AS verifies possession at presentation
({{sender-constrained}}). When cnf is present and verified, the
actor token is non-bearer at presentation: an attacker with only the
JWT cannot use it without also possessing the cnf private key. When
cnf is absent, an attacker who captures a live actor token within
its exp window can present it once before the jti cache rejects
replays (and not at all against a different AS thanks to aud
binding). For the auth-via-actor-token mode in particular
({{auth-via-actor-token}}), where the actor token is the only client
credential, ASes SHOULD reject requests whose actor token lacks cnf;
classes deploying this mode SHOULD ensure their instance issuers
populate cnf.

## Audience and Confused Deputy

The aud claim binds the actor token to a specific AS, preventing one
AS from replaying it against another ({{RFC7523}} Section 3). The
client_id claim, which this document treats as a binding (not as
actor identity), prevents an actor token issued for one client class
from being presented under a different client class's authentication.

## Defense in Depth for the client_instance_actor_token Authentication Method {#security-auth-via-actor-token}

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

## Mode-Switch Between Delegation and Self-Acting {#security-mode-switch}

Whether an issued access token represents delegation or self-acting
({{access-token-classification}}) determines whether the instance is
exposed to resource servers as act or as sub. An adversary that can
influence classification could escalate privileges, for example by
inducing the AS to drop a sub belonging to a user and re-anchor the
token on the instance's sub. The classification rule in
{{access-token-classification}} is determined by the grant type, not
by comparison of attacker-influenceable subject strings; ASes MUST
NOT employ heuristic or fuzzy matching of assertion contents to
override the table. In particular, ASes MUST NOT normalize either
side of any comparison they perform on subject identifiers (no
Unicode normalization, no case folding, no percent-decoding beyond
what {{RFC7519}} requires for JSON parsing). When classification is
ambiguous (for example, custom grants not listed in the table), the
AS MUST refuse rather than guess.

## Binding {#security-binding}

Without sender-constraint, an act claim is an *assertion* about who
acted, not a *binding* enforced at the resource server: any party in
possession of the access token can present it as the named actor.
For this reason {{sender-constrained}} requires sender-constrained
access tokens whenever act is populated under this profile and
forbids bearer issuance.

This document does not specify a single proof-of-possession
mechanism. DPoP {{RFC9449}} and Mutual-TLS-bound access tokens
{{RFC8705}} are the primary examples in current OAuth practice;
other mechanisms may be defined elsewhere. Where the actor token
itself carries cnf, {{sender-constrained}} requires the AS to
propagate cnf to the access token's top-level cnf and to verify
possession at the token endpoint; per {{ACTOR-PROFILE}}, the top-
level cnf is the binding the resource server validates against. The
same value is also propagated into the act object
({{access-token-delegation}}) as actor context for audit and
correlation; per {{ACTOR-PROFILE}}, confirmation members inside an
act object do not have standardized proof-of-possession semantics
and are not the primary binding the RS verifies.

## Delegation Control

Unbounded delegation chains permit privilege amplification across
boundaries. Client classes SHOULD set max_actor_chain_depth and AS
implementations SHOULD enforce their own ceiling. {{ACTOR-PROFILE}}
recommends supporting at least depth 4 for cross-domain interop;
deployments imposing lower ceilings should weigh interoperability
against the privilege-amplification surface they are willing to
allow.

## Privacy

A client instance actor token reveals fine-grained workload identity
to the AS and, after issuance, to resource servers via the act claim
(delegation case) or the access token's top-level sub (self-acting
case). Exposing per-instance identity to resource servers is the
deliberate purpose of this profile (it is what enables
instance-level audit, authorization, and binding downstream), but
it has privacy and operational consequences:

* Resource servers gain visibility into the deploying organization's
  internal workload structure, including (depending on sub) cluster
  names, namespaces, function instance IDs, or session identifiers.
  Resource server operators SHOULD treat this information with the
  same care as any other identity attribute received from an AS, and
  SHOULD NOT log or propagate it more broadly than necessary.
* Naming conventions in sub may inadvertently encode sensitive
  details. Issuers and client classes SHOULD avoid encoding
  identifiers of human users, secret material, or internal
  infrastructure topology in sub, and SHOULD prefer opaque or
  hierarchical identifiers (e.g., a SPIFFE path) whose minimum
  granularity matches the auditing need.

The error response guidance in {{errors}} extends to logs and audit
trails: actor token contents SHOULD be logged at a level commensurate
with the sensitivity of the workload identity they convey.

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

IANA is requested to register the following parameters in the "OAuth
Authorization Server Metadata" registry established by {{RFC8414}}.
The Change Controller for each entry is IETF.

### actor_token_types_supported

Metadata Name:
: actor_token_types_supported

Metadata Description:
: JSON array of actor_token_type values supported at the token
  endpoint.

Specification Document(s):
: {{as-metadata}} of this document

### subject_syntaxes_supported

Metadata Name:
: subject_syntaxes_supported

Metadata Description:
: JSON array of subject_syntax values understood by the AS when
  validating client instance actor tokens.

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

## Why reuse actor_token in the self-acting case? {#rationale-self-acting}
{:numbered="false"}

In the self-acting case ({{access-token-self-acting}}) the issued
access token's principal is the instance itself, not a separate
party. RFC 8693's "actor" framing literally describes the actor as
the party acting on behalf of the subject; with no other subject
present, the framing is technically a stretch.

Three considerations led to reuse rather than introducing a
parallel "subject_assertion" parameter:

1. *One artifact, one validator.* The JWT a workload identity
   provider issues to a runtime is the same JWT regardless of
   whether the runtime then asks the AS for a user-delegated token
   or a client_credentials token. Validation rules ({{claims}},
   {{as-processing}}) are also identical. A second parameter would
   double the wire surface without changing the validation.

2. *Classification belongs to the grant.* Whether the issued access
   token represents delegation or self-acting is determined by the
   grant ({{access-token-classification}}), not by the actor token.
   The same actor token can correctly produce either shape depending
   on the grant it accompanies.

3. *Deployment fit.* Workload identity systems already issue exactly
   this artifact for both purposes. Requiring deployments to re-mint
   the same JWT under a different parameter name to satisfy an
   academic distinction would not improve security.

The cost is that {{RFC8693}}'s "actor" terminology must be read with
this profile's classification rules in mind. Implementations and
specification readers should treat actor_token in this profile as
"validated instance identity assertion," with the understanding that
its placement in the issued access token (act vs. sub) is governed by
{{access-token-classification}}.

## Why a token_endpoint_auth_method rather than a client_assertion_type? {#rationale-auth-method}
{:numbered="false"}

{{SPIFFE-CLIENT-AUTH}} models its workload-identity-as-client-auth
mechanism as a client_assertion_type. The natural question is why
{{auth-via-actor-token}} does not.

The two cases differ in what the JWT names. A SPIFFE JWT-SVID
presented as a client_assertion under {{SPIFFE-CLIENT-AUTH}} names
*the client* (its sub is the spiffe_id of the workload acting as
the client). The CIMD listing of spiffe_id, including the permitted
/* prefix wildcard, turns the SVID into a credential for the client.
There is no separate notion of "instance" on the wire.

A client instance actor token under this profile names *the
instance*: its sub is the instance identifier and its client_id
claim names the class. The same JWT is required to do double duty
only when the client class chooses
token_endpoint_auth_method = client_instance_actor_token; in every
other auth method, a separate client credential authenticates the
class and the actor token names the instance.

Modeling the dual-use case as a client_assertion_type would have
required either (a) inventing a second token type identical to
client-instance-jwt to be the assertion, doubling the wire surface,
or (b) overloading client_assertion_type with the actor-token URN,
which conflicts with that URN's role as actor_token_type. Modeling
it as a token_endpoint_auth_method captures what is actually
happening, namely that the AS authenticates the client class
implicitly from its CIMD endorsement of the actor token's issuer,
while keeping client_assertion and actor_token semantically
distinct.

actor_token_required is intentionally redundant with this auth
method ({{actor-token-required}}). It exists for client classes that
use a separate client authentication method (such as
private_key_jwt) but still want every issued access token bound to
an instance.

# SPIFFE Deployment Recipe {#appendix-spiffe-recipe}
{:numbered="false"}

This appendix walks through an end-to-end SPIFFE deployment
combining {{SPIFFE-CLIENT-AUTH}} for client authentication and this
profile for instance identity, using the same JWT-SVID for both. The
recipe is non-normative.

## Setup {#appendix-spiffe-setup}
{:numbered="false"}

The OAuth client class is identified by a CIMD URL,
https://app.example.com/agent. The class is deployed across SPIFFE
workloads under the trust domain example.com, with all instances
under the path prefix /agent.

The class's CIMD document declares both client authentication
(SPIFFE-CLIENT-AUTH) and instance trust (this profile). Both point
at the same SPIFFE bundle endpoint:

~~~ json
{
  "client_id": "https://app.example.com/agent",
  "spiffe_id": "spiffe://example.com/agent/*",
  "spiffe_bundle_endpoint":
      "https://spiffe.example.com/bundle",
  "token_endpoint_auth_method":
      "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
  "instance_issuers": [
    {
      "issuer": "spiffe://example.com",
      "spiffe_bundle_endpoint":
          "https://spiffe.example.com/bundle",
      "subject_syntax": "spiffe",
      "trust_domain": "example.com",
      "spiffe_id": "spiffe://example.com/agent/*",
      "actor_profiles_supported": ["client_instance"]
    }
  ]
}
~~~

The top-level spiffe_id (under SPIFFE-CLIENT-AUTH) and the
descriptor's spiffe_id (under this profile) intentionally match: any
workload under spiffe://example.com/agent/* counts both as the
client and as a permitted instance.

## Workload Token Request {#appendix-spiffe-request}
{:numbered="false"}

A workload spiffe://example.com/agent/inst-01 obtains a JWT-SVID
from the SPIFFE Workload API with audience set to the AS
(https://as.example.com), then issues a client_credentials request
that uses the SVID as both client_assertion and actor_token:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=repo.write
&client_id=https%3A%2F%2Fapp.example.com%2Fagent
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe
&client_assertion=eyJhbGciOiJFUzI1NiIs...
&actor_token=eyJhbGciOiJFUzI1NiIs...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

client_assertion and actor_token carry the byte-identical JWT-SVID:

~~~ json
{
  "iss": "spiffe://example.com",
  "sub": "spiffe://example.com/agent/inst-01",
  "aud": "https://as.example.com",
  "iat": 1770000000,
  "exp": 1770000300,
  "jti": "1a2b3c4d-5e6f"
}
~~~

The SVID has no client_id claim and is not re-minted; SPIFFE
compatibility ({{spiffe-client-id-omission}}) handles the binding
structurally via the descriptor's spiffe_id.

## AS Processing {#appendix-spiffe-as}
{:numbered="false"}

The AS:

1. Resolves the CIMD document at https://app.example.com/agent.
2. Authenticates the client per {{SPIFFE-CLIENT-AUTH}}: the
   client_assertion's sub (spiffe://example.com/agent/inst-01) is
   matched against the top-level spiffe_id (spiffe://example.com/agent/*),
   and the SVID signature is verified against the SPIFFE bundle.
3. Validates the actor_token under this profile: matches the
   descriptor (issuer = spiffe://example.com), verifies the
   signature against the same SPIFFE bundle, validates JWT claims,
   confirms the sub falls under the descriptor's spiffe_id, and
   accepts the absence of a client_id claim per
   {{spiffe-client-id-omission}}.
4. Classifies as self-acting (client_credentials grant).
5. Issues a sender-constrained access token. The cnf is established
   per the deployment's binding mechanism (typically the SVID's key
   for DPoP, or the X.509-SVID's certificate for mTLS).

## Issued Access Token {#appendix-spiffe-access-token}
{:numbered="false"}

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://api.example.com",
  "sub": "spiffe://example.com/agent/inst-01",
  "sub_profile": "client_instance",
  "client_id": "https://app.example.com/agent",
  "scope": "repo.write",
  "iat": 1770000005,
  "exp": 1770000305,
  "cnf": { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

The access token's client_id is the client class (the CIMD URL),
sub is the SPIFFE ID of the specific instance, and cnf binds the
token to the instance's key. No re-minting was required at any
point in the workload's flow.

# Acknowledgments
{:numbered="false"}

The author thanks participants in the OAuth Working Group for
discussions on client instance identity, workload identity, and
actor-based delegation that informed this document.
