---
title: "OAuth 2.0 Actor Token Grant Extension and Client Instance Assertion Profile"
abbrev: "oauth-actor-token-grant-extension"
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
  RFC7662:
  RFC7800:
  RFC8414:
  RFC8693:
  RFC8705:
  RFC8725:
  RFC9068:
  RFC9449:
  CIMD: I-D.ietf-oauth-client-id-metadata-document
  ACTOR-PROFILE: I-D.mcguinness-oauth-actor-profile
  ENTITY-PROFILES: I-D.mora-oauth-entity-profiles

informative:
  RFC7009:
  RFC9101:
  RFC9126:
  RFC8707:
  SPIFFE-CLIENT-AUTH: I-D.ietf-oauth-spiffe-client-auth
  WIMSE-ARCH: I-D.ietf-wimse-arch
  WIMSE-CREDS: I-D.ietf-wimse-workload-creds
  WIMSE-WPT: I-D.ietf-wimse-wpt
  SPIFFE:
    title: "SPIFFE: Secure Production Identity Framework For Everyone"
    target: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
    author:
      org: SPIFFE
    date: 2024

--- abstract

This specification defines two related OAuth 2.0 extensions. First, it
permits the `actor_token` and `actor_token_type` parameters defined by
OAuth 2.0 Token Exchange (RFC 8693) to be used with selected token
endpoint grant types other than token exchange. Second, it defines a
profile for representing client instance identity using that extension.

The client instance profile does not introduce a new `client_instance`
identifier in protocol messages. Instead, it defines client metadata
parameters (applicable to clients identified by a Client ID Metadata
Document (CIMD) or registered via OAuth Dynamic Client Registration
(RFC 7591)) that let a `client_id` identify a logical client class
whose concrete runtime instances are authenticated by one or more
trusted instance issuers (for example, workload identity systems).

This document registers a new `actor_token_type`,
`urn:ietf:params:oauth:token-type:client-instance-jwt`, that carries
the instance identity as a signed JWT. The Authorization Server
validates the instance assertion and represents the instance either as
an `act` claim, when another principal is present (e.g., a user
delegating to the instance), or as the access token's `sub`, when the
instance itself is the principal (e.g., a client credentials grant).
The issued access token is sender-constrained to a key the instance
possesses.


--- middle

# Introduction

OAuth 2.0 {{RFC6749}} defines `client_id` as the identifier of a client.
In modern deployments such as agentic workloads, autoscaled services,
and ephemeral function executions, a single logical client routinely
corresponds to many concrete runtime instances that come and go on a
short timescale. Resource servers and authorization servers
increasingly need to know not only *which* client made a request but
*which instance* of that client made it. Instances may be acting on a
user's behalf or as the principal themselves; this profile covers
both.

OAuth 2.0 Token Exchange {{RFC8693}} defines the `actor_token` and
`actor_token_type` token request parameters and the `act` claim for
representing an actor in an issued token. The OAuth Actor Profile
{{ACTOR-PROFILE}} further constrains the `act` claim and registers
actor-related claims, but explicitly leaves out a token request
parameter for proving an actor in flows other than token exchange.

This document defines two related specifications, each
independently useful:

**An actor token grant extension.** It permits the
`actor_token` and `actor_token_type` parameters from {{RFC8693}} on
token endpoint grants other than token-exchange (specifically:
`authorization_code`, `client_credentials`, `refresh_token`, and
the JWT bearer grant {{RFC7523}}). The extension is independent of
any specific `actor_token_type`: it provides the wire mechanism on
which other profiles can build their own actor token types for
non-instance use cases (for example, AI agents acting on behalf of
a user, or services invoked under a delegation grant). See
{{grant-extension}}.

**An actor token type for client instance identity.** Building on
the actor token grant extension, this document:

* Treats the OAuth `client_id` as identifying a client *class*, and
  defines client metadata describing the *instance issuers* trusted
  to assert that a particular runtime is an instance of that class.
  The metadata applies whether the client is identified by a Client
  ID Metadata Document {{CIMD}} or registered via {{RFC7591}}; see
  {{registration-models}}.
* Registers a new `actor_token_type`,
  `urn:ietf:params:oauth:token-type:client-instance-jwt`, that
  carries the instance identity as a JWT {{RFC7519}} signed by an
  instance issuer published in the client's metadata.
* Requires issued access tokens to be sender-constrained to a key
  the instance possesses, and specifies how the instance
  assertion's `cnf` claim drives that binding.
* Registers `client_instance_jwt` as a `token_endpoint_auth_method`
  value, allowing deployments without an online class-controlled
  credential to authenticate the client via the instance assertion
  alone.
* Defines first-class support for SPIFFE workload identity,
  including direct presentation of JWT-SVIDs as `actor_token`.
* Defines authorization server metadata so that clients can
  discover support.

What this document does *not* do:

* It does not introduce a `client_instance` request parameter.
* It does not change the syntax or processing of the `act` claim
  beyond what {{ACTOR-PROFILE}} already defines.
* It does not define authorization endpoint interactions for
  conveying actor identity; like {{ACTOR-PROFILE}}, this is left for
  future work.

# Relationship to Other Specifications {#relationships}

## Relationship to RFC 8693 {#relationship-rfc8693}

{{RFC8693}} defines `actor_token` and `actor_token_type` only on
the token-exchange grant. This document permits these parameters on
additional grant types ({{grant-extension}}) and registers a new
`actor_token_type` for asserting client instance identity
({{client-instance-jwt}}); the two contributions are separable.
For the `client-instance-jwt` token type, delegation requests
represent the instance in `act` ({{access-token-delegation}}) and
self-acting requests (notably `client_credentials`) represent it
in top-level `sub` ({{access-token-self-acting}}); {{RFC8693}}'s
"actor" framing strictly addresses only the delegation case but
this profile reuses the `actor_token` wire artifact for both, with
classification determined by the grant rather than the assertion
(see {{rationale-self-acting}}). Use on a token-exchange request
remains fully governed by {{RFC8693}}.

## Relationship to OAuth Actor Profile {#relationship-actor-profile}

{{ACTOR-PROFILE}} defines the structure of the `act` claim, the
`sub_profile` claim, and nested actor representation. This document does
not redefine those constructs. It defines (a) how a client instance
proves itself at the token endpoint and (b) how the AS represents the
validated assertion in issued access tokens, either in `act`
(delegation) or top-level `sub` (self-acting). Implementations of this
document MUST also implement {{ACTOR-PROFILE}}.

## Relationship to SPIFFE Client Authentication {#relationship-spiffe-client-auth}

{{SPIFFE-CLIENT-AUTH}} (an OAuth Working Group document) defines how
a SPIFFE workload authenticates *as the OAuth client itself*, using a
JWT-SVID or X.509-SVID in place of a client secret. It registers the
`client_assertion_type`
`urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` and adds CIMD
metadata (`spiffe_id`, `spiffe_bundle_endpoint`) for resolving the
client's SPIFFE trust bundle. Notably, its `spiffe_id` field permits a
trailing /* wildcard, enabling one OAuth client to be authenticated
by any SPIFFE workload whose ID matches the prefix.

This document operates at a different layer. Its scope is *actor /
instance identity*, not client authentication. The two specifications
operate on different OAuth parameters and trust sources:

| Layer | SPIFFE Client Auth | This document |
| --- | --- | --- |
| What is authenticated | The OAuth client | An actor (instance) acting under an OAuth client |
| Token request parameter | `client_assertion` / `client_assertion_type` | `actor_token` / `actor_token_type` |
| Trust source | SPIFFE bundle endpoint and `spiffe_id` (CIMD) | `instance_issuers` (CIMD) |
| Where the SPIFFE ID surfaces | Validated against `spiffe_id`; not propagated | Surfaced in `act.sub` or top-level `sub` of issued access tokens |

The two specifications are orthogonal and MAY be combined.
{{SPIFFE-CLIENT-AUTH}} answers "may this workload act as this
client?" (a yes/no prefix match against `spiffe_id`); this profile
answers "which specific instance is acting?" (a named, bindable
identity surfaced in `act.sub` or `sub`). A common combined pattern
uses {{SPIFFE-CLIENT-AUTH}} with a wildcard `spiffe_id` for client
authentication and this profile to surface the specific instance
and bind the access token to it. Where {{SPIFFE-CLIENT-AUTH}}
alone suffices (no need to name instances downstream), this
profile is not needed.

This document does not require SPIFFE. Instance issuers may issue
non-SPIFFE JWT instance assertions (any `subject_syntax` other than
"spiffe"), and the client class itself may authenticate via
`private_key_jwt`, {{SPIFFE-CLIENT-AUTH}}, or any other registered
method.

For SPIFFE deployments, this profile defines first-class support to
enable presenting JWT-SVIDs from the SPIFFE Workload API directly as
`actor_token` without re-minting; the descriptor format and
processing rules are in {{instance-issuers}} and
{{spiffe-compatibility}}. A deployment combining
{{SPIFFE-CLIENT-AUTH}} with this profile MAY present the same SVID
as both `client_assertion` and `actor_token` in a single request
({{spiffe-combined}}); an end-to-end recipe is in
{{appendix-spiffe-recipe}}.

## Relationship to WIMSE Workload Credentials {#relationship-wimse}

The IETF Workload Identity in Multi System Environments (WIMSE)
working group is defining specifications for workload identity,
including a Workload Identity Token {{WIMSE-CREDS}} (a JWT credential
asserting a workload's identity) and the broader WIMSE architecture
{{WIMSE-ARCH}}. WIMSE work is in progress; the descriptions below
reflect drafts current at the time of writing and may shift as that
work progresses.

This profile and WIMSE address adjacent layers:

* **WIMSE workload identity credential**: a general-purpose
  workload identity assertion designed for any HTTP endpoint, not
  specifically for OAuth.
* **This profile's Client Instance Assertion**: the OAuth-aware
  projection of the same workload identity model, carrying the
  OAuth-specific bindings (`client_id` for class membership, `aud`
  identifying the AS) needed to be presented as `actor_token` at
  the OAuth token endpoint.

A WIMSE workload identity credential alone cannot be presented as
`actor_token` under this profile because it lacks the OAuth-specific
claims. Deployments that already hold one (or a SPIFFE JWT-SVID, a
Kubernetes projected service-account token, or other workload
credential) SHOULD use the OAuth-aware adapter pattern
({{issuer-obligations}}) to mint a Client Instance Assertion carrying
the underlying credential's identity together with the required
OAuth claims. From the AS's perspective, the adapter is the
instance issuer.

The WIMSE Workload Proof Token (WPT) {{WIMSE-WPT}} is a workload-to-
workload HTTP signing mechanism (analogous to {{RFC9449}} DPoP for
workloads). WPT operates at a different layer than this profile and
does not interact with the OAuth token endpoint; sender-constraint
of access tokens issued under this profile remains DPoP- or mTLS-
based per {{sender-constrained}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the following terms:

Client Class:
: The logical OAuth client identified by a `client_id` (a CIMD URL or
  a registered `client_id` under {{RFC7591}}; see
  {{registration-models}}). The client class is the issuer (in the
  OAuth metadata sense) that publishes the set of instance issuers
  permitted to authenticate its runtime instances.

Client Instance:
: A concrete runtime of a client class, for example a particular
  process, container, function invocation, or session.

Instance Issuer:
: An authority trusted by the client class to authenticate client
  instances and issue instance assertions on their behalf. Examples include
  workload identity providers (e.g., a SPIFFE control plane
  {{SPIFFE}}) and platform-managed identity services.

Client Instance Assertion:
: A JWT issued by an instance issuer asserting the identity of a
  client instance, presented as the `actor_token` in a token request.
  This document distinguishes "`actor_token`" (the RFC 8693 request
  parameter, always typeset in backticks) from "Client Instance
  Assertion" or "instance assertion" in prose (the JWT artifact
  defined by this profile, which is what the `actor_token` parameter
  carries when its `actor_token_type` is
  `urn:ietf:params:oauth:token-type:client-instance-jwt`).

Actor Token Grant Extension:
: The wire-level extension defined in {{grant-extension}} permitting
  `actor_token` and `actor_token_type` ({{RFC8693}}) on the grant
  types listed in {{permitted-grants}}. This document's
  `client-instance-jwt` actor token type builds on the extension;
  other profiles may define their own actor token types under it.

Delegation case:
: A token request whose grant produces a principal distinct from the
  instance presenting the `actor_token` (for example, a user under
  authorization_code or jwt-bearer). The issued access token's `sub`
  is the principal and the instance appears in `act` per
  {{access-token-delegation}}.

Self-acting case:
: A token request whose grant produces no principal distinct from
  the instance (notably `client_credentials`). The issued access
  token's `sub` is the instance and `act` is omitted per
  {{access-token-self-acting}}.

# Actor Token Grant Extension {#grant-extension}

This section defines a grant extension for carrying actor tokens at
the OAuth token endpoint. It is independent of the client instance
model defined later in this document: any profile that defines an
`actor_token_type`, including profiles based on {{ACTOR-PROFILE}},
can use this extension to present actor tokens on the grant types
listed below. This document's `client-instance-jwt` actor token type
({{client-instance-jwt}}) is one such profile; its token-type-specific
processing rules are defined in {{token-endpoint}}.

{{RFC8693}} provides a general-purpose way to present an actor token
to the AS, but scopes `actor_token` and `actor_token_type` to the
token-exchange grant. Actor identity is also useful when an AS issues
tokens directly from other grants: for example, an agent may redeem
an authorization code on behalf of a user, a service may request a
self-acting client credentials token, a delegated actor may refresh a
token while preserving actor identity, or a JWT bearer assertion may
identify one principal while the request still identifies the actor
performing the operation.

Defining new request parameters for each grant or actor-token profile
would fragment the token endpoint surface. This extension instead
reuses the existing `actor_token` and `actor_token_type` parameters
as a common presentation mechanism. The extension does not define a
universal actor-token validation model or access-token representation;
those remain the responsibility of each `actor_token_type` profile.

## Permitted Grant Types {#permitted-grants}

{{RFC8693}} defines `actor_token` and `actor_token_type` only on
the token-exchange grant. This document permits these parameters
on the following additional token endpoint grant types:

* `authorization_code` ({{RFC6749}})
* `client_credentials` ({{RFC6749}})
* `refresh_token` ({{RFC6749}})
* `urn:ietf:params:oauth:grant-type:jwt-bearer` ({{RFC7523}})

Token-exchange ({{RFC8693}}) is also in scope; processing under
{{RFC8693}} continues to apply unchanged for any `actor_token_type`
the AS supports.

This actor token grant extension defines only where the `actor_token` and
`actor_token_type` parameters may appear. Each `actor_token_type`
profile defines how the AS validates that actor token, how it
represents the actor in issued tokens, and how refresh-token
requests are processed for that token type.

This document does not define behavior for the implicit grant or
for the device authorization grant; specifying those is left to
future work.

## Other Actor Token Types {#other-actor-token-types}

The actor token grant extension is independent of any specific
`actor_token_type`. Any profile MAY register an `actor_token_type`
value suitable for its actor model (for example, AI agents acting on
behalf of a user, services acting under a delegation grant, or
workload identities outside the OAuth client-class model). Such
profiles can use this document's actor token grant extension to present
their actor tokens on the same set of grants without re-specifying
the grant-level actor-token presentation interaction.

This document defines and registers
`urn:ietf:params:oauth:token-type:client-instance-jwt` for asserting
client instance identity ({{client-instance-jwt}}).

At the token endpoint, the AS dispatches by `actor_token_type`:
tokens of type
`urn:ietf:params:oauth:token-type:client-instance-jwt` are
processed under this document's rules in {{token-endpoint}}, while
tokens of other registered types are processed under their own
specifications. An AS MAY support multiple `actor_token_type`
values concurrently and SHOULD advertise them via
`actor_token_types_supported` ({{as-metadata}}).

A profile defining a new `actor_token_type` for use under the
actor token grant extension MUST specify the validation, trust
resolution, access-token representation, sender-constraint,
refresh-token, and security rules for that token type. Such profiles
can reference this actor token grant extension for the wire-level
permission to carry `actor_token` and `actor_token_type` on the
grant types listed in {{permitted-grants}}.

The token endpoint processing rules for the `client-instance-jwt`
token type ({{token-endpoint}}) are written in a way that may serve
as a template for future actor token type profiles. In particular,
{{auth-time-consistency}}, {{sender-constrained}}, {{access-token}},
and {{refresh}} are largely token-type-agnostic and MAY be adopted
verbatim or adapted by other profiles; their token-type-specific
hooks (descriptor lookup, JWT claim validation, `client_id` binding)
are the parts a new profile is expected to redefine.

# Client Instance Model {#client-instance-model}

This section describes the architecture, registration models, and
trust delegation that underpin the `client-instance-jwt` profile.

## Architecture {#architecture}

Three roles cooperate to authenticate a client instance:

| Role | Responsibility |
| --- | --- |
| Client Class | Logical OAuth client identified by a `client_id` (CIMD URL or RFC 7591-registered identifier). Publishes the list of trusted instance issuers in its registered client metadata. |
| Instance Issuer | Authenticates concrete runtime instances and issues short-lived JWT instance assertions describing them. |
| Authorization Server (AS) | Authenticates the client per its registered client authentication method; resolves the client metadata (via CIMD dereference or local registration storage); verifies the instance assertion against a trusted instance issuer; mints an access token whose `act` claim or top-level `sub` represents the instance. |

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
|                    |  -> issues access token with act or sub
+--------------------+
~~~

The client class identifier (the CIMD URL or RFC 7591 `client_id`) is
the OAuth client identifier; the instance issuer identifier is the
JWT `iss` of the instance assertion. They are distinct trust anchors: the AS
authenticates the client class using its registered client
authentication method (typically `private_key_jwt` with keys from the
client's registered `jwks_uri`) and authenticates the instance
through the instance assertion.

When the client class registers `token_endpoint_auth_method`
`client_instance_jwt` ({{instance-assertion-auth}}), these two trust
anchors collapse onto a single artifact: the instance assertion
both authenticates the client class (via the CIMD endorsement of
its issuer) and identifies the instance. In that mode the request
carries no separate `client_assertion`. See {{instance-assertion-auth}}
for the token request and validation procedure.

## Client Registration Models {#registration-models}

This profile applies to OAuth clients regardless of how their
metadata is registered with the AS. Two models are supported:

Client ID Metadata Document ({{CIMD}}):
: The `client_id` is an HTTPS URL that dereferences to a metadata
  document. The AS fetches the document on demand and caches it.
  This model suits cross-organization deployments and public
  discovery: the trust relationship between class and instance
  issuers is auditable in a publicly resolvable document, and other
  parties (including resource servers, federation peers, and SPIFFE
  control planes) can read it directly.

Dynamic Client Registration ({{RFC7591}}):
: The `client_id` is opaque (or otherwise AS-assigned) and the
  metadata is registered with the AS via the dynamic registration
  endpoint or pre-registered out of band. The metadata stays
  internal to the AS. This model suits closed or managed deployments
  where the metadata should not be publicly discoverable, and
  integrates with existing RFC 7591-based registration toolchains.

The runtime behavior is identical in both models. The descriptor
format ({{instance-issuers}}), the instance-assertion auth mode
({{instance-assertion-auth}}), the SPIFFE compatibility features
({{spiffe-compatibility}}), and the AS processing rules
({{as-processing}}) all apply uniformly. The only difference is
whether the AS obtains the metadata by dereferencing the CIMD URL or
from stored registration data.

Cross-organization SPIFFE federation ({{cross-org-federation}}) is
operationally easier under CIMD because the foreign organization
can publicly publish its bundle endpoint and instance descriptors;
under RFC 7591, equivalent federation requires manual coordination
of registration between the organizations.

## Trust Delegation Model {#trust-model}

This profile defines a three-party trust delegation between the
client class, the instance issuer, and the AS. The client class
*delegates* attestation of its runtime instances to one or more
instance issuers; the AS *relies on* that delegation as expressed in
the CIMD document.

### Delegation by the Client Class {#trust-model-delegation}

By listing an instance issuer in its CIMD `instance_issuers`
({{instance-issuers}}), a client class delegates to that issuer the
authority to attest that a concrete runtime is an instance of the
client class. This delegation is bounded by the descriptor; the AS
MUST enforce, and the instance issuer MUST honor, the following
limits:

* The asserted `sub` MUST fall within `trust_domain` when present and
  MUST conform to `subject_syntax` when present.
* The asserted `sub_profile` values MUST be a subset of
  `actor_profiles_supported` when present.
* The signing `alg` MUST be among `signing_alg_values_supported` when
  present.

A client class MUST NOT list instance issuers it does not control or
trust to enforce these bounds. An instance issuer accepting delegation
MUST NOT mint instance assertions naming this `client_id` outside the
delegated scope, and MUST NOT mint instance assertions whose `client_id` names
a class for which the runtime has not been authorized as a member
({{issuer-obligations}}). This per-class minting requirement is what prevents
cross-class instance impersonation when the same instance issuer is
listed by multiple client classes (for example, in multi-tenant
SaaS).

Because the CIMD listing endorses the issuer to mint tokens naming
this `client_id`, an instance assertion signed by such an issuer is itself
attributable to the client class. A class MAY exploit this to use
the instance assertion as its client credential; see
{{instance-assertion-auth}}.

### Authority of the Authorization Server {#trust-model-as}

The AS treats the CIMD `instance_issuers` list as authoritative: it
derives its trust in an instance assertion solely from the descriptor whose
issuer member matches the instance assertion's `iss` claim. This document
does not define out-of-band or AS-side configuration of additional
instance issuers for a `client_id`; deployments requiring such
configuration MUST do so via a separate specification.

### Trust Lifecycle {#trust-lifecycle}

The trust relationship between client class and instance issuer is
mutable. When the CIMD document changes (for example, an instance
issuer is removed, its `jwks_uri` or `jwks` rotates, its `trust_domain` is
replaced, or its `actor_profiles_supported` or
`signing_alg_values_supported` narrows), the AS applies the same
freshness and re-fetch rules it applies to other CIMD-published
trust material such as `jwks_uri` (see {{CIMD}}).

For the cache window during which the AS may continue to honor a
stale descriptor, this profile imposes no additional revocation
requirement on previously issued access tokens. After the AS has
adopted the updated CIMD document, the AS SHOULD treat further use
of access tokens whose `act` claim either (a) names a removed instance
issuer, or (b) falls outside the descriptor's updated scope, as no
longer endorsed by the client class. Where the deployment supports
it, this is naturally enforced by access-token introspection and
short access-token lifetimes; AS implementations MAY additionally
revoke such tokens per {{RFC7009}}, including via the per-instance
mechanism described in {{revocation}}.

To bound the compromise recovery window, ASes issuing access tokens
under this profile SHOULD set the access token TTL no longer than
the AS's CIMD cache TTL plus the instance assertion's `exp` window.
Deployments that cannot satisfy this bound MUST support active
access-token revocation ({{revocation}}) and SHOULD support
introspection-based status checks at the resource server.

### Cross-Organization Federation {#cross-org-federation}

A client class MAY list instance issuers operated by a different
organization than the class itself. This is the cross-organization
case: the class belongs to organization A, the instance issuer is
operated by organization B, and the AS resides in either A, B, or a
third party. In SPIFFE terms, the class's trust domain may differ
from the instance's trust domain.

This document permits cross-organization descriptors with the
following constraints:

* The class MUST have a documented trust agreement with the foreign
  issuer covering at minimum: which workloads the foreign issuer is
  authorized to attest as instances of the class, the descriptor
  bounds (`trust_domain`, `spiffe_id`, `actor_profiles_supported`,
  `signing_alg_values_supported`) the issuer agrees to honor, and key-
  rotation and revocation procedures.
* The foreign issuer MUST enforce the per-class minting rule
  ({{trust-model-delegation}}).
* For SPIFFE deployments where trust domains differ, the trust
  relationship SHOULD be expressed via SPIFFE federation: the AS
  resolves the foreign trust bundle via the descriptor's
  `spiffe_bundle_endpoint` ({{instance-issuers}}), which MUST be
  operated by the foreign organization or its delegate.

Cross-domain RS processing of `act.sub` follows {{ACTOR-PROFILE}};
this profile adds no new RS-side rules for federation. Multi-AS
federation, where the same workload obtains tokens from multiple
ASes, is supported structurally: each AS resolves its own client
metadata independently, and workloads request audience-specific
JWT-SVIDs per target AS so that `aud`-based replay protection
({{security-replay}}) holds across destinations.

# Metadata and Discovery {#metadata}

This section defines client metadata used to delegate instance
attestation and authorization server metadata used by clients to
discover support.

## Client Metadata Extensions {#client-metadata}

This document defines client metadata parameters describing the
trust relationship between a client class and the instance issuers
that authenticate its runtime instances. These parameters are
registered in the OAuth Dynamic Client Registration Metadata
registry ({{iana-client-metadata}}) and apply to clients regardless
of how their metadata reaches the AS:

* For clients identified by a Client ID Metadata Document {{CIMD}},
  these parameters appear in the CIMD document and the AS resolves
  them by dereferencing the CIMD URL.
* For clients registered via OAuth Dynamic Client Registration
  {{RFC7591}} (or admin-registered with RFC 7591-shaped metadata),
  these parameters appear in the registered client metadata stored
  by the AS.

The descriptor format and processing rules are identical in both
cases. {{registration-models}} discusses the trade-offs between the
two registration models.

### instance_issuers {#instance-issuers}

OPTIONAL. A non-empty JSON array of *instance issuer descriptor*
objects. Each descriptor declares an issuer that the client class
trusts to authenticate its instances. If this parameter is absent,
or is present as an empty array, the AS MUST NOT accept instance assertions
of type `urn:ietf:params:oauth:token-type:client-instance-jwt` for this
client; the AS SHOULD treat an empty array as a metadata error and
log it for the client class operator.

An instance issuer descriptor has the following members:

issuer (REQUIRED):
: A StringOrURI {{RFC7519}} identifying the instance issuer. This
  value MUST exactly match the `iss` claim of accepted instance assertions.

A descriptor MUST contain exactly one of `jwks_uri`, `jwks`, and
`spiffe_bundle_endpoint`. If two or more are present, or all are
absent, the AS MUST reject the descriptor as invalid client metadata.

`jwks_uri`:
: An HTTPS URL of a JWK Set {{RFC7517}} containing the public keys
  used to verify signatures of instance assertions issued by this issuer.

`jwks`:
: An inline JWK Set serving the same purpose as `jwks_uri`.

`spiffe_bundle_endpoint`:
: An HTTPS URL of a SPIFFE trust bundle endpoint {{SPIFFE}} from
  which the AS resolves verification keys for instance assertions issued by
  this issuer. When present, `subject_syntax` MUST be "spiffe". The
  bundle endpoint format and resolution rules are governed by SPIFFE;
  see {{SPIFFE-CLIENT-AUTH}} for the analogous use in client
  authentication.

`signing_alg_values_supported` (OPTIONAL):
: A JSON array of JWS {{RFC7515}} `alg` values that this issuer uses to
  sign instance assertions. If present, the AS MUST reject instance assertions
  whose `alg` is not listed.

`subject_syntax` (OPTIONAL):
: A short identifier indicating the syntactic profile of the `sub`
  claim used by this issuer. Defined values are "uri" (default,
  arbitrary StringOrURI) and "spiffe" (a SPIFFE ID {{SPIFFE}}; see
  also {{SPIFFE-CLIENT-AUTH}} for the related SPIFFE-based client
  authentication profile). Other values MAY be defined by future
  specifications. An AS that does not understand the value MUST reject
  instance assertions for that descriptor with `invalid_grant`.

`trust_domain` (OPTIONAL):
: When `subject_syntax` is "spiffe", a SPIFFE trust domain that the
  `sub` claim MUST belong to. The AS MUST reject any instance assertion
  whose `sub` does not lie within this trust domain. A descriptor's
  `trust_domain` is independent of any SPIFFE trust domain associated
  with the client class itself under {{SPIFFE-CLIENT-AUTH}}; the two
  MAY differ.

`spiffe_id` (OPTIONAL):
: When `subject_syntax` is "spiffe", a SPIFFE ID that further bounds
  which workloads this issuer may attest as instances of this class.
  The value is a SPIFFE ID, optionally with a trailing "/*" wildcard,
  using the same syntax and matching rules as {{SPIFFE-CLIENT-AUTH}}.
  Without "/*", the instance assertion's `sub` MUST equal this value exactly;
  with "/*", the instance assertion's `sub` MUST be a SPIFFE ID whose prefix
  before the wildcard matches this value's prefix and whose path
  begins with the prefix's path. If both `spiffe_id` and `trust_domain`
  are present, the trust domain in `spiffe_id` MUST equal `trust_domain`.
  This member, when present, structurally binds a workload subtree
  to this client class; see {{spiffe-client-id-omission}}.

`actor_profiles_supported` (OPTIONAL):
: A JSON array of `sub_profile` values from the OAuth Entity Profiles
  registry {{ENTITY-PROFILES}} that this issuer is authorized to
  assert. If present, the AS MUST reject any instance assertion whose
  `sub_profile` contains values not listed.

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
  ]
}
~~~

## Authorization Server Metadata {#as-metadata}

This document defines the following AS metadata parameters for
{{RFC8414}} (see {{iana-as-metadata}}):

`actor_token_types_supported`:
: A JSON array of `actor_token_type` values supported by the AS at the
  token endpoint. An AS implementing this profile SHOULD publish this
  parameter and MUST include
  `urn:ietf:params:oauth:token-type:client-instance-jwt` in it. This is
  the only AS-side discovery signal for support of this profile;
  clients use it to decide whether to assemble token requests
  carrying an instance assertion.

Other values MAY appear and are processed under their own
specifications; their trust resolution is not via `instance_issuers`.

`subject_syntaxes_supported`:
: OPTIONAL. A JSON array of `subject_syntax` values
  ({{instance-issuers}}) that the AS understands when validating
  client instance assertions. If the AS publishes this array, a
  client class SHOULD only register `instance_issuers` descriptors
  whose `subject_syntax` appears in it. If absent, clients MUST assume
  the AS supports at least the default value "uri".

In addition, an AS that supports {{instance-assertion-auth}} MUST
advertise `client_instance_jwt` in
`token_endpoint_auth_methods_supported` ({{RFC8414}}).

Example AS metadata document (abridged):

~~~ json
{
  "issuer": "https://as.example.com",
  "token_endpoint": "https://as.example.com/token",
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt",
    "client_instance_jwt"
  ],
  "actor_token_types_supported": [
    "urn:ietf:params:oauth:token-type:client-instance-jwt"
  ],
  "subject_syntaxes_supported": ["uri", "spiffe"],
  "dpop_signing_alg_values_supported": ["ES256", "RS256"]
}
~~~

# Client Instance Assertion Format {#client-instance-jwt}

This section defines `client-instance-jwt` — a specific
`actor_token_type` registered under this document for asserting
client instance identity. Tokens of this type are presented under
the actor token grant extension defined in
{{grant-extension}}; their AS-side processing is
specified in {{token-endpoint}}.

A *Client Instance Assertion* is a JWT {{RFC7519}} that asserts the
identity of a client instance. It is presented as the `actor_token`
parameter ({{RFC8693}}) with `actor_token_type` set to
`urn:ietf:params:oauth:token-type:client-instance-jwt` (see
{{iana-token-type}}).

## Issuer Obligations {#issuer-obligations}

A client instance assertion serves two conceptually distinct
purposes:

1. it authenticates the *runtime instance* (workload identity); and
2. it asserts that the instance is a member of the named *client
   class*.

This document defines a single combined artifact: a JWT signed by the
instance issuer that carries both. This matches the prevailing pattern
in workload identity systems, which already issue audience-scoped,
signed assertions of runtime identity (e.g., JWT-SVIDs in {{SPIFFE}}).

The instance issuer is the trust authority for the combined assertion
and MUST, before minting an instance assertion under this profile:

* Authenticate the runtime instance (e.g., via attestation,
  platform-level identity, or possession of an instance key); and
* Verify, under issuer-side policy, that the runtime is permitted to
  claim the `client_id` named in the token. This typically means that
  the runtime is operationally part of the client class's deployment.
  An instance issuer MUST refuse to mint an instance assertion whose
  `client_id` claim names a class for which the runtime has not been
  authorized, by issuer-side policy, as a member.

How the issuer internally authenticates the runtime is out of scope.
A common deployment pattern wraps an underlying workload identity
system (Kubernetes projected service-account tokens, AWS IMDS, GCP
metadata server, Azure managed identity, a SPIFFE control plane,
etc.) in a thin OAuth-aware adapter that re-mints a Client Instance
Assertion by adding the claims required by this profile and signing
with a key registered in the issuer's descriptor. From the AS's
perspective, the adapter is the instance issuer; the adapter SHOULD
enforce the per-class authorization rule above, since underlying
workload-identity systems typically do not know about OAuth client
classes.

## JWT Claims {#claims}

The following claims are defined for client instance assertions.

`iss` (REQUIRED):
: The instance issuer identifier. MUST exactly match an issuer
  member of an `instance_issuers` descriptor in the client class CIMD
  metadata.

`sub` (REQUIRED):
: The identifier of the client instance, in the syntax declared by
  the descriptor's `subject_syntax` (default: arbitrary StringOrURI).

`aud` (REQUIRED):
: The intended audience, identifying the AS. The AS validates `aud` per
  {{RFC7523}} Section 3, accepting its own issuer identifier or
  token endpoint URL; if multiple values are present, at least one
  MUST match. Each AS SHOULD specify a single canonical `aud` format
  (typically its issuer identifier) and document it; instance issuers
  SHOULD use that canonical form. Where instance assertions are scoped per
  AS, instance issuers SHOULD mint an AS-specific instance assertion rather
  than a multi-`aud` JWT, to limit the replay surface.

`client_id` (REQUIRED unless the SPIFFE compatibility conditions of {{spiffe-client-id-omission}} are met):
: The `client_id` of the client class to which this instance belongs.
  This claim uses the JSON Web Token `client_id` claim registered by
  {{RFC9068}} Section 2.2 (which itself defers to {{RFC8693}}
  Section 4.3 for the underlying definition). Note that RFC 9068
  defines `client_id` as the OAuth client to which a JWT access token
  was issued; in this profile, the claim instead names the client
  class to which the asserted instance belongs. It binds the actor
  token to a specific client class and is not part of the actor's
  identity (per {{ACTOR-PROFILE}}, `client_id` identifies an OAuth
  client, not an actor). When present, the AS MUST reject the token
  if this value does not exactly equal the `client_id` of the
  authenticated client. When omitted under
  {{spiffe-client-id-omission}}, the binding is established
  structurally by the matched descriptor's `spiffe_id` rather than by
  a JWT claim, and a SPIFFE JWT-SVID may be presented as the
  `actor_token` directly without re-minting.

`exp` (REQUIRED):
: Expiration time. Issuers SHOULD set short lifetimes (e.g., five
  minutes or less); see {{security-replay}}.

`iat` (REQUIRED):
: Issued-at time.

`jti` (REQUIRED):
: A unique identifier used for replay prevention; see
  {{security-replay}}.

`sub_profile` (RECOMMENDED):
: One or more OAuth Entity Profile names {{ENTITY-PROFILES}}
  classifying the actor. Its syntax (a space-delimited string of
  profile names) is the one defined by {{ACTOR-PROFILE}}, which
  matches the format of the `actor_profiles_supported` descriptor
  member ({{instance-issuers}}) when each member of that array is
  treated as a single profile name. This document registers the
  value `client_instance` ({{iana-entity-profile}}). Issuers MAY
  include additional values registered with the "Actor Profile"
  usage location in the OAuth Entity Profiles registry, or
  privately defined collision-resistant values, per
  {{ACTOR-PROFILE}}.

`cnf` (RECOMMENDED):
: A confirmation claim {{RFC7800}} carrying a key bound to this
  instance. When present, the `cnf` value MUST contain exactly one
  of `jkt` (a JWK SHA-256 thumbprint per {{RFC9449}} Section 3.1) or
  `x5t#S256` (an X.509 certificate SHA-256 thumbprint per
  {{RFC8705}} Section 3); other confirmation methods registered
  under {{RFC7800}} MAY appear in addition but MUST NOT be the only
  member. The instance issuer MUST mint `cnf` from a key the named
  runtime instance demonstrably possesses (e.g., an instance-
  attested key, a per-instance workload key, or a `DPoP` public key
  presented to the issuer at attestation time). Binding rules and
  AS verification are defined in {{sender-constrained}}.

`nbf` (OPTIONAL):
: Not-before time. If present, the AS MUST reject the token before
  this time.

A client instance assertion MUST NOT contain an `act` claim. The
instance assertion is a direct identity assertion of a single party (the
instance); per {{ACTOR-PROFILE}}, an `actor_token` that carries an
`act` claim represents a delegation chain rather than a direct
identity, and the AS MUST reject such a token with `invalid_grant`
({{chain-merging}}, {{errors}}).

Additional claims MAY be present and MUST be ignored if not
understood, except where this document or {{ACTOR-PROFILE}} specifies
processing rules. Future profiles requiring AS understanding of a
new claim SHOULD use the JWS `crit` header parameter ({{RFC7515}}
Section 4.1.11) to mark it must-understand; ASes MUST reject
assertions whose `crit` header includes claims they do not implement.

## Signing and JOSE Header {#signing}

A Client Instance Assertion MUST be signed using an asymmetric JWS
{{RFC7515}} algorithm; `none` and symmetric (HMAC-based)
algorithms (`HS256`, `HS384`, `HS512`) MUST NOT be used and ASes
MUST reject assertions signed with them. The descriptor's
`signing_alg_values_supported` ({{instance-issuers}}), when present,
MUST contain only asymmetric algorithm identifiers. Implementations
MUST follow the guidance in {{RFC8725}}. For interoperability, ASes
SHOULD support at least `RS256` and `ES256`. Issuers SHOULD include a
`kid` in the JWS protected header; ASes SHOULD use `kid` for key
selection.

Issuers minting a Client Instance Assertion under this profile MUST
set the JWS `typ` (type) protected header parameter to
`client-instance+jwt` per {{RFC8725}} Section 3.11, and ASes MUST
reject such assertions whose `typ` is anything else. Explicit typing
prevents JWT confusion attacks where a token of a different type
(for example, a WIMSE workload identity credential {{WIMSE-CREDS}},
a JWT-SVID outside the SPIFFE compatibility mode, or an OAuth JWT
access token {{RFC9068}}) is mistaken for a Client Instance
Assertion.

The only exception is the SPIFFE compatibility mode in
{{spiffe-client-id-omission}}, where a raw JWT-SVID is intentionally
presented without re-minting. In that mode, the AS MUST validate the
token as a JWT-SVID according to {{SPIFFE-CLIENT-AUTH}} and
{{spiffe-bundle-resolution}}, and MUST NOT require the JWS `typ`
header to be `client-instance+jwt`.

Verification keys are obtained from the descriptor's `jwks_uri`,
`jwks`, or `spiffe_bundle_endpoint` for the issuer that matches the
`iss` claim; the AS MUST verify `alg` against
`signing_alg_values_supported` when present.

## Example Assertion {#example-assertion}

A decoded client instance assertion. The JWS protected header includes
`"typ": "client-instance+jwt"` per {{signing}}:

~~~ json
{
  "alg": "ES256",
  "kid": "4vC8agycHu6rnkEEJYAH6VuCe4JoSkPV",
  "typ": "client-instance+jwt"
}
~~~

The payload follows:

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

The `sub_profile` value "`ai_agent`" is illustrative; only
"`client_instance`" is registered by this document
({{iana-entity-profile}}). Other values require their own
registration in the OAuth Entity Profiles registry
{{ENTITY-PROFILES}}.

# Token Endpoint Processing {#token-endpoint}

This section specifies AS-side processing for token requests
carrying an `actor_token` of type
`urn:ietf:params:oauth:token-type:client-instance-jwt`. It builds on
the actor token grant extension in {{grant-extension}} by
defining the validation, authorization-time consistency, sender-
constraint, representation, refresh, client authentication, SPIFFE
compatibility, and error rules specific to the `client-instance-jwt`
token type.

This profile applies whether the AS issues JWT access tokens
({{RFC9068}}) or opaque (reference) access tokens. The
representation rules in {{access-token}} describe the *claims* an
issued access token carries (`act`, `sub`, `client_id`, `cnf`,
`sub_profile`); for JWT access tokens these appear directly in the
token payload, while for opaque access tokens they MUST be reflected
in introspection responses ({{RFC7662}}, {{interactions}}). The
sender-constraint binding in {{sender-constrained}} applies to both
formats; the binding key is verified at presentation regardless of
whether the access token is self-contained or requires introspection.

## Token Request {#token-request}

A client presents a client instance assertion at the token endpoint
by adding the `actor_token` and `actor_token_type` parameters defined by
{{RFC8693}} to a token request of any grant type listed in
{{grant-extension}}.

The following example shows a client credentials grant carrying a
client instance assertion. The client class authenticates with
`private_key_jwt`; line breaks are for readability:

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
`invalid_request` if any of the following pre-conditions hold:

* exactly one of `actor_token` and `actor_token_type` is present;
* `actor_token_type` is
  `urn:ietf:params:oauth:token-type:client-instance-jwt` but
  `actor_token` is absent;
* `actor_token_type` is
  `urn:ietf:params:oauth:token-type:client-instance-jwt` and
  `actor_token` is present but is not a syntactically valid JWT.

1. **Authenticate the client.** Authenticate the client class using
   its registered `token_endpoint_auth_method` per {{RFC6749}} and, if
   applicable, {{RFC7523}}. The CIMD `client_id` is the client class.
   When the registered method is `client_instance_jwt`, follow
   {{instance-assertion-auth}} instead of presenting a separate
   client-controlled credential.

2. **Match the token type.** If `actor_token_type` is not
   `urn:ietf:params:oauth:token-type:client-instance-jwt`, processing
   under this document does not apply. Other registered
   `actor_token_type` values MAY be processed under their own
   specifications ({{other-actor-token-types}}).

3. **Resolve client metadata.** Retrieve the client metadata for the
   authenticated `client_id`. For clients identified by {{CIMD}},
   dereference the CIMD document subject to its caching rules. For
   clients registered via {{RFC7591}} or pre-registered with the AS,
   read the stored metadata. The remaining steps operate on the
   resolved metadata regardless of source.

4. **Locate the instance issuer descriptor.** Parse the `actor_token`
   as a JWT and read its `iss` claim. Find the descriptor in
   `instance_issuers` whose issuer member exactly equals `iss`. If no
   descriptor is found, or `instance_issuers` is absent, reject the
   request with `invalid_grant` ({{errors}}).

5. **Verify the signature.** Using the descriptor's `jwks_uri`, `jwks`,
   or `spiffe_bundle_endpoint`, verify the JWS signature per
   {{RFC7515}}, {{signing}}, and, when applicable,
   {{spiffe-bundle-resolution}}.

6. **Validate JWT claims.** Validate `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
   and `jti` per {{claims}} and {{RFC7523}} Section 3. Enforce
   `subject_syntax`, `trust_domain`, `signing_alg_values_supported`, and
   `actor_profiles_supported` when present in the descriptor.

7. **Verify `client_id` binding.** If the instance assertion contains a
   `client_id` claim, it MUST exactly equal the authenticated
   `client_id`; reject with `invalid_grant` otherwise. If the
   instance assertion has no `client_id` claim, the AS MUST verify that the
   matched descriptor satisfies the SPIFFE compatibility conditions
   ({{spiffe-client-id-omission}}); if not, reject with
   `invalid_grant`. When the descriptor satisfies those conditions,
   the AS MUST verify that the `actor_token`'s `sub` falls under the
   descriptor's `spiffe_id` (with wildcard expansion if any); if not,
   reject with `invalid_grant`.

8. **Enforce delegation policy.** Apply the AS's local maximum
   delegation depth per {{ACTOR-PROFILE}}.

9. **Check authorization-time consistency.** For grants that
   originate from a prior authorization step (notably
   authorization_code), apply the rules of
   {{auth-time-consistency}}.

10. **Bind the instance.** If issuance succeeds, represent the
    instance in the access token per {{access-token}}, applying
    {{sender-constrained}} for token binding. Reflect any prior
    actor chain present in input tokens by nesting per
    {{ACTOR-PROFILE}}; chain merging rules are given in
    {{chain-merging}}.

If validation succeeds, the AS issues an access token (and optionally
a refresh token) per the requested grant.

## Client Authentication via Instance Assertion {#instance-assertion-auth}

A client class MAY register the `token_endpoint_auth_method` value
`client_instance_jwt` in its CIMD metadata to indicate that
the AS authenticates the client implicitly from a presented
instance assertion, without requiring a separate `client_assertion` or other
credential controlled by the class itself.

This mode is appropriate where the class has no online private key
that an instance can use, for example when the class identifier is
a logical CIMD URL with class-key custody centralized away from the
runtime, or when the workload identity provider trusted to attest
instances is also the only authority the class wishes to publish.
The trust chain to the class is preserved: the class's CIMD listing
of the instance issuer is itself the endorsement, and a token signed
by such an issuer naming this `client_id` is attributable to the
class.

### Request Format {#instance-assertion-auth-request}

A request using this auth method carries `client_id`, `actor_token`,
and `actor_token_type`. It MUST NOT carry `client_assertion` or any
other client authentication credential. Example, using the
`client_credentials` grant:

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

### Validation Procedure {#instance-assertion-auth-validation}

When the registered `token_endpoint_auth_method` for the `client_id` is
`client_instance_jwt`, the AS replaces step 1 of {{as-processing}}
("Authenticate the client") with the following procedure:

1. Resolve CIMD metadata for `client_id`.
2. Validate the presented `actor_token` using the token-type check,
   instance issuer descriptor lookup, signature verification, and JWT
   claim validation rules in {{as-processing}}.
3. Verify that the `actor_token`'s `client_id` claim exactly equals
   the request's `client_id` parameter.
4. Verify proof-of-possession of the `actor_token` at presentation per
   {{sender-constrained}}. In this mode the `actor_token` serves as the
   sole client authentication credential, so the bearer-replay
   considerations in {{security-replay}} apply with no fallback
   credential; ASes SHOULD reject requests in this mode whose
   `actor_token` lacks a `cnf` claim, and MUST verify possession of the
   `cnf` key when present.
5. Reject the request with `invalid_client` if any of the above fails.
6. Treat the client as authenticated. The validated `actor_token` also
   satisfies the `actor_token` requirement of this profile and is used
   for instance representation per {{access-token}}.

The `actor_token`'s `aud` claim serves both purposes (the
{{RFC7523}} client-assertion audience and this profile's actor-token
audience). A single value identifying the AS satisfies both.

The SPIFFE `client_id` claim omission mode
({{spiffe-client-id-omission}}) does not apply to
`client_instance_jwt` client authentication. Because the same JWT is
the sole client authentication credential, the assertion MUST contain
the `client_id` claim and the AS MUST verify it exactly as described
above.

After this procedure completes, processing continues with step 2 of
{{as-processing}} ("Match the token type") and onward.

## Authorization-Time Consistency {#auth-time-consistency}

When a token request is made under the authorization_code grant
({{RFC6749}} Section 4.1), the user has authorized the *client class*
identified by `client_id`, not any specific client instance. The AS
MUST ensure that the instance introduced at the token endpoint is
consistent with that authorization:

* The `client_id` authenticated at the token endpoint MUST match the
  `client_id` that received the authorization_code ({{RFC6749}}
  Section 4.1.3). Combined with the `client_id`-binding requirement
  in {{as-processing}}, this prevents an instance assertion from
  another client class from being attached to a code.
* The AS MUST NOT permit the instance identity to bypass standard
  authorization-code controls (single-use redemption, redirect URI
  matching, and any code challenge bound to the original
  authorization request).
* If the AS has any authorization-time policy that depends on the
  instance (for example, a per-instance allow-list), the AS MUST
  evaluate that policy against the instance assertion presented at /token
  and reject inconsistent requests with `invalid_grant`.

When the issued access token is to be DPoP-bound, clients SHOULD
include the `dpop_jkt` parameter ({{RFC9449}} Section 10) on the
authorization request, naming the same public key whose thumbprint
will appear in the instance assertion's `cnf.jkt` at the token endpoint.
When `dpop_jkt` is present, the AS binds the authorization code to
that key per {{RFC9449}}, and at the token endpoint MUST verify that
the DPoP proof, the authorization code's `dpop_jkt`, and the
instance assertion's `cnf.jkt` all reference the same key. This provides
cryptographic continuity from /authorize to /token bound to a
specific instance: only the instance that holds the named DPoP
private key can redeem the resulting code, even if the code is
intercepted or transferred to another runtime under the same
client class.

For Mutual-TLS-bound access tokens ({{RFC8705}}), the equivalent
continuity is established at the TLS layer: the AS sees the same
client certificate at both the authorization and token endpoints,
and the instance assertion's `cnf.x5t#S256` MUST match that certificate.

User consent under this profile applies to the client class as a
whole; consent thereby covers all instances attested by listed
instance issuers. ASes MAY display the client class identifier and
the trust domain of the instance issuer at consent time. The
key-bound continuity above adds cryptographic guarantees about
*which* instance redeems a code, but does not constitute per-instance
consent.

ASes that record consent SHOULD record the descriptor scope under
which consent was granted (in particular, the descriptor's issuer
and `trust_domain`), and MAY refuse access tokens for the same client
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
instance is represented in `act` (delegation case;
{{access-token-delegation}}) or in `sub` (self-acting case;
{{access-token-self-acting}}), the AS MUST issue a
sender-constrained access token bound to a key the instance
possesses. Established mechanisms include `DPoP` {{RFC9449}} and
Mutual-TLS-bound access tokens {{RFC8705}}.

The AS MUST NOT issue a bearer access token under this profile.
Deployments unable to sender-constrain access tokens for
operational reasons are outside the scope of this profile; they
should publish or reference a separate profile that addresses their
constraints.

If the instance assertion includes a `cnf` claim ({{claims}}), the AS MUST:

* bind the issued access token to the same key by setting the access
  token's top-level `cnf` to the instance assertion's `cnf` value;
* verify possession of the `cnf` key at the token endpoint, matching
  the confirmation method used in `cnf` per {{RFC7800}}. For `cnf.jkt`,
  the JWK thumbprint of the `DPoP` proof's public key {{RFC9449}} MUST
  equal `cnf.jkt`. For `cnf.x5t#S256`, the certificate authenticated at
  the TLS layer {{RFC8705}} MUST match `cnf.x5t#S256`. Other
  confirmation methods MUST be verified per their defining
  specifications;
* reject the request with `invalid_request` if verification fails.

This protects the instance assertion from bearer-style replay within its
validity window ({{security-replay}}); without it, the instance assertion
would be a bearer credential whose replay is bounded only by `exp`
and the `jti` cache.

The binding key MUST be specific to the validated client instance.
A credential shared by the client class as a whole, such as the
class-level mTLS certificate authenticated under {{RFC8705}}, the
class's `private_key_jwt` key, or any other class-controlled key not
provisioned per-instance, is not sufficient.

If the instance assertion does not include a `cnf` claim, the AS MUST
establish an instance-specific binding through some other means
whose key is attributable to the validated instance, for example:

* a per-instance mTLS client certificate provisioned by the instance
  issuer (or otherwise tied to instance attestation) and presented
  under {{RFC8705}}; or
* a `DPoP` key {{RFC9449}} that the AS confirms, through deployment-
  specific attestation or out-of-band binding to the instance issuer,
  represents the same runtime named by the instance assertion's `sub`.

If the AS cannot establish such an instance-specific binding, it
MUST reject the request with `invalid_request` ({{errors}}). For this
reason, instance issuers SHOULD include `cnf` in instance assertions so that
the binding key is supplied by the same authority that named the
instance.

Deployments combining class-level Mutual-TLS-bound client
authentication ({{RFC8705}}) with this profile MUST establish
instance binding through a separate, instance-specific key. The
typical configuration uses the class's mTLS certificate at the TLS
layer for client authentication and a `cnf.jkt` in the instance assertion
paired with `DPoP` {{RFC9449}} at the token endpoint for instance
binding. Per-instance mTLS certificates issued by the instance
issuer (or otherwise bound to instance attestation) are an
alternative; in that case the same TLS certificate satisfies both
class authentication and instance binding only if the AS treats it
as belonging to the instance for binding purposes.

## Access Token Representation {#access-token}

A client instance may be acting on behalf of another principal
(*delegation case*; e.g., a user authorized the request through an
authorization_code grant) or acting as itself with no other
principal involved (*self-acting case*; e.g., a
`client_credentials` grant). The AS MUST classify each request as
delegation or self-acting before populating the issued access
token's claims. In both cases the access token's `client_id`
remains the client class, the access token MUST be sender-
constrained per {{sender-constrained}}, and any upstream actor
chain MUST be preserved by nesting per {{ACTOR-PROFILE}} (merge
rules in {{chain-merging}}). The classification rule, the two
representation cases, and the chain-merging rule appear as peer
subsections below.

### Classification {#access-token-classification}

The AS classifies the request based on whether the grant produces
a principal distinct from the client instance presenting the
`actor_token`:

| Grant | Principal | Classification |
| --- | --- | --- |
| authorization_code ({{RFC6749}}) | the user who authorized the code | delegation |
| `client_credentials` ({{RFC6749}}) | none | self-acting |
| `refresh_token` ({{RFC6749}}) | inherited from the original grant | inherited |
| jwt-bearer ({{RFC7523}}) | the assertion's `sub` | delegation |
| token-exchange ({{RFC8693}}) | the `subject_token`'s subject | delegation |

The jwt-bearer and token-exchange rows always classify as delegation
under this profile. {{RFC7523}} requires a JWT-bearer assertion that
identifies a principal, and {{RFC8693}} Section 2.1 requires a
`subject_token`; in both cases another party is present and named, so
the issued access token's `sub` is that party and the actor appears
in `act`. ASes MUST NOT classify these grants as self-acting based
on heuristic matching of subject identifiers; see
{{security-mode-switch}}. This rule applies even when the
`subject_token` was itself a self-acting access token whose `sub`
named the same instance now presenting the `actor_token` (e.g., a
client-credentials token from an upstream AS exchanged at a
downstream AS): the resulting access token has `sub` and `act.sub`
naming the same instance. This is benign chain self-reference and
is not an error; the AS MUST NOT collapse the two into a self-
acting representation.

When neither delegation nor self-acting cleanly applies (for example,
custom or experimental grants), the AS MUST refuse to issue the
access token rather than guess; reject with `invalid_grant`
({{errors}}).

### Delegation Case {#access-token-delegation}

When the request is classified as delegation, the AS MUST populate
the issued access token's `act` claim per {{ACTOR-PROFILE}} from the
validated client instance assertion:

* `act.iss` = `actor_token`'s `iss`
* `act.sub` = `actor_token`'s `sub`
* `act.sub_profile` = `actor_token`'s `sub_profile` (if present);
  the value `client_instance` SHOULD be included.
* `act.cnf` = `actor_token`'s `cnf`, if present.

The access token's `sub` MUST be the principal identified by the
grant (e.g., the authenticated user). Sender-constraint binding
(top-level `cnf` and PoP verification) is governed by
{{sender-constrained}}. Note that the instance assertion's `aud`,
`client_id`, `exp`, `iat`, and `jti` are validated and consumed by
the AS but do not appear in the issued access token (`client_id`
appears at the top level as a property of the token, not as an
actor claim).

For a worked example see {{appendix-examples-auth-code}}; for a
nested actor chain (token-exchange whose `subject_token` already
carries an `act` chain), see {{appendix-examples-token-exchange}}.

### Self-Acting Case {#access-token-self-acting}

When the request is classified as self-acting, the instance is the
principal and there is no other party on whose behalf it acts. The
AS MUST populate the issued access token from the validated client
instance assertion:

* `sub` = `actor_token`'s `sub`
* `sub_profile` = `actor_token`'s `sub_profile` (if present); the
  value `client_instance` SHOULD be included
* `cnf` is set per {{sender-constrained}}
* `act` MUST be omitted, except that an upstream actor chain
  (introduced by an inner `act` in a presented `subject_token`) MUST
  be preserved.

The instance issuer's identifier (the instance assertion's `iss`) is not
represented as a claim in the self-acting access token. Trust in the
instance issuer is structural: the AS validated the instance assertion
against the descriptor in {{instance-issuers}} before issuance, and
the resource server trusts the AS. Deployments that require
in-token instance-issuer attribution for self-acting tokens may
define a separate claim in a future profile.

In the issued access token, `client_id` (the class) and `sub` (the
instance) are distinct, and `act` is absent. For a worked example
see {{appendix-examples-client-credentials}}.

### Actor Chain Merging {#chain-merging}

Per {{ACTOR-PROFILE}}, a Client Instance Assertion presented as an
`actor_token` MUST NOT itself carry an `act` claim; if it does, the AS
MUST reject the request with `invalid_grant`. A Client Instance
Assertion is a direct identity assertion of the actor, not a
delegation-chain credential.

Consequently, only two inputs can contribute actor information to
the issued token:

* the validated client instance assertion (this request's actor, the
  new outermost actor); and
* the `subject_token`'s `act` chain, if any (only applicable to a
  token-exchange ({{RFC8693}}) request, since other grants do not
  introduce a `subject_token`).

The AS MUST construct the issued access token's `act` chain by
applying the algorithm in {{ACTOR-PROFILE}} (its "Delegation Chain
Validation and Construction" section) with the validated client
instance assertion as the new outermost actor and the
`subject_token`'s preserved delegation chain (when present) nested
inside. The resulting depth MUST NOT exceed the AS's local maximum
delegation depth; otherwise the AS MUST reject the request with
`invalid_request` ({{errors}}), per {{ACTOR-PROFILE}}.

In the self-acting case ({{access-token-self-acting}}) the `act`
claim is omitted at top level. When a `subject_token` is present
(uncommon outside token-exchange, which this profile classifies as
delegation in any case), any `act` chain it carries is preserved
verbatim per {{ACTOR-PROFILE}}.

## Refresh Tokens {#refresh}

When an access token is refreshed ({{RFC6749}} Section 6), the AS
reuses the classification ({{access-token-classification}}) of the
original grant to shape the refreshed access token; the original
classification is *inherited* and is not re-derived from the refresh
request itself.

A client MAY include the `actor_token` and `actor_token_type`
({{token-request}}) parameters on a refresh token request to supply
a fresh client instance assertion. When present:

* `actor_token_type` MUST be
  `urn:ietf:params:oauth:token-type:client-instance-jwt`;
* the `actor_token` MUST validate per {{as-processing}}, including
  token-type checking, instance issuer descriptor lookup, signature
  verification, JWT claim validation, `client_id` binding, and `aud`
  validation;
* the instance assertion's `sub` MAY differ from the previous instance (for
  example, when the original instance has terminated and a successor
  instance is now operating under the same client class), provided
  the new `sub` satisfies the descriptor's `subject_syntax`,
  `trust_domain`, and `actor_profiles_supported` constraints;
* the AS MUST update the refreshed access token's `act` (delegation)
  or `sub` (self-acting) and `cnf` to reflect the new instance assertion,
  preserving any nested upstream actor chain per {{ACTOR-PROFILE}};
* the AS MUST re-establish sender-constraint per
  {{sender-constrained}} against the new key.

If `actor_token` is absent on a refresh request, the AS MAY either
copy the previously validated actor identity into the refreshed
access token or reject the request with `invalid_request` and require
a fresh instance assertion. The choice is a matter of AS policy and SHOULD
be documented by the deployment.

Refresh tokens issued under this profile SHOULD be sender-constrained
to the originating instance's `cnf` key, by the same mechanism used to
sender-constrain the access token ({{sender-constrained}}). A
refresh token shared across successor instances of a class is a
credential-theft amplifier: any present-or-future instance of the
class can use it to obtain access tokens by presenting its own
instance assertion. Where a deployment intentionally permits successor-instance
refresh (for example, agentic workloads whose runtime is recycled
but whose long-running session must continue), the deployment MUST
document the audit consequence: the resulting access token's
`act.sub` (delegation case) or `sub` (self-acting case) names the
*current* instance, not the instance that originally received the
refresh token, and audit pipelines reading these claims will see
the instance change mid-stream.

Issuing access tokens with stale instance identity across long
refresh windows is discouraged; see {{security-replay}}.

## SPIFFE Compatibility {#spiffe-compatibility}

A SPIFFE workload typically obtains a JWT-SVID from the SPIFFE
Workload API. JWT-SVIDs carry `iss` (the trust domain), `sub` (the
SPIFFE ID), `aud`, `exp`, `iat`, and a signature, but do not carry an
OAuth `client_id` claim. To allow such SVIDs to be presented as
`actor_token` without re-minting, this profile defines a SPIFFE
compatibility mode driven entirely by descriptor configuration.

When a raw JWT-SVID is presented under this compatibility mode, it is
not a reminted Client Instance Assertion and is not required to carry
the `client-instance+jwt` JWS `typ` value. The AS instead validates the
JWT-SVID using the SPIFFE trust bundle and descriptor constraints in
this section. A deployment that re-mints the SVID into a Client
Instance Assertion MUST use `typ` = `client-instance+jwt` per
{{signing}}.

### Client ID Claim Omission {#spiffe-client-id-omission}

When all of the following hold for the descriptor that matches the
`actor_token`'s `iss`:

* `subject_syntax` is "spiffe";
* a `spiffe_id` member is present ({{instance-issuers}}); and
* the `actor_token`'s `sub` satisfies the `spiffe_id` matching rule
  (exact match or prefix match including the "/*" wildcard);

the AS MUST treat the descriptor as the per-class binding even if
the `actor_token` has no `client_id` claim. In this mode:

* The AS MUST verify that the `actor_token`'s `sub` falls under the
  descriptor's `spiffe_id` (after applying the wildcard, if any).
* If the `actor_token` has a `client_id` claim, it MUST still equal the
  request's `client_id` parameter ({{as-processing}}); the
  exception narrows the *requirement* that the claim be present,
  not the *consistency* of the claim when present.
* All other JWT claims and validation rules of {{claims}} continue
  to apply unchanged.

The security rationale is that the descriptor's `spiffe_id`, signed
into the client class's CIMD document and dereferenced by the AS,
is itself the per-class binding: a workload's SPIFFE ID is bound to
a class by the class explicitly listing the prefix that contains it.
This is the same model SPIFFE-CLIENT-AUTH uses for client
authentication, applied here to actor identity.

### SPIFFE Trust Bundle Resolution {#spiffe-bundle-resolution}

When a descriptor specifies `spiffe_bundle_endpoint` instead of
`jwks_uri` or `jwks`, the AS resolves verification keys via the SPIFFE
trust bundle endpoint. The AS MUST validate the bundle's freshness
and applicability to the trust domain in the descriptor's
`trust_domain` (or the trust domain implied by `spiffe_id`), and MUST
reject instance assertions whose `iss` does not correspond to a key in the
bundle for the relevant trust domain. The bundle endpoint format,
freshness, and rotation rules follow SPIFFE; see
{{SPIFFE-CLIENT-AUTH}} for the analogous handling in client
authentication.

### Combined Authentication and Actor Identity {#spiffe-combined}

A SPIFFE deployment that uses {{SPIFFE-CLIENT-AUTH}} for client
authentication MAY use the same JWT-SVID as the `actor_token` under
this profile, in the same token request:

* The SVID is presented as `client_assertion` with
  `client_assertion_type` =
  `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` per
  {{SPIFFE-CLIENT-AUTH}} (validated against the client's `spiffe_id`
  CIMD member).
* The same SVID is presented as `actor_token` with `actor_token_type` =
  `urn:ietf:params:oauth:token-type:client-instance-jwt` (validated
  against an `instance_issuers` descriptor under this profile).

The SVID's `aud` MUST identify the AS in a form acceptable to both
specifications (typically a single value identifying the AS
satisfies both). The two parameters carry the same JWT bytes; the
AS performs both validations against the same artifact.

This is a non-normative coordination pattern; neither
{{SPIFFE-CLIENT-AUTH}} nor this document requires it. A future
profile MAY define a single auth method that subsumes both roles.

## Error Responses {#errors}

Errors are returned per {{RFC6749}} Section 5.2 and {{RFC8693}}
Section 2.2.2. The following table maps the validation failures
defined in {{as-processing}} to error codes:

| Failure | Error code |
| --- | --- |
| `actor_token` present but `actor_token_type` absent | `invalid_request` |
| `actor_token_type` present but `actor_token` absent | `invalid_request` |
| `client-instance-jwt` `actor_token` not a syntactically valid JWT | `invalid_request` |
| reminted Client Instance Assertion `typ` JOSE header is not `client-instance+jwt` ({{signing}}) | `invalid_request` |
| `cnf` possession verification fails ({{sender-constrained}}) | `invalid_request` |
| instance-specific binding key cannot be established ({{sender-constrained}}) | `invalid_request` |
| `actor_token_type` not understood and required for the grant | `unsupported_token_type` ({{RFC8693}}) |
| `iss` not found in `instance_issuers` | `invalid_grant` |
| signature invalid | `invalid_grant` |
| `alg` not in `signing_alg_values_supported`, or `alg` is "none" | `invalid_grant` |
| `crit` header includes unrecognized parameter | `invalid_grant` |
| `aud`, `exp`, `iat`, `nbf`, or `jti` validation fails | `invalid_grant` |
| `client_id` binding mismatch | `invalid_grant` |
| `client_id` claim absent and SPIFFE compatibility conditions not met ({{spiffe-client-id-omission}}) | `invalid_grant` |
| `spiffe_id` prefix match fails ({{instance-issuers}}) | `invalid_grant` |
| `subject_syntax`, `sub_profile`, or `trust_domain` constraint fails | `invalid_grant` |
| `subject_syntax` is "spiffe" but `sub` is not a valid SPIFFE ID | `invalid_grant` |
| delegation chain depth exceeds AS local maximum ({{ACTOR-PROFILE}}) | `invalid_request` |
| `actor_token` carries an `act` claim ({{ACTOR-PROFILE}}) | `invalid_grant` |
| classification ambiguous ({{access-token-classification}}) | `invalid_grant` |

The AS MAY return additional information via the error_description
parameter; deployments MUST NOT include sensitive instance details
(e.g., raw SPIFFE IDs of unrelated workloads) in error responses.

# Resource Server Processing {#rs-processing}

Resource servers consuming access tokens issued under this profile
follow the resource server processing rules defined in
{{ACTOR-PROFILE}} (its "Resource Server Processing" section) for
delegated access tokens, including actor authorization, JWT access
token validation, sender-constraint validation against the top-level
`cnf`, error responses (including the `actor_unauthorized` error code),
and introspection. This section adds only the considerations specific
to this profile.

When the access token carries an `act` claim
({{access-token-delegation}}), the resource server processes it
per {{ACTOR-PROFILE}}; this profile adds no new RS-side requirements
for the delegation case. Resource servers MAY use
`act.sub_profile` = `client_instance` as a signal that the actor is
a concrete runtime of an OAuth client class, which can inform
authorization policy. Resource servers MUST NOT rely on `act.iss`
for proof of possession; per {{ACTOR-PROFILE}}, the top-level `cnf`
is the binding for the current presenter.

Under this profile, the access token's top-level `cnf` is the
*instance's* key, not the principal's key (the principal in `sub` is
typically a user, who does not present the token). The instance,
named in `act.sub`, is the bearer; sender-constraint validation
authenticates that instance. This is a deliberate consequence of
binding the access token to the instance that holds the
authorization, not to the principal who delegated to it.

## Self-Acting Case {#rs-self-acting}

In the self-acting case ({{access-token-self-acting}}), the access
token carries no `act` claim. From the resource server's perspective,
the access token is a non-delegated token whose top-level claims have
the following semantics under this profile:

* `sub` names the *client instance* (typically a SPIFFE ID or other
  workload identifier), not a human user.
* `sub_profile` = `client_instance` signals that the subject is a runtime
  instance and resource servers SHOULD apply policy appropriate to
  workload identities (for example, scope-restricted machine-to-
  machine policies, rate limits, or workload-specific audit).
* `client_id` names the *client class* (the logical OAuth client to
  which the instance belongs), not the instance. Resource servers
  MUST NOT treat `client_id` as the actor identifier in the self-
  acting case; the actor identifier is `sub`. (When delegation is
  also present, this distinction is moot; `client_id` remains the
  class and `act.sub` names the actor.)
* `cnf` binds the token to the instance's key; PoP validation follows
  the access token's binding mechanism (`DPoP` {{RFC9449}} or
  Mutual-TLS-bound {{RFC8705}}).

Resource servers that distinguish "human-delegated" from "workload-
self-acting" requests SHOULD make the determination based on the
presence or absence of `act`, not on the format of `sub`. In both
cases the top-level `client_id` names the client class, not the
instance; when the instance is a SPIFFE workload, the SPIFFE ID is
conveyed via `act.sub` (delegation) or `sub` (self-acting), never
via `client_id`.

# Operational Considerations {#operational}

This section covers behavior that affects deployment and operation of
the protocol after tokens have been issued: revocation, interactions
with other OAuth extensions, and migration.

## Token Revocation {#revocation}

This profile supports two complementary revocation models for access
tokens issued under it. Both build on {{RFC7009}}; deployments MAY
support either, both, or neither, subject to operational constraints.

### Per-Token Revocation {#per-token-revocation}

An AS that supports {{RFC7009}} revocation MAY accept the access
token (or its associated refresh token) as the token parameter and
revoke that specific issued token. This works unchanged for tokens
issued under this profile; no profile-specific extensions to the
revocation endpoint are required.

### Per-Instance Revocation {#per-instance-revocation}

When an instance is compromised or otherwise needs to be quarantined,
a deployment may need to invalidate all access tokens whose
`act.sub` (delegation case) or `sub` (self-acting case) names that
instance, without enumerating every issued token. ASes implementing
this profile SHOULD support a per-instance revocation mode that:

* invalidates all currently-active access tokens whose `act.sub` or
  `sub` matches the specified instance identifier (and, optionally,
  whose `act.iss` or descriptor scope matches additional constraints);
* prevents issuance of new access tokens with that instance
  identifier as actor or principal until a follow-up condition is
  met (for example, expiration of an internal blocklist entry, or
  removal of the instance from the workload identity system).

The mechanism for triggering per-instance revocation is deployment-
specific and out of scope for this document; common patterns include
an administrative API on the AS, a control-plane hook from the
workload identity system that signals compromised instances, or
removal of the instance from the workload identity provider's
roster (which the AS observes via the descriptor's
`spiffe_bundle_endpoint` or `jwks_uri` rotation).

### Introspection Behavior on Revocation {#introspection-on-revocation}

When an AS supports introspection ({{RFC7662}}), introspection
responses for access tokens issued under this profile MUST honor
both per-token revocation and per-instance revocation: an
introspection response MUST return active = false for any access
token that has been revoked under either model. Introspection MUST
also honor the trust update and CIMD freshness rules in
{{trust-lifecycle}}: when the AS has adopted an updated CIMD
document that removes an instance issuer or narrows a descriptor's
scope so that an issued access token's `act` (or, for self-acting
tokens, `sub`) is no longer endorsed, introspection responses for
that access token MUST return active = false within the AS's CIMD
cache window.

### Revocation and Refresh Tokens {#revocation-refresh}

When a refresh token is sender-constrained to the originating
instance ({{refresh}}), per-instance revocation MUST also revoke
the refresh token (and prevent any further access tokens it would
mint). A deployment that intentionally permits successor-instance
refresh ({{refresh}}) MUST decide whether per-instance revocation
cascades to successors and document its choice; the safe default
is that revocation of any successor in a chain revokes the chain.

## Interactions with Other OAuth Extensions {#interactions}

This profile conveys actor identity at the token endpoint only and
does not define authorization-request extensions, so it does not
interact directly with Pushed Authorization Requests {{RFC9126}} or
JWT-Secured Authorization Requests {{RFC9101}}; the `actor_token`
and `actor_token_type` parameters are presented at /token regardless
of how the authorization step was performed.

The resource parameter {{RFC8707}} is orthogonal to actor identity:
the AS populates `act` (delegation) or `sub` (self-acting) the same
way regardless of resource. AS-side per-resource policies that depend
on the actor MUST be evaluated against the validated instance
assertion, with inconsistent requests rejected via `invalid_grant`
({{errors}}).

When an AS supports token introspection {{RFC7662}}, delegated-token
responses follow {{ACTOR-PROFILE}}; the top-level `cnf`, when present,
SHOULD be returned so introspection-based PoP has the binding key. In
the self-acting case, `sub_profile` and `cnf` SHOULD be returned
alongside the standard {{RFC7662}} response fields.

## Adoption and Migration {#adoption}

This profile is designed for incremental adoption. Existing CIMD
documents that do not declare `instance_issuers` continue to work
unchanged, and existing access tokens in circulation when a class
adds `instance_issuers` remain valid for their original lifetime.
An AS MAY implement this profile while continuing to serve clients
that don't use it: token requests are dispatched on
`actor_token_type`, with `urn:ietf:params:oauth:token-type:client-
instance-jwt` triggering this profile's processing
({{as-processing}}) and other (or absent) values processed under
their own specifications. ASes SHOULD advertise support via
`actor_token_types_supported` ({{as-metadata}}). A client class MAY
add `instance_issuers` at any time; a class that wants to mandate
instance assertions for every issued access token can register
`token_endpoint_auth_method = client_instance_jwt`
({{instance-assertion-auth}}), which intrinsically requires the
`actor_token`.

### Migration without cnf {#adoption-without-cnf}

A class MAY deploy this profile before adopting per-instance proof-
of-possession keys, but the bearer-replay protection in
{{security-replay}} requires an instance-specific binding. Until
the instance issuer can populate `cnf` on instance assertions, deployments
MUST establish an instance-specific binding through some other
means per {{sender-constrained}} (per-instance mTLS certificates
provisioned by the issuer being the most common alternative), or
the AS will reject the request. Short access-token lifetimes (e.g.,
five minutes or less) further bound exposure during this transition.

ASes and class operators SHOULD NOT enable the
`client_instance_jwt` authentication method
({{instance-assertion-auth}}) until `cnf` is present in instance assertions:
that mode has no fallback client credential, so an instance assertion
without `cnf` is fully bearer at presentation
({{security-instance-assertion-auth}}).

# Conformance {#conformance}

This document defines separable implementation capabilities. A
deployment or implementation claiming conformance MUST identify which
of the following capabilities it supports.

Actor Token Grant Extension AS:
: An AS that supports presentation of `actor_token` and
  `actor_token_type` on the grant types listed in
  {{permitted-grants}}. Such an AS MUST dispatch by
  `actor_token_type` and MUST NOT apply `client-instance-jwt` token
  validation rules to other actor token types.

Client Instance Assertion AS:
: An AS that supports
  `urn:ietf:params:oauth:token-type:client-instance-jwt`. Such an AS
  MUST implement {{as-processing}}, {{sender-constrained}},
  {{access-token}}, {{chain-merging}}, and {{errors}}. It MUST also
  implement {{ACTOR-PROFILE}}.

Client Instance Assertion Auth Method AS:
: An AS that supports the `client_instance_jwt`
  `token_endpoint_auth_method`. Such an AS MUST implement
  {{instance-assertion-auth}} in addition to the Client Instance
  Assertion AS capability.

Client Class:
: A client class using this profile MUST publish or register
  `instance_issuers` metadata as defined in {{instance-issuers}} and
  MUST ensure that each listed instance issuer is authorized to attest
  instances of the class.

Instance Issuer:
: An issuer of Client Instance Assertions MUST mint assertions
  according to {{claims}}, {{signing}}, and the delegated scope
  described in {{trust-model-delegation}}.

Resource Server:
: A resource server that consumes access tokens issued under this
  profile MUST process delegated tokens according to
  {{ACTOR-PROFILE}} and MUST apply the self-acting semantics in
  {{rs-self-acting}} when no `act` claim is present.

# Security Considerations {#security}

This document inherits the security considerations of {{RFC6749}},
{{RFC7519}}, {{RFC7523}}, {{RFC8693}}, {{RFC8725}}, {{CIMD}}, and
{{ACTOR-PROFILE}}.

## Trust Model {#security-trust-model}

The normative trust model for this profile is in {{trust-model}}.
This subsection summarizes the security implications.

A client class delegates the authentication of its instances to one
or more instance issuers. A compromised or misconfigured instance
issuer can mint instance assertions that the AS will accept as legitimate
instances of the named client class. Client classes SHOULD list only
instance issuers under their own administrative control (or
contractually equivalent), and SHOULD set `trust_domain`,
`actor_profiles_supported`, and `signing_alg_values_supported` to bound
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
: Instance issuers MUST mint short-lived instance assertions
  ({{security-replay}}). New tokens are issued continuously as
  instances start, restart, or rotate keys.

Revocation within the validity window:
: Within an instance assertion's `exp` window, the AS prevents reuse via the
  `jti` replay rule ({{security-replay}}). A specific issued access
  token, or all tokens associated with an instance, can be revoked
  only via the AS's own revocation mechanisms ({{revocation}}); this
  profile does not define a standardized revocation endpoint or
  instance revocation list format.

Trust withdrawal:
: To stop accepting instance assertions from an issuer (e.g., after a
  workload identity compromise), the client class removes the issuer
  from `instance_issuers`, replaces or removes `trust_domain`, reduces
  `actor_profiles_supported`, or rotates `jwks` at the issuer level. The
  AS's response is governed by {{trust-lifecycle}}: subsequent uses
  of access tokens whose `act` references the withdrawn scope are
  treated as no longer endorsed.

Refresh windows are a particular concern: an access token refreshed
without a new instance assertion may carry stale instance identity long after
the original instance has terminated. ASes SHOULD prefer requiring a
fresh instance assertion on refresh ({{refresh}}), or set short refresh
intervals when instance identity is present.

## Replay {#security-replay}

Actor tokens MUST include `jti`, `exp`, and `iat` ({{claims}}). After the
AS has identified the issuer and validated the instance assertion signature,
it MUST reject a token whose (`iss`, `jti`) pair has already been seen
within the token's validity window. The AS MUST retain replay-cache
entries at least until the token's `exp` time, plus any allowed clock
skew. Issuers SHOULD use short lifetimes (five minutes or less) both
to limit replay exposure and because client instances often have
lifetimes of seconds to minutes.

When refreshing access tokens ({{refresh}}), AS implementations
SHOULD prefer requiring a fresh instance assertion rather than perpetuating
stale instance identity, especially across long refresh windows.

The replay surface depends on whether the instance assertion carries `cnf`
({{claims}}) and whether the AS verifies possession at presentation
({{sender-constrained}}). When `cnf` is present and verified, the
instance assertion is non-bearer at presentation: an attacker with only the
JWT cannot use it without also possessing the `cnf` private key. When
`cnf` is absent, an attacker who captures a live instance assertion within
its `exp` window can present it once before the `jti` cache rejects
replays (and not at all against a different AS thanks to `aud`
binding). For the instance-assertion auth mode in particular
({{instance-assertion-auth}}), where the instance assertion is the only client
credential, ASes SHOULD reject requests whose instance assertion lacks `cnf`;
classes deploying this mode SHOULD ensure their instance issuers
populate `cnf`.

## Audience and Confused Deputy {#security-audience}

The `aud` claim binds the instance assertion to a specific AS, preventing one
AS from replaying it against another ({{RFC7523}} Section 3). The
`client_id` claim, which this document treats as a binding (not as
actor identity), prevents an instance assertion issued for one client class
from being presented under a different client class's authentication.

## Hardening client_instance_jwt Authentication {#security-instance-assertion-auth}

The `client_instance_jwt` authentication method
({{instance-assertion-auth}}) eliminates the requirement for the client
class to control a private key used at the token endpoint. The
trust chain to the class is preserved (the CIMD listing endorses the
instance issuer), but the AS no longer requires possession of two
independent keys to issue a token: compromise of any CIMD-listed
instance issuer is sufficient to mint tokens that authenticate as
the class.

In contrast, modes such as `private_key_jwt` require an attacker to
possess both an instance issuer's signing key (to mint the
instance assertion) and the class's private key (to assert the client) before any
token can be issued. Where the operational model permits, deployments
SHOULD prefer two-key authentication.

When `client_instance_jwt` is used, classes SHOULD constrain
each instance issuer's authority through `trust_domain`,
`actor_profiles_supported`, and `signing_alg_values_supported`, and
SHOULD list only the minimum set of `instance_issuers` necessary.

Trust withdrawal under this auth method has immediate consequences
for client authentication: removing an instance issuer from
`instance_issuers` (or narrowing its descriptor scope) immediately
invalidates client authentications that depended on that issuer's
endorsement. The AS MUST stop accepting `client_instance_jwt`
authentications via the removed or narrowed issuer within its CIMD
cache window per {{trust-lifecycle}}.

## Mode-Switch Between Delegation and Self-Acting {#security-mode-switch}

Whether an issued access token represents delegation or self-acting
({{access-token-classification}}) determines whether the instance is
exposed to resource servers as `act` or as `sub`. An adversary that can
influence classification could escalate privileges, for example by
inducing the AS to drop a `sub` belonging to a user and re-anchor the
token on the instance's `sub`. The classification rule in
{{access-token-classification}} is determined by the grant type, not
by comparison of attacker-influenceable subject strings; ASes MUST
NOT employ heuristic or fuzzy matching of assertion contents to
override the table. In particular, ASes MUST NOT normalize either
side of any comparison they perform on subject identifiers (no
Unicode normalization, no case folding, no percent-decoding beyond
what {{RFC7519}} requires for JSON parsing). When classification is
ambiguous (for example, custom grants not listed in the table), the
AS MUST refuse rather than guess.

## Sender-Constraint Requirement {#security-binding}

Without sender-constraint, an `act` claim is an assertion about who
acted, not a binding enforced at the resource server: any party in
possession of the access token can present it as the named actor.
{{sender-constrained}} therefore requires sender-constrained access
tokens and forbids bearer issuance under this profile. Per
{{ACTOR-PROFILE}}, the resource server validates proof of
possession against the access token's top-level `cnf` only;
confirmation members inside an `act` object are actor context for
audit and correlation, not a binding the RS independently verifies.

## Delegation Control {#security-delegation-control}

Unbounded delegation chains permit privilege amplification across
boundaries. AS implementations MUST enforce a local maximum
delegation depth ({{ACTOR-PROFILE}}). {{ACTOR-PROFILE}} recommends
supporting at least depth 4 for cross-domain interop; deployments
imposing lower ceilings should weigh interoperability against the
privilege-amplification surface they are willing to allow.

## Privacy {#security-privacy}

A client instance assertion reveals fine-grained workload identity
to the AS and, after issuance, to resource servers via the `act` claim
(delegation case) or the access token's top-level `sub` (self-acting
case). Exposing per-instance identity to resource servers is the
deliberate purpose of this profile (it is what enables
instance-level audit, authorization, and binding downstream), but
it has privacy and operational consequences:

* Resource servers gain visibility into the deploying organization's
  internal workload structure, including (depending on `sub`) cluster
  names, namespaces, function instance IDs, or session identifiers.
  Resource server operators SHOULD treat this information with the
  same care as any other identity attribute received from an AS, and
  SHOULD NOT log or propagate it more broadly than necessary.
* Naming conventions in `sub` may inadvertently encode sensitive
  details. Issuers and client classes SHOULD avoid encoding
  identifiers of human users, secret material, or internal
  infrastructure topology in `sub`, and SHOULD prefer opaque or
  hierarchical identifiers (e.g., a SPIFFE path) whose minimum
  granularity matches the auditing need.

The error response guidance in {{errors}} extends to logs and audit
trails: instance assertion contents SHOULD be logged at a level commensurate
with the sensitivity of the workload identity they convey.

For incident response, per-instance revocation ({{per-instance-revocation}}),
and operational audit, ASes issuing access tokens under this profile
SHOULD log at least the following at issuance time, subject to the
sensitivity guidance above:

* the authenticated `client_id` (the client class);
* the validated instance assertion's `iss` (the instance issuer) and `sub`
  (the instance identifier);
* the instance assertion's `jti` (for replay correlation);
* the `cnf` value or its thumbprint (binding the issued token to a
  specific key);
* the descriptor scope under which validation succeeded (in
  particular `trust_domain` and any matched `spiffe_id`); and
* the classification of the request (delegation or self-acting).

These fields together let operators answer "which instance, attested
by which issuer, obtained which token" without re-validating the
original assertion. They also enable the per-instance revocation
mechanism in {{per-instance-revocation}}, which inherently requires
the AS to know which active access tokens name a given instance.

# IANA Considerations {#iana}

## OAuth Token Type {#iana-token-type}

IANA is requested to register the following value in the "OAuth URI"
registry established by {{RFC6755}} (and used by {{RFC8693}} for
`actor_token_type` values):

URN:
: `urn:ietf:params:oauth:token-type:client-instance-jwt`

Common Name:
: OAuth 2.0 Client Instance Assertion

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
: `instance_issuers`

Client Metadata Description:
: Trusted issuers of client instance assertions for this client.

Specification Document(s):
: {{instance-issuers}} of this document

## OAuth Token Endpoint Authentication Method {#iana-auth-method}

IANA is requested to register the following value in the "OAuth Token
Endpoint Authentication Methods" registry established by {{RFC8414}}:

Token Endpoint Authentication Method Name:
: `client_instance_jwt`

Change Controller:
: IETF

Specification Document(s):
: {{instance-assertion-auth}} of this document

## OAuth Authorization Server Metadata {#iana-as-metadata}

IANA is requested to register the following parameters in the "OAuth
Authorization Server Metadata" registry established by {{RFC8414}}.
The Change Controller for each entry is IETF.

### actor_token_types_supported

Metadata Name:
: `actor_token_types_supported`

Metadata Description:
: JSON array of `actor_token_type` values supported at the token
  endpoint.

Specification Document(s):
: {{as-metadata}} of this document

### subject_syntaxes_supported

Metadata Name:
: `subject_syntaxes_supported`

Metadata Description:
: JSON array of `subject_syntax` values understood by the AS when
  validating client instance assertions.

Specification Document(s):
: {{as-metadata}} of this document

## Media Type {#iana-media-type}

IANA is requested to register the following media type in the
"Media Types" registry:

Type name:
: application

Subtype name:
: client-instance+jwt

Required parameters:
: N/A

Optional parameters:
: N/A

Encoding considerations:
: binary; A Client Instance Assertion is a JWT; JWT values are
  encoded as a series of base64url-encoded values separated by
  period characters.

Security considerations:
: See {{security}} of this document.

Interoperability considerations:
: N/A

Published specification:
: This document.

Applications that use this media type:
: OAuth 2.0 authorization servers and clients implementing this
  profile.

Fragment identifier considerations:
: N/A

Additional information:
: Magic number(s): N/A; File extension(s): N/A; Macintosh file type
  code(s): N/A

Person & email address to contact for further information:
: Karl McGuinness <public@karlmcguinness.com>

Intended usage:
: COMMON

Restrictions on usage:
: none

Author:
: Karl McGuinness

Change controller:
: IETF

This media type, when used as a value of the `typ` JWS protected
header parameter ({{RFC7515}} Section 4.1.9), MUST be
`client-instance+jwt` (per {{RFC8725}} Section 3.11; the
`application/` prefix is omitted).

## OAuth Entity Profile {#iana-entity-profile}

IANA is requested to register the following value in the "OAuth
Entity Profiles" registry established by {{ENTITY-PROFILES}}. This
registration is contingent on the establishment of that registry.

Profile Name:
: `client_instance`

Profile Description:
: A concrete runtime instance of an OAuth client class identified by a
  `client_id`.

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

A new top-level `client_instance` parameter would have to flow through
the authorization request, the token request, introspection, the
access token, and several existing extensions. Each is a separate
specification touch-point and a deployment cliff. Reusing `actor_token`
keeps the protocol surface unchanged.

## Why extend actor_token to non-token-exchange grants?
{:numbered="false"}

{{RFC8693}} already defines request parameters for presenting an
actor token and identifying its token type. Those parameters are not
specific to token exchange as a protocol concept; token exchange is
only the grant on which {{RFC8693}} defines them. Other grants also
need a way to identify the actor performing the request. Reusing the
existing parameter machinery avoids grant-specific actor parameters
and gives actor-token profiles a single token endpoint presentation
model.

Client instance identity is one motivating example: the instance acts
on behalf of the subject (the human user or service principal) under
the authority of the client class. Other actor delegation use cases
share the same presentation need. The only normative move in
{{grant-extension}} is permitting `actor_token` and
`actor_token_type` on additional grants; validation and access-token
representation remain token-type-specific.

The actor token grant extension is intentionally separable from the specific
`actor_token_type` defined here. By isolating the actor token grant
extension ({{grant-extension}}), this document provides
future profiles a defined wire mechanism to build on, rather than
each profile re-litigating the question of whether `actor_token` may
appear on `authorization_code` or `client_credentials`. See
{{other-actor-token-types}}.

## Why CIMD as the trust anchor for instance issuers?
{:numbered="false"}

CIMD already establishes a publication mechanism for client metadata
keyed to a stable, dereferenceable client identifier. Listing
instance issuers in the same document keeps the trust relationship
between client class and instance issuer auditable in one place and
reuses CIMD's caching and key-rotation rules.

## Why a dedicated actor_token_type URN?
{:numbered="false"}

The general-purpose JWT token type does not signal that the AS should look
up trust via CIMD's `instance_issuers`, nor that `client_id` binding
applies. A dedicated URN lets ASes route processing unambiguously
and lets clients advertise support via `actor_token_types_supported`.

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
   or a `client_credentials` token. Validation rules ({{claims}},
   {{as-processing}}) are also identical. A second parameter would
   double the wire surface without changing the validation.

2. *Classification belongs to the grant.* Whether the issued access
   token represents delegation or self-acting is determined by the
   grant ({{access-token-classification}}), not by the instance assertion.
   The same instance assertion can correctly produce either shape depending
   on the grant it accompanies.

3. *Deployment fit.* Workload identity systems already issue exactly
   this artifact for both purposes. Requiring deployments to re-mint
   the same JWT under a different parameter name to satisfy an
   academic distinction would not improve security.

The cost is that {{RFC8693}}'s "actor" terminology must be read with
this profile's classification rules in mind. Implementations and
specification readers should treat `actor_token` in this profile as
"validated instance identity assertion," with the understanding that
its placement in the issued access token (`act` vs. `sub`) is governed by
{{access-token-classification}}.

## Why a token_endpoint_auth_method rather than a client_assertion_type? {#rationale-auth-method}
{:numbered="false"}

{{SPIFFE-CLIENT-AUTH}} models its workload-identity-as-client-auth
mechanism as a `client_assertion_type`. The natural question is why
{{instance-assertion-auth}} does not.

The two cases differ in what the JWT names. A SPIFFE JWT-SVID
presented as a `client_assertion` under {{SPIFFE-CLIENT-AUTH}} names
*the client* (its `sub` is the `spiffe_id` of the workload acting as
the client). The CIMD listing of `spiffe_id`, including the permitted
/* prefix wildcard, turns the SVID into a credential for the client.
There is no separate notion of "instance" on the wire.

A client instance assertion under this profile names *the
instance*: its `sub` is the instance identifier and its `client_id`
claim names the class. The same JWT is required to do double duty
only when the client class chooses
`token_endpoint_auth_method` = `client_instance_jwt`; in every
other auth method, a separate client credential authenticates the
class and the instance assertion names the instance.

Modeling the dual-use case as a `client_assertion_type` would have
required either (a) inventing a second token type identical to
client-instance-jwt to be the assertion, doubling the wire surface,
or (b) overloading `client_assertion_type` with the actor-token URN,
which conflicts with that URN's role as `actor_token_type`. Modeling
it as a `token_endpoint_auth_method` captures what is actually
happening, namely that the AS authenticates the client class
implicitly from its CIMD endorsement of the instance assertion's issuer,
while keeping `client_assertion` and `actor_token` semantically
distinct.

# SPIFFE Deployment Recipe {#appendix-spiffe-recipe}
{:numbered="false"}

This appendix walks through an end-to-end SPIFFE deployment
combining {{SPIFFE-CLIENT-AUTH}} for client authentication and this
profile for instance identity, using the same JWT-SVID for both. The
recipe is non-normative.

The full sequence:

~~~ ascii-art
Workload      SPIFFE           AS              RS
              Workload API
   |              |              |               |
   | FetchJWTSVID |              |               |
   |   aud=AS     |              |               |
   |------------->|              |               |
   |              |              |               |
   |   JWT-SVID   |              |               |
   |<-------------|              |               |
   |                             |               |
   |   POST /token                               |
   |   grant_type=client_credentials             |
   |   client_id=<class CIMD URL>                |
   |   client_assertion=<SVID>                   |
   |   actor_token=<SVID>   (same JWT bytes)     |
   |   DPoP: <proof>                             |
   |---------------------------->|               |
   |                             |               |
   |        [resolves CIMD for class]            |
   |        [fetches SPIFFE trust bundle]        |
   |        [validates SVID signature]           |
   |        [SPIFFE-CLIENT-AUTH: sub matches     |
   |         top-level spiffe_id /*]             |
   |        [this profile: sub matches           |
   |         descriptor's spiffe_id /*; no       |
   |         client_id claim required]           |
   |        [validates DPoP proof key]           |
   |        [issues sender-constrained access    |
   |         token]                              |
   |                             |               |
   |   access_token (DPoP-bound, sub = SPIFFE ID)|
   |<----------------------------|               |
   |                                             |
   |   GET /resource                             |
   |   Authorization: DPoP <access_token>        |
   |   DPoP: <proof>                             |
   |-------------------------------------------->|
   |                                             |
   |              [validates token signature]    |
   |              [validates DPoP against cnf]   |
   |              [enforces sub/act per          |
   |               ACTOR-PROFILE and             |
   |               this profile §RS]             |
   |                                             |
   |              200 OK                         |
   |<--------------------------------------------|
~~~

The same JWT-SVID flows from the SPIFFE Workload API through the AS
to the resource server: no re-minting, no OAuth-aware adapter, one
artifact serving both client authentication and instance identity.

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

The top-level `spiffe_id` (under SPIFFE-CLIENT-AUTH) and the
descriptor's `spiffe_id` (under this profile) intentionally match: any
workload under spiffe://example.com/agent/* counts both as the
client and as a permitted instance.

## Workload Token Request {#appendix-spiffe-request}
{:numbered="false"}

A workload spiffe://example.com/agent/inst-01 obtains a JWT-SVID
from the SPIFFE Workload API with audience set to the AS
(https://as.example.com), then issues a `client_credentials` request
that uses the SVID as both `client_assertion` and `actor_token`:

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

`client_assertion` and `actor_token` carry the byte-identical JWT-SVID:

~~~ json
{
  "alg": "ES256",
  "kid": "4vC8agycHu6rnkEEJYAH6VuCe4JoSkPV",
  "typ": "JWT"
}
~~~

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

The SVID has no `client_id` claim and is not re-minted; SPIFFE
compatibility ({{spiffe-client-id-omission}}) handles the binding
structurally via the descriptor's `spiffe_id`.

## AS Processing {#appendix-spiffe-as}
{:numbered="false"}

The AS:

1. Resolves the CIMD document at https://app.example.com/agent.
2. Authenticates the client per {{SPIFFE-CLIENT-AUTH}}: the
   `client_assertion`'s `sub` (spiffe://example.com/agent/inst-01) is
   matched against the top-level `spiffe_id` (spiffe://example.com/agent/*),
   and the SVID signature is verified against the SPIFFE bundle.
3. Validates the `actor_token` under this profile: matches the
   descriptor (issuer = spiffe://example.com), verifies the
   signature against the same SPIFFE bundle, validates JWT claims,
   confirms the `sub` falls under the descriptor's `spiffe_id`, and
   accepts the absence of a `client_id` claim per
   {{spiffe-client-id-omission}}.
4. Classifies as self-acting (`client_credentials` grant).
5. Issues a sender-constrained access token. The `cnf` is established
   per the deployment's binding mechanism (typically the SVID's key
   for `DPoP`, or the X.509-SVID's certificate for mTLS).

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

The access token's `client_id` is the client class (the CIMD URL),
`sub` is the SPIFFE ID of the specific instance, and `cnf` binds the
token to the instance's key. No re-minting was required at any
point in the workload's flow.

# Worked Examples {#appendix-examples}
{:numbered="false"}

This appendix gives end-to-end worked examples for each grant type
that interacts with this profile. Examples are non-normative and
omit unrelated headers or grant-specific details that do not affect
actor processing.

The examples share a common deployment:

* Client class: https://app.example.com/agent
* CIMD document declares one instance issuer
  https://workload.app.example.com (`subject_syntax` "uri",
  `signing_alg_values_supported` containing `ES256`, and
  `actor_profiles_supported` containing `client_instance`).
* AS: https://as.example.com.
* Resource server: https://api.example.com.
* All access tokens are `DPoP`-bound; the instance assertion's `cnf` carries
  the instance's `DPoP` key thumbprint.

## Authorization Code with User Delegation {#appendix-examples-auth-code}
{:numbered="false"}

Alice authorizes the agent (client class) at the AS through a
standard authorization_code flow. The agent runs as instance
inst-01, which presents an instance assertion at the token endpoint to
identify itself.

Authorization request from the agent (abridged). `dpop_jkt` carries
the thumbprint of inst-01's DPoP key (matching the instance assertion's
`cnf.jkt`) to establish key-bound continuity per
{{auth-time-consistency}}:

~~~ http-message
GET /authorize?response_type=code
  &client_id=https%3A%2F%2Fapp.example.com%2Fagent
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb
  &scope=repo.write
  &state=xyz
  &code_challenge=...
  &code_challenge_method=S256
  &dpop_jkt=0ZcOCORZNYy...iguA4I HTTP/1.1
Host: as.example.com
~~~

The AS authenticates Alice, displays consent for the client class
(per {{auth-time-consistency}} consent applies to the class as a
whole, not per-instance), binds the authorization code to the
`dpop_jkt` value per {{RFC9449}}, and redirects with an
authorization_code.

Token request from instance inst-01:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof bound to inst-01's key>

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb
&client_id=https%3A%2F%2Fapp.example.com%2Fagent
&code_verifier=...
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs... (private_key_jwt)
&actor_token=eyJhbGciOiJFUzI1NiIs...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

Decoded `actor_token`:

~~~ json
{
  "iss":         "https://workload.app.example.com",
  "sub":         "https://workload.app.example.com/inst-01",
  "aud":         "https://as.example.com",
  "client_id":   "https://app.example.com/agent",
  "sub_profile": "client_instance",
  "iat":         1770000000,
  "exp":         1770000300,
  "jti":         "ac-1a2b3c",
  "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
}
~~~

AS validation:

1. Authenticates the client (`private_key_jwt`).
2. Recognizes `actor_token_type`.
3. Resolves CIMD for the agent.
4. Locates the descriptor by matching `iss`.
5. Verifies signature via descriptor's `jwks_uri`.
6. Validates JWT claims.
7. Verifies `actor_token`.`client_id` == request `client_id`.
8. Applies AS-local maximum delegation depth.
9. {{auth-time-consistency}}: the request's `client_id` matches the
   `client_id` that received the code, and the DPoP proof's
   thumbprint matches both the code's `dpop_jkt` and the actor
   token's `cnf.jkt`.
10. Classifies as delegation; issues sender-constrained access token.

Issued access token:

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://app.example.com/agent",
  "scope":     "repo.write",
  "iat":       1770000005,
  "exp":       1770003605,
  "cnf":       { "jkt": "0ZcOCORZNYy...iguA4I" },
  "act": {
    "iss":         "https://workload.app.example.com",
    "sub":         "https://workload.app.example.com/inst-01",
    "sub_profile": "client_instance",
    "cnf":         { "jkt": "0ZcOCORZNYy...iguA4I" }
  }
}
~~~

The RS authorizes the request based on (alice, inst-01) per
{{rs-processing}}.

## Client Credentials (Self-Acting) {#appendix-examples-client-credentials}
{:numbered="false"}

A workload makes a `client_credentials` request with no human user
involved.

Token request:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof bound to inst-02's key>

grant_type=client_credentials
&scope=repo.read
&client_id=https%3A%2F%2Fapp.example.com%2Fagent
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs...
&actor_token=eyJhbGciOiJFUzI1NiIs...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

Issued access token (self-acting; no user, instance is the
principal):

~~~ json
{
  "iss":         "https://as.example.com",
  "aud":         "https://api.example.com",
  "sub":         "https://workload.app.example.com/inst-02",
  "sub_profile": "client_instance",
  "client_id":   "https://app.example.com/agent",
  "scope":       "repo.read",
  "iat":         1770000005,
  "exp":         1770003605,
  "cnf":         { "jkt": "PqR...XyZ" }
}
~~~

The RS treats `sub` as the workload identity (not a human user) per
{{rs-self-acting}}.

## Token Exchange with Prior Delegation Chain {#appendix-examples-token-exchange}
{:numbered="false"}

A user-delegated access token issued by an upstream service is
exchanged at the AS for a downstream-resource-scoped token. The
agent's instance presents an instance assertion; the inbound `subject_token`
already carries an `act` chain from a previous hop.

Inbound `subject_token` (decoded; issued earlier by an upstream
service named "service-router"):

~~~ json
{
  "iss":       "https://upstream.example.com",
  "aud":       "https://app.example.com/agent",
  "sub":       "user:alice@example.com",
  "scope":     "repo.write",
  "act": {
    "iss":         "https://upstream.example.com",
    "sub":         "service-router",
    "sub_profile": "service"
  }
}
~~~

Token request:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof bound to inst-03's key>

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&audience=https%3A%2F%2Fapi.example.com
&subject_token=eyJhbGciOiJFUzI1NiIs...
&subject_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&client_id=https%3A%2F%2Fapp.example.com%2Fagent
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs...
&actor_token=eyJhbGciOiJFUzI1NiIs...
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

The `actor_token` is the agent instance inst-03, with no `act` of its
own (per {{ACTOR-PROFILE}}, `actor_token` MUST NOT carry `act`).

Chain construction per {{chain-merging}}:

* Outermost: the validated `actor_token` (inst-03).
* Inner: the `subject_token`'s `act` chain, preserved (service-router).

Issued access token:

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://app.example.com/agent",
  "scope":     "repo.write",
  "iat":       1770000010,
  "exp":       1770003610,
  "cnf":       { "jkt": "AbC...123" },
  "act": {
    "iss":         "https://workload.app.example.com",
    "sub":         "https://workload.app.example.com/inst-03",
    "sub_profile": "client_instance",
    "cnf":         { "jkt": "AbC...123" },
    "act": {
      "iss":         "https://upstream.example.com",
      "sub":         "service-router",
      "sub_profile": "service"
    }
  }
}
~~~

Resulting chain depth is 2, well within typical AS-local maximums.

## Refresh Token with Instance Succession {#appendix-examples-refresh}
{:numbered="false"}

The original instance inst-01 obtained an access token and refresh
token (from the authorization_code example above), then terminated.
A successor instance inst-04 obtains the refresh token (via a
deployment-specific handoff such as a shared persistent state) and
presents a fresh instance assertion to refresh.

Refresh request:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof bound to inst-04's key>

grant_type=refresh_token
&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=https%3A%2F%2Fapp.example.com%2Fagent
&client_assertion_type=
  urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs...
&actor_token=eyJhbGciOiJFUzI1NiIs... (inst-04's actor token)
&actor_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aclient-instance-jwt
~~~

Per {{refresh}}, classification is inherited from the original grant
(authorization_code → delegation). The actor identity changes from
inst-01 to inst-04.

Issued access token:

~~~ json
{
  "iss":       "https://as.example.com",
  "aud":       "https://api.example.com",
  "sub":       "user:alice@example.com",
  "client_id": "https://app.example.com/agent",
  "scope":     "repo.write",
  "iat":       1770003610,
  "exp":       1770007210,
  "cnf":       { "jkt": "DeF...456" },
  "act": {
    "iss":         "https://workload.app.example.com",
    "sub":         "https://workload.app.example.com/inst-04",
    "sub_profile": "client_instance",
    "cnf":         { "jkt": "DeF...456" }
  }
}
~~~

The `act.sub` has switched from inst-01 to inst-04. Audit pipelines
reading `act.sub` will see this change; the deployment SHOULD have
documented this behavior per {{refresh}}, and SHOULD have considered
whether the refresh token should have been sender-constrained to
prevent transfer between instances.

# Acknowledgments
{:numbered="false"}

The author thanks participants in the OAuth Working Group for
discussions on client instance identity, workload identity, and
actor-based delegation that informed this document.
