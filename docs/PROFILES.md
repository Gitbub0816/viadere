# Customer profiles with selective sharing

A customer can keep a profile in Viadere and decide, business by business and field by field, what each connected business may see.
Normative wire formats and threats are in [SECURITY.md §2.97](SECURITY.md); this page explains the model.

Code: `ViadereCore/Profile` (catalog, public name, access policy, DTOs, routes), `Server/.../Profile` (storage, grants, requests, reads,
category entitlements, verification), `ViadereKit/Profile` (API and view models), `App/Viadere/Features/Profile` (screens),
`ViadereBusinessSDK/Profiles.swift`.

## Public name

Every customer has a **public name**. It is **not private**: every connected business receives it, with the relationship
(`relationship.connected` webhook `data.publicName`, and `publicName` in `GET /v1/business/profiles/{subjectRef}`), next to the pairwise
`subjectRef`.

- **Default:** first name plus last initial (`John D.`), derived from the profile's first and last name, else from the name entered at
  registration. A device-first account that never entered a name has **no** public name until it sets one (`publicName` is absent).
- **Custom:** the customer may choose another name. It must pass the display-text rules (`DisplayTextSanitizer`: no control, invisible or
  reordering characters, at most 32 characters), must not mention Viadere (homoglyph-, width- and case-insensitive), must not use official
  words (support, admin, official, verified, security, staff, team, ...) and must not look like contact data (an e-mail, a link, 5+ digits,
  a card-shaped number). `PublicName.validate` is the shared rule; the app shows a live preview.
- Stored sealed (`consumer_profiles.public_name`), erased with the account.

## Catalog (version 1)

`ProfileCatalog` is the closed, versioned list of fields. A key that is not in it is refused everywhere (customer writes, business requests,
grants). Keys are `category.name`. Derived fields are computed and read-only.

| Category | Fields | Justification to be allowed |
|---|---|---|
| `contact` | `email`, `phone` (E.164), `mailing_address`, `service_address` (up to 3, labelled) | review only |
| `personal` | `given_name`, `family_name` (legal name), `preferred_name`, `preferred_language` (BCP 47), `pronouns` | review only |
| `birthdate` | `date`; derived `age_over_18`, `age_over_21` (preferred: a business asking for an age check never sees the date) | written + heightened-review reference |
| `travel` | `frequent_flyer` (per airline code), `known_traveler_number`, `seat_preference`, `meal_preference` (standard, vegetarian, vegan, no preference) | written |
| `memberships` | `loyalty_number` (per program, up to 20) | review only |
| `vehicle` | `make`, `model`, `year`, `plate` | written |
| `home` | `property_type`, `access_notes` (200 characters) | written |
| `work` | `employer`, `title` | written |
| `verified` | derived `identity`, `legal_name`, `age_over_18`, `age_over_21` (from an ID check) | written + heightened-review reference |

Each field has a type, length limits, a sensitivity class (`standard`, `elevated`, `high`) and, for multi-entry fields, an entry label.
Values are normalized (whitespace collapsed, e-mail lower-cased, phone in E.164, identifiers upper-cased).

### Never collected

There is no field, and so no way to store or request: health, medical, allergy or disability data (healthcare is banned platform-wide),
government ID numbers (SSN, passport or driver's licence numbers), payment card or bank numbers, biometric data, religion, sexual
orientation, political views, precise live location. Meal preference has no medical or religious options. In every free-text, name,
entry-label and address value, anything that looks like a card number (13 to 19 digits passing Luhn) or a run of 9 or more digits (bank
account, SSN `ddd-dd-dddd`) is refused; identifier fields refuse the card shape. A test checks the catalog for banned terms, so a future
field cannot slip a banned category in.

Residual: a 9-digit government number typed into a membership or known-traveler field cannot be told apart from a membership number, and
free text (access notes) can still carry something a person chooses to type. The known traveler number is itself a government-issued
program number the product owner chose to support (open decision, below).

## Access: three gates

A business sees a field only when **all three** hold, checked when it asks and again **at every read**:

1. **Category entitlement (like an Apple entitlement).** Viadere allowed the field's category to the business. **No category is allowed by
   default.** During onboarding (or later), the business picks categories in the console (Organization > Customer profile access) and, for
   categories marked "written", explains why. That only records a request (`profile_category_requests`). A Viadere operator reviews each
   request with a fresh passkey and approves or denies it, and may allow fewer than asked. Approval is an `EntitlementService` grant
   (`business_entitlements.kind = profile_category`): justification required, operator recorded, audited, revocable; `verified` and
   `birthdate` also need the heightened-review reference (AGE-007). An operator can only decide a category the business asked for. A
   business cannot grant itself anything, and an operator revocation takes effect on the next call.
2. **Customer grant.** The customer granted that field to that business: from a request (field by field, partial approval is normal,
   nothing preselected) or from "What this business can see". Grants are recorded with timestamps and a disclosure receipt the customer can
   see; revoking stops reads immediately and sends `profile.access_revoked` (keys only).
3. **Environment.** Live keys read only real customers; test keys only sandbox customers (a sandbox request is answered at once with
   simulated values). Anything else is a plain `404`.

The business API needs scope `profiles:read` (an elevated scope: a Security Admin or Owner issues it). Requests and reads are rate-limited,
and every read is audited with the field keys returned, never values.

## Verified profile

The customer may verify their profile with the **existing Verify methods** (Apple Wallet ID via mdoc, or a Didit document + liveness +
face-match check), behind the same `VERIFY_ENABLED` gate. They choose which facts to keep:

- `identity`: a valid ID was presented;
- `legal_name`: the first and last name on the profile match the ID (compared in memory, case- and accent-insensitive; only "matches" is kept);
- `age_over_18`, `age_over_21`: from the ID's age statements or birth date (conservative day, as Verify).

Only those booleans are stored, with provenance (method, time, assurance, policy version). Never a document number, image, the ID's name or
birth date. A fact is kept only if the method can establish it (a selfie age estimate keeps nothing). Editing the profile name forgets
`legal_name`. The Verified badge shows while `identity` is kept. Verified facts reach a business only through a grant of the `verified.*`
field and the `verified` category entitlement, and carry their provenance in the read. Didit sessions are purged after every outcome, with
the same never-give-up backoff as Verify.

## Storage, export, deletion

- Values are sealed with the row-bound field cipher (`profile_values.value#{rowId}`); operators have no reader and there is no support
  tooling that shows values.
- The data export (`ConsumerExports.document`) has a `profile` section: values, public name, verified facts, grants, receipts, requests.
- Disconnecting ends every grant of that business (and its open requests) and tells it which keys it lost. Account deletion deletes values,
  the custom public name, verified facts, requests and finished verification attempts, and ends every grant (SECURITY.md §2.20).

## Open owner decisions

- A device-first account without any name has no public name. Alternative: a neutral placeholder.
- Known traveler numbers are collected as requested, though they are government-issued program numbers.
- Which categories need a written justification (current: everything except contact, personal and memberships).
- Retention of grant rows and receipts after account deletion (kept without values, like consent history; no business can read them).
