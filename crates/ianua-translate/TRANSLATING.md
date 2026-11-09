# Translating messages

`catalog.json` is the maintained translation inventory. Add or correct text in
each message's `translations` object. Keep its English source, identity,
interpolation grammar, placeholders and source locations unchanged. An absent
translation remains `null`. Supplied translations still need native review and
are not enabled in the running backend.

Run `ianua-translate check` after editing, then `write-fluent` to regenerate
`crates/ianua-infra/locales/`. Never edit the generated Fluent files or
template copies; `check-fluent` refuses them. When source coverage changes, run
`collect` to refresh it while retaining translations and message keys for
unchanged sources and archiving removed messages. A message's `key` may be
renamed by hand to a clearer name, as long as it stays `<topic>-<words>` in
lowercase and unique.

Keep the inventory limited to response text, mail/pages and published event
descriptions, including helper fragments used to form those messages. Internal
diagnostics, storage labels and serialized protocol data do not need translations.
The collector filters these sources on every refresh. When adding an indirect
response helper, trace its public caller and extend the collector's scope and
regression coverage so recollection keeps its text.

For bulk input, `import` and `revise` accept tables from an explicitly selected
temporary directory. `import` fills empty translations and refuses conflicts;
`revise` applies intentional corrections. Once the imported catalog has been
verified, discard the temporary tables. Keep no second maintained copy in the
repository.

Translate the meaning in Ianua's source, rather than an isolated dictionary
entry. Keep format fields, entity names supplied as parameters, protocol values
and executable template syntax unchanged.

## Terminology

| Source term | Meaning in Ianua | Ukrainian | German | French |
| --- | --- | --- | --- | --- |
| topic | A publish/subscribe destination for messages | топік | Topic | topic de messagerie |
| access request | A person's request for permission, awaiting a decision | запит на доступ | Zugriffsanfrage | demande d’accès |
| consumer | A non-human caller, such as an integration or background service | сервісний клієнт | technischer Client | client technique |
| credential | Authentication material, not necessarily a username | облікові дані | Zugangsdaten | données d’authentification |
| support impersonation | Authorized support acting as the user | сеанс підтримки від імені користувача | Support-Sitzung im Namen des Benutzers | session d’assistance au nom de l’utilisateur |
| passkey | A WebAuthn sign-in credential | ключ доступу | Passkey | clé d’accès |
| tenant | The organization's isolated workspace | робочий простір | Mandant | espace de travail |
| organization | The organization containing workspaces | організація | Organisation | organisation |
| agent | A software agent acting through delegated authority | агент | Agent | agent |
| delegation | Authority granted to an agent, with its own scope and lifetime | делегування повноважень | Delegation | délégation |
| data clearance | Permission to receive data up to a sensitivity level | допуск до даних | Datenfreigabe | habilitation aux données |
| authentication assurance | How strongly a sign-in establishes the caller's identity | рівень надійності автентифікації | Authentifizierungsniveau | niveau de garantie d’authentification |

| Source term | Georgian | Spanish | Simplified Chinese | Japanese |
| --- | --- | --- | --- | --- |
| topic | შეტყობინებების თემა | tema de mensajes | 消息主题 | トピック |
| access request | წვდომის მოთხოვნა | solicitud de acceso | 访问权限申请 | アクセス権限の申請 |
| consumer | სერვისული კლიენტი | cliente de servicio | 服务客户端 | サービスクライアント |
| credential | ავთენტიფიკაციის მონაცემები | credencial | 凭据 | 認証情報 |
| support impersonation | მომხმარებლის სახელით მხარდაჭერის სესია | sesión de soporte en nombre del usuario | 支持人员代用户操作的会话 | サポート担当者による代理操作セッション |
| passkey | წვდომის გასაღები | clave de acceso | 通行密钥 | パスキー |
| tenant | ტენანტი | espacio de trabajo | 租户 | テナント |
| organization | ორგანიზაცია | organización | 组织 | 組織 |
| agent | აგენტი | agente | 智能体 | エージェント |
| delegation | უფლებამოსილების დელეგირება | delegación | 委托 | 委任 |
| data clearance | მონაცემებზე დაშვება | habilitación de datos | 数据安全许可 | データへのアクセス資格 |
| authentication assurance | ავთენტიფიკაციის სანდოობის დონე | nivel de garantía de autenticación | 认证保证级别 | 認証保証レベル |

Use short, natural UI wording where a complete sentence is unnecessary. For
example, `Запит на доступ не знайдено` identifies what is missing directly.
`Не знайдено запиту на доступ` is grammatical, but a different sentence order.
Neither wording should be used to infer how an access check itself behaved.

Keep state changes distinct: revocation withdraws authority, suspension pauses
use, and expiry ends a validity period. A sent request does not prove receipt or
completion. A requested cancellation does not prove the run has stopped. Review
verdicts are advisory; the first approval of a two-person action is not final
approval. An agent's data mark records the sensitivity of data it has read;
clearance describes what it may receive.

A finished sign-in has completed all required authentication steps. In session
handoff and factor changes, a finished session means a session whose sign-in is
complete and whose validity is checked separately. Preserve this distinction
from a session that has ended. Registering a passkey does not establish who
holds the account or complete a sign-in by itself.

The Chinese term `智能体` names an agent using delegated authority. The connector's
network agent is a different component and uses `代理` in its enrollment messages.

A linked-identity group is one person's linked accounts across an organization's
workspaces. It is not an authorization group. Linking requires the person's own
completed sign-in to each account and a shared verified email address. Preserve
the distinction between a completed sign-in and an expired session when wording
account switching. A held erasure request is paused by a legal hold; releasing
the hold does not mean the data has already been deleted.

An organization's SAML sign-in requests are sent unsigned; the provider's signed
response is a separate message and still requires verification. A payment lifts
only a suspension for nonpayment. A suspension imposed by an operator remains
until the platform lifts it.

Domain verification proves control of a name. Certificate validity and the
certificate's source are separate: a tenant renews certificates it uploaded,
while ACME renews certificates obtained through ACME. A domain handover offer
that expired is different from one already accepted. A tenant clone copies
configuration, never people, sessions, signing keys or secrets. Sorting by an
attribute that holds a text list is different from sorting the list's items.

Validation fragments retain the current source inputs. Count messages use
parenthesized unit labels to avoid choosing an inflected unit from an English
singular/plural helper. The Fluent migration must replace these assembled
fragments with complete messages that select plurals for each language.
When an English helper prevents reliable translation, replace the source
assembly with a complete message before drafting it. The five stranded-attribute
refusals now carry named values and a separate affected-person count, avoiding
English pronouns and singular/plural helpers. All five have drafts in every
language; their nine former fragments are archived.
Protocol headers, PEM boundary markers, parameter names, enum values and
literal filter syntax are not translated. Parser details supplied through
`{e}` also need public error mappings before runtime localization is complete.

In OAuth responses, a device approval is the person's decision. Collecting it
is the device receiving that decision and obtaining tokens, a separate step.
A machine client acts as itself, while a person's token acts for that person.
Keep the token's holder distinct from its intended audience and from an actor
named in a token exchange. A refresh or exchange may narrow scopes, never widen
them. A rotated refresh token was used; a revoked token had its authority
withdrawn. Preserve protocol names such as `openid`, `DPoP`, `request_uri` and
`id_token_hint`.

For federation, a link connects a provider's subject to a local account. A
subject is scoped to its provider and is distinct from an email address.
Provider confirmation of identity, mailbox verification and domain-control
proof remain separate. A group mapping withdraws only the roles and memberships
it granted itself, and only when it no longer grants them. Directory authority
over sign-in does not verify addresses. A received single-logout request is not
proof that every peer has ended its sessions. Keep `SAML`, `SCIM`, `NameID` and
`SP` unchanged when present in a source message.

A flow is an ad hoc workflow created and started immediately, with one version;
a designed workflow is reusable. Preserve requested cancellation, completed
cancellation, timeout and failure as separate outcomes. A first approval of a
two-person step does not allow execution yet. Keep routing pipeline stage names
such as `Identity` and `Policy`, and URL, CIDR and CSS examples, unchanged.

An agent's owner and an agent administrator have different authority. A root
delegation, a sub-delegation and a task token have distinct renewal and scope
rules. A token carries one delegator's authority; it does not combine different
delegators. An agent's data mark records what it has read and can be lowered
only after the agent stops. A sighting records an unregistered agent being
observed; dismissing it does not revoke access or register it as an agent.
