---
name: translate-messages
description: Give a new refusal, event description or mail text its key and its translations in every language, and regenerate the language files. Use after adding or changing English text the API, mail or event feed shows, e.g. "/translate-messages".
---

# Translate messages

Every message a person can read has a stable key and a translation in each
language: Ukrainian (`uk`), German (`de`), French (`fr`), Georgian (`ka`),
Spanish (`es`), Simplified Chinese (`zh-Hans`) and Japanese (`ja`). English is
the source. `crates/ianua-translate/README.md` is the full guide.

The source of truth is `crates/ianua-translate/catalog.json`. The files under
`crates/ianua-infra/locales/` are generated. Never edit them.

## In the code

A refusal carries a key:

```rust
AppError::Conflict(message!(
    "scheduling-the-same-work-waits-or-runs-already",
    "the same work waits or runs already"
))
```

- The key is the context, then the first words of the sentence, in lowercase
  with dashes.
- Values go through `format!` with named fields:
  `message!("people-is-taken", format!("{name} is taken"))`.
  Write a whole sentence with named values. Never join fragments, because
  word order differs by language.
- A key is never changed once given. Editing the English makes a new message
  with a new key.
- The `///` on an event variant in `types/event_type/` is its description,
  and is collected too.
- Integration crates under `integrations/` use no keys.
- OAuth and SCIM descriptions are not translated: those protocols ask for
  ASCII.

## Steps

1. Collect the new text:

   ```sh
   cargo run -p ianua-translate -- collect --root . --out crates/ianua-translate/catalog.json
   cargo run -p ianua-translate -- check --root . --catalog crates/ianua-translate/catalog.json
   ```

   `check` reports how many messages are supplied in all eight languages.
2. Find entries whose `translations` hold `null`, and fill every language.
3. Translate the way the catalog already does. Search it for the same word
   first. An internal job, for example, is always the same phrase in each
   language. Start with a capital. Event descriptions end with a full stop,
   and refusals do not. Keep placeholders exactly as they are.
4. Keep the key order of `translations` sorted, as the file has it.
5. Generate the language files and check them.

Translations written here are drafts until a native speaker has read them.
Say so when you hand the work over.

## Check

```sh
cargo run -p ianua-translate -- check --root . --catalog crates/ianua-translate/catalog.json
cargo run -p ianua-translate -- write-fluent --catalog crates/ianua-translate/catalog.json --out crates/ianua-infra/locales
cargo run -p ianua-translate -- check-fluent --catalog crates/ianua-translate/catalog.json --locales crates/ianua-infra/locales
```
