//! Rust-rendered administration; every dynamic value is escaped by Maud.
use crate::{
    WebState,
    blocklists::{ApiError, snapshot},
};
use axum::{
    Extension,
    extract::{Query, State},
    response::Html,
};
use maud::{DOCTYPE, Markup, html};
use nullgate_core::{Blocklist, BlocklistSource, Identity, PolicySnapshot, Role, Rule, SourceKind};
#[derive(Default, serde::Deserialize)]
pub struct Screen {
    pub list: Option<i64>,
    pub source: Option<i64>,
    #[serde(default)]
    pub list_offset: usize,
    #[serde(default)]
    pub source_offset: usize,
    #[serde(default)]
    pub rule_offset: usize,
}
fn shell(title: &str, page: &str, content: Markup) -> Html<String> {
    Html(html!{
 (DOCTYPE)
 html lang="en" {
  head {meta charset="utf-8";meta name="viewport" content="width=device-width, initial-scale=1";title{(title)" · NullGate"}link rel="stylesheet" href="/app.css";script src="/app.js" defer {}}
  body data-page=(page) {(content)}
 }
}.into_string())
}
fn revision(value: u64) -> Markup {
    html! {input type="hidden" name="expected_revision" value=(value);}
}
fn source_name(kind: &SourceKind) -> String {
    match kind {
        SourceKind::Manual => "Manual entries".into(),
        SourceKind::File { filename } => filename.clone(),
        SourceKind::Remote { url } => format!("Remote: {url}"),
    }
}
pub async fn login() -> Html<String> {
    shell(
        "Sign in",
        "login",
        html! {
         main.login {
          a.brand href="/" {"N" span {"NullGate"}}
          section.login-card {
           p.eyebrow {"ADMINISTRATION"} h1 {"Welcome back"} p.muted {"Sign in to manage your shared filtering policy."} noscript {p {"JavaScript is required to sign in securely."}}
           form data-kind="login" method="post" action="/api/v1/auth/login" {
            label {"Username" input name="username" autocomplete="username" required maxlength="64";}
            label {"Password" input type="password" name="password" autocomplete="current-password" required maxlength="1024";}
            button type="submit" {"Sign in"}
           }
           div id="feedback" role="status" aria-live="polite" {}
           p.small {"First run? Provision an Administrator with the local " code {"provision-admin"} " command. There is no default password."}
          }
         }
        },
    )
}
pub async fn index(
    State(state): State<WebState>,
    Extension(identity): Extension<Identity>,
    Query(screen): Query<Screen>,
) -> Result<Html<String>, ApiError> {
    let snapshot = snapshot(&state)?;
    let remote = state.remote.is_some();
    tokio::task::spawn_blocking(move || dashboard(&snapshot, &identity, screen, remote))
        .await
        .map_err(|_| nullgate_core::PolicyError::WorkerFailed.into())
}
fn dashboard(
    snapshot: &PolicySnapshot,
    identity: &Identity,
    screen: Screen,
    remote: bool,
) -> Html<String> {
    let repo = snapshot.repository();
    let admin = identity.role == Role::Administrator;
    let rev = snapshot.revision();
    let selected = screen
        .list
        .and_then(|id| repo.lists.iter().find(|list| list.id == id))
        .or_else(|| repo.lists.get(screen.list_offset));
    shell(
        "Blocklists",
        "lists",
        html! {
         header.topbar {
          a.brand href="/" {"N" span {"NullGate"}}
          nav {span.active {"Blocklists"}}
          div.account {
           span.role {(if admin{"Administrator"}else{"Viewer · read only"})}
           span {(identity.username.as_deref().unwrap_or("Authentication disabled"))}
           form data-kind="logout" method="post" action="/api/v1/auth/logout" {button.quiet type="submit" {"Sign out"}}
          }
         }
         main.workspace {
          aside.sidebar {
           div.sidebar-title {h2 {"Your lists"} span.count {(repo.lists.len())}}
           nav.list-nav {
            @for list in repo.lists.iter().skip(screen.list_offset).take(50) {
             a class=(if selected.is_some_and(|s|s.id==list.id){"list-link selected"}else{"list-link"}) href=(format!("/?list={}&list_offset={}",list.id,screen.list_offset)) {
              span {(list.name)} small {(list.sources.iter().map(|s|s.entries.len()).sum::<usize>()) " rules"}
             }
            }
            @if repo.lists.is_empty() {p.muted {"No lists yet."}}
           }
           div.pager {
            @if screen.list_offset>0 {a href=(format!("/?list_offset={}",screen.list_offset.saturating_sub(50))) {"← Previous"}}
            @if repo.lists.len()>screen.list_offset.saturating_add(50) {a href=(format!("/?list_offset={}",screen.list_offset.saturating_add(50))) {"Next →"}}
           }
           @if admin {
            form.card.new-list method="post" action="/api/v1/lists" {
             (revision(rev))
             label {"New blocklist" input name="name" placeholder="e.g. Everyday browsing" required maxlength="128";}
             button type="submit" {"Create list"}
            }
           }
           p.sidebar-note {"Domain and URL rules can share a list. Changes apply to all configured clients."}
          }
          section.main-panel {
           div.page-heading {div {p.eyebrow {"SHARED FILTERING POLICY"} h1 {"Blocklists"} p.muted {"Choose what gets through."}} span.revision {"Revision " (rev)}}
           div id="feedback" role="status" aria-live="polite" {}
           div.notice {strong {"HTTPS path filtering is not available yet."} " Domain rules apply to HTTPS connections; URL-only hosts continue through without inspection."}
           @if let Some(list)=selected {(list_detail(list,&screen,admin,rev,remote))}
           @else {section.card.empty {h2 {"Your policy starts here"} p.muted {(if admin{"Create a list, then add domains and URLs or import a text file."}else{"No blocklists have been created yet."})}}}
           footer {"Saved changes are persisted and published before success is reported. Existing in-flight requests may finish."}
          }
         }
        },
    )
}
fn list_detail(list: &Blocklist, screen: &Screen, admin: bool, rev: u64, remote: bool) -> Markup {
    let chosen = screen
        .source
        .and_then(|id| list.sources.iter().find(|source| source.id == id))
        .or_else(|| list.sources.get(screen.source_offset));
    html! {
     section.card.list-detail {
      div.section-heading {div {p.eyebrow {"SELECTED LIST"} h2 {(list.name)}} span.count {(list.sources.iter().map(|s|s.entries.len()).sum::<usize>()) " rules"}}
      @if admin {
       div.list-actions {
        form.inline data-method="PATCH" method="post" action=(format!("/api/v1/lists/{}",list.id)) {(revision(rev)) label.sr-only for="rename" {"List name"} input id="rename" name="name" value=(list.name) required maxlength="128"; button.secondary type="submit" {"Rename list"}}
        form data-method="DELETE" data-confirm="Delete this list and all its rule memberships?" method="post" action=(format!("/api/v1/lists/{}",list.id)) {(revision(rev)) button.danger type="submit" {"Delete list"}}
       }
       @if remote {
        form.editor method="post" action=(format!("/api/v1/lists/{}/remote",list.id)) {
         (revision(rev)) h3 {"Import a remote URL"}
         label {"Public HTTP(S) blocklist URL" input type="url" name="url" placeholder="https://example.com/blocklist.txt" required maxlength="8192";}
         p.small {"Prefer HTTPS. Fetch only when requested. Refresh replaces this source; manual and file rules are preserved. Empty or failed downloads retain previous rules."}
         button.secondary type="submit" {"Fetch remote rules"}
        }
       }
       div.import-grid {
        form.editor method="post" action=(format!("/api/v1/lists/{}/rules",list.id)) {
         (revision(rev)) h3 {"Add rules"} label for="manual-rules" {"One domain or URL per line"}
         textarea id="manual-rules" name="text" rows="5" placeholder="example.com\n*.tracking.example.com\nhttps://news.example.com/ads/*" required {}
         p.small {"Wildcards are supported. URL query parameters are ignored."} button type="submit" {"Add rules"}
        }
        form.editor data-file="true" method="post" action=(format!("/api/v1/lists/{}/imports",list.id)) {
         (revision(rev)) h3 {"Import a file"} p.muted {"Add domain and URL rules from a plain-text file. Valid lines are accepted; malformed lines are reported."}
         label.file-drop {"Choose a UTF-8 text file" input type="file" name="rules_file" accept=".txt,text/plain" required;}
         p.small {"Up to 4 MiB. Reimporting the same file adds entries without clearing prior rules."} button.secondary type="submit" {"Import file"}
        }
       }
      }
      div.sources {
       h3 {"Rule sources"}
       div.source-nav {
        @for source in list.sources.iter().skip(screen.source_offset).take(20) {
         a class=(if chosen.is_some_and(|s|s.id==source.id){"source-link selected"}else{"source-link"}) href=(format!("/?list={}&source={}&source_offset={}",list.id,source.id,screen.source_offset)) {(source_name(&source.kind)) span.count {(source.entries.len())}}
        }
       }
       div.pager {
        @if screen.source_offset>0 {a href=(format!("/?list={}&source_offset={}",list.id,screen.source_offset.saturating_sub(20))) {"← Previous sources"}}
        @if list.sources.len()>screen.source_offset.saturating_add(20) {a href=(format!("/?list={}&source_offset={}",list.id,screen.source_offset.saturating_add(20))) {"More sources →"}}
       }
      }
      @if let Some(source)=chosen {(source_detail(source,list.id,screen.rule_offset,admin,rev,remote))}
      @else {div.empty {h3 {"Start with a domain or URL"} p.muted {"Add rules manually or import a text file. Each import keeps its source information."}}}
     }
    }
}
fn source_detail(
    source: &BlocklistSource,
    list: i64,
    offset: usize,
    admin: bool,
    rev: u64,
    remote: bool,
) -> Markup {
    let editable = admin && !matches!(source.kind, SourceKind::Remote { .. });
    html! {
     h3 {(source_name(&source.kind))}
     @if admin && remote && matches!(source.kind,SourceKind::Remote{..}) {
      form method="post" action=(format!("/api/v1/sources/{}/refresh",source.id)) {(revision(rev)) button.secondary type="submit" {"Refresh remote source"}}
      form data-method="DELETE" data-confirm="Delete this remote source and its rules?" method="post" action=(format!("/api/v1/sources/{}",source.id)) {(revision(rev)) button.text-danger type="submit" {"Delete remote source"}}
     }
     @if matches!(source.kind,SourceKind::Remote{..}) {p.small {
      "Last attempt: " @if let Some(at)=source.last_attempt {time data-unix=(at) {(at)}} @else {"never"}
      " · Last success: " @if let Some(at)=source.last_success {time data-unix=(at) {(at)}} @else {"never"}
     }}
     div.rule-table {
      table {
       thead {tr {th {"Rule"} th {"Type"} @if editable {th {"Action"}}}}
       tbody {
        @for entry in source.entries.iter().skip(offset).take(50) {
         tr {
          td {code {(entry.input())}} td {span.rule-type {(if matches!(entry.rule,Rule::Url(_)){"URL"}else{"Domain"})}}
          @if editable {td {form method="post" action=(format!("/api/v1/sources/{}/remove",source.id)) {(revision(rev)) input type="hidden" name="rule" value=(entry.input()); button.text-danger type="submit" {"Remove"}}}}
         }
        }
       }
      }
     }
     div.pager {
      @if offset>0 {a href=(format!("/?list={list}&source={}&rule_offset={}",source.id,offset.saturating_sub(50))) {"← Previous rules"}}
      span.small {"Showing up to 50 of " (source.entries.len()) " rules"}
      @if source.entries.len()>offset.saturating_add(50) {a href=(format!("/?list={list}&source={}&rule_offset={}",source.id,offset.saturating_add(50))) {"Next rules →"}}
     }
     @if let Some(report)=&source.last_report {
      details.report {summary {"Last import: " (match report.outcome {nullgate_core::ImportOutcome::Applied=>"applied · ",nullgate_core::ImportOutcome::NoValidRules=>"no valid rules; previous rules retained · ",nullgate_core::ImportOutcome::FetchFailed=>"download failed; previous rules retained · "}) (report.accepted) " accepted · " (report.malformed) " malformed"}
       @for diagnostic in report.diagnostics.iter().take(50) {p {strong {"Line " (diagnostic.line) ": "} (diagnostic.message)}}
       @if report.diagnostics.len()>50 {p.small {"Additional diagnostics are available through the source API."}}
      }
     }
     @if editable {
      details.replace-source {
       summary {"Edit or replace this source"} p.muted {"This replaces every rule in this source. Other sources are preserved. An empty replacement clears this source."}
       form data-method="PUT" method="post" action=(format!("/api/v1/sources/{}/entries",source.id)) {
        (revision(rev)) label {"Complete replacement" textarea name="text" rows="6" placeholder="Paste the complete replacement here" {
         @if source.entries.iter().map(|e|e.input().len()+1).sum::<usize>()<=65536 {(source.entries.iter().map(|e|e.input()).collect::<Vec<_>>().join("\n"))}
        }}
        label.check {input type="checkbox" required; "I want to replace all rules in this source."} button.secondary type="submit" {"Replace source rules"}
       }
       form data-method="DELETE" data-confirm="Delete this source and all its rule memberships?" method="post" action=(format!("/api/v1/sources/{}",source.id)) {(revision(rev)) button.text-danger type="submit" {"Delete source"}}
      }
     }
    }
}
