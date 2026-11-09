//! The tools a tenant registers for its runs, each over a route that
//! serves it.

use serde::{Deserialize, Serialize};

/// `POST …/tools`: a tool the model may call, and the route serving it.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterTool {
    /// The name the model calls.
    pub name: String,
    /// What it does, shown to the model.
    pub description: String,
    /// The JSON schema of its input.
    pub schema: serde_json::Value,
    /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: String,
    /// The path it calls, such as `/tickets/{id}`.
    pub path: String,
    /// The route serving it.
    pub route_id: String,
}

/// A registered tool, with the classes it took from its route.
#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    /// Handle used to inspect or disable the registered tool.
    pub id: String,
    /// Identifier exposed to the model for tool calls.
    pub name: String,
    /// HTTP verb sent to the serving route.
    pub method: String,
    /// Request target template expanded from tool arguments.
    pub path: String,
    /// What it does, such as `read` or `delete`.
    pub action_class: String,
    /// `active` or `disabled`.
    pub status: String,
}
