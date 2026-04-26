use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use crate::auth;
use crate::models::{TransactionInfo, TransactionsQuery, TransferReq};
use crate::AppState;

pub async fn transfer(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<TransferReq>,
) -> HttpResponse {
    let claims = match auth::require_claims(&req, &state.keys) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if body.amount <= 0.0 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Amount must be positive"}));
    }
    if body.amount > 1_000_000.0 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Amount exceeds limit"}));
    }

    let comment = body.comment.clone().unwrap_or_default();
    if comment.len() > 256 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Comment too long"}));
    }

    let to_id = if body.to.len() == 36 && body.to.contains('-') {
        body.to.clone()
    } else {
        let db = state.db.lock().unwrap();
        match db.query_row(
            "SELECT id FROM users WHERE username = ?1",
            params![body.to],
            |row| row.get::<_, String>(0),
        ) {
            Ok(id) => id,
            Err(_) => {
                return HttpResponse::NotFound()
                    .json(serde_json::json!({"error": "Recipient not found"}))
            }
        }
    };

    if to_id == claims.sub {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Cannot transfer to yourself"}));
    }

    let db = state.db.lock().unwrap();

    let from_balance: f64 = match db.query_row(
        "SELECT balance FROM users WHERE id = ?1",
        params![claims.sub],
        |row| row.get(0),
    ) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Sender not found"}))
        }
    };

    let to_exists: bool = db
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![to_id], |_| {
            Ok(true)
        })
        .unwrap_or(false);

    if !to_exists {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Recipient not found"}));
    }

    if from_balance < body.amount {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Insufficient funds",
            "balance": from_balance
        }));
    }

    let tx_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    db.execute(
        "UPDATE users SET balance = balance - ?1 WHERE id = ?2",
        params![body.amount, claims.sub],
    )
    .unwrap();
    db.execute(
        "UPDATE users SET balance = balance + ?1 WHERE id = ?2",
        params![body.amount, to_id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO transactions (id, from_user, to_user, amount, comment, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![tx_id, claims.sub, to_id, body.amount, comment, now],
    )
    .unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "id": tx_id,
        "from_user": claims.sub,
        "to_user": to_id,
        "amount": body.amount,
        "balance": from_balance - body.amount,
    }))
}

pub async fn list_transactions(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TransactionsQuery>,
) -> HttpResponse {
    let claims = match auth::require_claims(&req, &state.keys) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    // ✅ FIX: Whitelist для order (обратно совместимо)
    let order_raw = query.order.as_deref().unwrap_or("desc");
    let order = match order_raw.to_lowercase().as_str() {
        "asc" => "ASC",
        "desc" => "DESC",
        invalid => {
            log::warn!("Invalid order value: '{}', defaulting to DESC", invalid);
            "DESC"
        }
    };

    // ✅ FIX: Whitelist для sort column (обратно совместимо)
    let sort_raw = query.sort.as_deref().unwrap_or("created_at");
    let order_column = match sort_raw {
        "amount" => "t.amount",
        "id" => "t.id",
        "created_at" => "t.created_at",
        unknown => {
            log::warn!("Unknown sort column: '{}', defaulting to created_at", unknown);
            "t.created_at"
        }
    };

    // ✅ FIX: Дополнительная проверка на опасные символы
    let dangerous_chars = [';', '\'', '"', '\\', '\n', '\r', '\0', '(', ')'];
    
    if order_raw.chars().any(|c| dangerous_chars.contains(&c)) {
        log::error!("Potential SQL injection in order: {:?}", order_raw);
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid order parameter"}));
    }
    
    if sort_raw.chars().any(|c| dangerous_chars.contains(&c)) {
        log::error!("Potential SQL injection in sort: {:?}", sort_raw);
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid sort parameter"}));
    }

    let sql = format!(
        "SELECT t.id, t.from_user, t.to_user,
                fu.username, tu.username,
                t.amount, t.comment, t.created_at
         FROM transactions t
         JOIN users fu ON fu.id = t.from_user
         JOIN users tu ON tu.id = t.to_user
         WHERE t.from_user = ?1 OR t.to_user = ?1
         ORDER BY {} {}
         LIMIT ?2",
        order_column, order
    );

    // ✅ FIX: Финальная проверка SQL
    if sql.contains([';', '\'', '"']) {
        log::error!("SQL injection detected in generated query");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "Internal error"}));
    }

    let db = state.db.lock().unwrap();
    let mut stmt = match db.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            log::error!("SQL prepare error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Query error"}));
        }
    };

    let rows = stmt.query_map(params![claims.sub, limit], |row| {
        Ok(TransactionInfo {
            id: row.get(0)?,
            from_user: row.get(1)?,
            to_user: row.get(2)?,
            from_username: row.get(3)?,
            to_username: row.get(4)?,
            amount: row.get(5)?,
            comment: row.get(6)?,
            created_at: row.get(7)?,
        })
    });

    let txs: Vec<TransactionInfo> = match rows {
        Ok(r) => r.filter_map(|x| x.ok()).collect(),
        Err(e) => {
            log::error!("Query failed: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Query failed"}));
        }
    };

    HttpResponse::Ok().json(txs)
}