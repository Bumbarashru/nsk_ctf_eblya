# Silver Pear - Applied Changes

This file lists all code changes I made in this dialog.

## 1) IDOR fix in `GET /api/list_transaction/{id}`

File: `backend/handlers_orders.go`

What was changed:
- Added owner check to SQL query:
  - before: `WHERE li.id = $1`
  - after: `WHERE li.id = $1 AND o.buyer_id = $2`
- Added `user.ID` as the second argument in `QueryRowContext`.

Result:
- A buyer can no longer read other users' `list_transaction` records by iterating sequential `id` values.

## 2) IDOR fix in `GET /api/transactions/{public_id}`

File: `backend/handlers_orders.go`

What was changed:
- In `handleGetLegacyTransaction`, order loading was changed:
  - before: `getOrderRecordByPublicID(ctx, publicID)`
  - after: `getOwnedOrder(ctx, user.ID, publicID)`

Result:
- Transaction access is now limited to the order owner.
- Requests with a foreign `public_id` now return `404 transaction not found`.
